# Port Scan Guard（nftables）

基于 nftables 的高危端口扫描防护脚本：监听从指定端口发起的入站新连接，非白名单来源即时拉黑（默认 24 小时）；同时记录 ICMP ping 探测（只记录，不封禁、不丢包）。

---

## 目录

- [一、功能与边界](#一功能与边界)
- [二、环境预检](#二环境预检)
- [三、克隆仓库与权限](#三克隆仓库与权限)
- [四、Python venv 与依赖](#四python-venv-与依赖)
- [五、下载 IP 离线库](#五下载-ip-离线库)
- [六、脚本部署与配置](#六脚本部署与配置)
- [七、前台测试运行](#七前台测试运行)
- [八、systemd 服务化](#八systemd-服务化)
- [九、DRY_RUN 观察期](#九dry_run-观察期)
- [十、切换生产模式](#十切换生产模式)
- [十一、验证封禁 / 解封](#十一验证封禁--解封)
- [十二、数据库查询速查](#十二数据库查询速查)
- [十三、日常运维](#十三日常运维)
- [十四、故障排查](#十四故障排查)
- [十五、容器 / macvlan 部署](#十五容器--macvlan-部署)
- [十六、卸载](#十六卸载)
- [附：一页部署速查](#附一页部署速查)

---

## 一、功能与边界

**它做什么**

- 监听 `TCP_PORTS` / `UDP_PORTS` 清单内的端口，任何**非白名单**来源的入站新连接都会被加入 nft 黑名单（时长 `BAN_TIME`，默认 86400 秒 = 24 小时）。
- 同时记录 ICMP echo-request（ping）探测：只写数据库，不加黑名单、不丢包——用于审计"谁在探测 NAS 是否在线"。
- 规则挂在 `prerouting` 链、优先级 `-110`，即位于 Docker DNAT（`-100`）之前，`saddr` / `dport` 都是原始值。
- 封禁时查询 IP 归属地（离线库优先，缺失时在线补充），记录写入 SQLite，便于筛选统计。

**能保护**

- 所有入站方向的新连接，包括宿主机自身端口。
- 常见 TCP 扫描手法：**SYN 扫描**（`nmap -sS`）、**FIN / XMAS 扫描**（`-sF` / `-sX`）、**NULL 扫描**（`-sN`）。后两者由 `ENABLE_FLAG_SCAN` 控制，默认开启，且只匹配 `ct state invalid,untracked`，不会误伤正常关闭连接。
- Docker bridge 模式发布到宿主机的服务：按**发布端口**识别（`-p 8080:80` 只认 8080），容器内部端口不可见；发布端口本身是你在用的端口，通常不该放进清单。
- macvlan 容器（需在容器内独立部署一份脚本并使用不同前缀，否则会互相误封）。

**保护不了**

- 出站流量、已建立连接的后续包。
- **ACK 扫描**（`nmap -sA`）：ACK 包与正常流量的标志位无法区分，只能靠 `ct state` 判定；而单独加规则会命中大量畸形 ACK 包（可被伪造源 IP 利用来误封第三方）。另外本表已对清单内端口的 TCP 新连接一律 drop，ACK 扫描收不到 RST，本来也拿不到端口状态。
- 内网横向流量（含容器←→宿主）：源地址落在私网白名单（`172.16.0.0/12` 含默认 bridge 的 `172.17.0.0/16`），规则在端口匹配前就 `return`，不记录、不封禁。

**关键理解**

- 脚本只对 `TCP_PORTS` / `UDP_PORTS` 清单里的端口做记录和封禁；**清单外端口一律放行、不记录**。
- 清单里的端口应当是你**确实不使用**的端口。自己正在提供服务的端口**切勿**放进清单，否则所有正常访客都会被封。

**默认放行的地址**

- 私网段：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`fc00::/7`、`fe80::/10`。
- 回环、未指定、多播地址一律放行（不是攻击）。
- IPv4-mapped IPv6（`::ffff:a.b.c.d`）会自动归一为 IPv4 处理，避免误写入 IPv6 黑名单却拦不住 IPv4 流量。

---

## 二、环境预检

### 2.1 nftables

```bash
nft --version
```

建议 ≥ 1.0.6（1.0.9 已实测）。未安装：

```bash
sudo apt update && sudo apt install -y nftables
```

### 2.2 内核日志模块

```bash
sudo nft add table inet test_log
sudo nft add chain inet test_log c '{ type filter hook input priority filter; }'
sudo nft add rule inet test_log c tcp dport 12345 log prefix "TEST_LOG: "

# 关键：log 规则只在有包命中时才触发，必须主动发一个包
nc -zv 127.0.0.1 12345 || true
```

另一终端：

```bash
sudo journalctl -k --since "10 seconds ago" | grep TEST_LOG
```

有输出 → OK。检查完清理测试表：

```bash
sudo nft delete table inet test_log
```

无输出：

```bash
sudo apt install -y kmod
sudo modprobe nf_log_ipv4 nf_log_ipv6
```

### 2.3 Python

```bash
python3 --version
```

要求 ≥ 3.7。

### 2.4 iptables 后端（Docker 场景重点关注）

```bash
sudo update-alternatives --config iptables
```

建议选 iptables-nft。如果显示 iptables-legacy 且你运行 Docker：

```bash
sudo update-alternatives --set iptables /usr/sbin/iptables-nft
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
sudo systemctl restart docker
```

### 2.5 日志源确认（Armbian zram 场景）

```bash
sudo journalctl -k -f -n 0 -o cat
```

能看到内核日志流即可。按 Ctrl+C 退出。

Armbian 默认 `/var/log` 挂 zram，`/var/log/kern.log` 可能不存在——脚本会自动回退到 `journalctl -k -f`。zram 只在意外断电时丢失同步间隔内的历史日志，不影响脚本封禁功能（封禁依赖实时事件 + nft set 状态）。

---

## 三、克隆仓库与权限

从 GitHub 克隆仓库（仓库已包含 `port_scan_guard_nft.py` 与 `requirements.txt`）：

```bash
cd /root
git clone https://github.com/wishday/port_scan_guard.git port_scan_guard
chmod 700 /root/port_scan_guard
cd /root/port_scan_guard
```

---

## 四、Python venv 与依赖

依赖已在仓库的 `requirements.txt` 中声明，直接安装即可：

```bash
cd /root/port_scan_guard
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt
```

> ⚠️ 不要先建 venv 再 `mv`——activate 里的路径会写死旧位置。请直接在 `/root/port_scan_guard` 下建。

`requests` 仅用于离线库未命中时的在线归属地查询，缺失时可正常运行（只是没有在线补充）。

---

## 五、下载 IP 离线库

离线库（xdb）体积较大，未纳入仓库，需单独下载：

```bash
cd /root/port_scan_guard

sudo wget -O ip2region_v4.xdb \
  "https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb"
sudo wget -O ip2region_v6.xdb \
  "https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v6.xdb"

chmod 600 *.xdb
```

离线库能否真正加载，以脚本启动时是否出现下列告警为准（无告警即已加载）：

- `[!] 离线库不存在: ...`
- `[!] IPv4 离线库未加载，将全部走在线查询`
- `[!] IPv6 离线库未加载`

建议优先准备好本地离线库：在线查询在高并发时时延、请求数都可能无法满足。

---

## 六、脚本部署与配置

### 6.1 脚本与权限

克隆仓库后 `port_scan_guard_nft.py` 已在 `/root/port_scan_guard/`，只需赋予可执行权限：

```bash
chmod 700 /root/port_scan_guard/port_scan_guard_nft.py
```

### 6.2 必须确认的配置项

打开脚本，重点看顶部配置区：

**`TCP_PORTS` / `UDP_PORTS`**

清单内的端口会被监测，非白名单连接即封。**不要把自己在用的服务端口放进来**。

| 你的访问方式 | 需要做什么 |
| --- | --- |
| 只从 LAN 访问 NAS | 不用改（私网白名单覆盖） |
| 从公网 IPv4 访问 22/80/443 | 注释掉这些端口，或把公网 IP 加入 `EXTRA_WHITELIST` |
| 从公网 IPv6 访问 | 把家宽 IPv6 前缀加入 `EXTRA_WHITELIST` |

否则切到 `DRY_RUN = False` 后，你自己会被封。

**`DRY_RUN`（默认 `False`，务必注意）**

代码中默认值就是 `False`，即**直接封禁**。首次部署强烈建议先改为 `True` 观察 1~3 天，确认不误封自己再切回 `False`：

```bash
sudo sed -i 's/^DRY_RUN[[:space:]]*=[[:space:]]*False/DRY_RUN    = True/' \
  /root/port_scan_guard/port_scan_guard_nft.py
```

> `DRY_RUN` 只影响端口扫描的封禁动作，不影响 ICMP 记录。

**`EXTRA_WHITELIST`**

```python
EXTRA_WHITELIST = [
    # ipaddress.ip_network("2409:8a00:1234:5678::/64"),  # 你的家宽 IPv6 前缀
]
```

白名单来源访问监测端口也不会被封。

**`BAN_DEDUP_WINDOW`**

默认 10 秒。同一 IP 的**同类事件**（端口扫描 / ICMP 各自独立）在窗口期内只处理一次，避免日志刷屏时反复写库 / 调 nft。库增长太快可调大（如 300）。

**`DB_RETENTION_DAYS`**

默认 180 天。设为 `<= 0` 表示完全不清理（数据库只增不减）。

**`ENABLE_ICMP_LOG`**

默认 `True`：记录非白名单的 ping 探测（只记录不封禁）。想关闭改为 `False`。

**`ENABLE_FLAG_SCAN`**

默认 `True`：除纯 SYN 扫描外，额外检测 **FIN / XMAS 扫描**（`tcp flags fin`）与**NULL 扫描**（六个标志位全为 0）。两条规则都要求 `ct state invalid,untracked`，因此正常连接关闭时的 FIN 不会被误判；依赖 `nf_conntrack`。设为 `False` 则只保留 SYN 规则。ACK 扫描（`-sA`）不在覆盖范围内，原因见[第一节](#一功能与边界)。

**`NFT_TABLE` / 日志前缀（容器场景重点）**

默认表名 `port_scan_guard_host`，日志前缀 `HOST_SCAN:`（端口扫描）与 `HOST_ICMP:`（ICMP）。容器与宿主机必须使用**不同**前缀，否则会同时封禁——详见[第十五节](#十五容器--macvlan-部署)。

改完不必翻代码核对：启动时的 `[*] nft 表：inet ...；日志前缀：... / ...` 一行会打印**当前生效**的表名与两个前缀，加载失败与恢复失败的告警里也会带上它们。nft 自身的报错只给 `/dev/stdin:38:69` 这类行号，不带表名，靠这行才能确认失败的是哪一个实例。

### 6.3 语法检查

```bash
/root/port_scan_guard/venv/bin/python3 -m py_compile \
  /root/port_scan_guard/port_scan_guard_nft.py && echo "语法 OK"
```

---

## 七、前台测试运行

```bash
sudo /root/port_scan_guard/venv/bin/python3 \
  /root/port_scan_guard/port_scan_guard_nft.py
```

预期输出（`DRY_RUN = False` 时）：

```
[*] 已就绪：TCP 113 个 / UDP 5 个端口
[*] nft 表：inet port_scan_guard_host；日志前缀：HOST_SCAN: / HOST_ICMP:
[*] 链：PREROUTING（优先级 -110，在 Docker DNAT 之前）
[*] 策略：内网 IPv4/IPv6 放行，命中端口即封 86400s
[*] ICMP：只记录非白名单 echo-request，不封禁、不丢包
[*] 数据库：/root/port_scan_guard/scan.db
[*] 保留策略：最近 180 天，每 24 小时检查一次
[*] DRY_RUN = False：端口扫描实际封禁
[*] 日志限速: 5/sec / burst 10（仅影响 log，不影响 drop）
[*] UDP 日志仅对 ct state new 生效（依赖 nf_conntrack）
[*] 日志来源: journalctl -k -f
```

`DRY_RUN = True` 时对应行变为：

```
[!] DRY_RUN = True：端口扫描只记录不封禁
```

关注点：

- `[!] 离线库不存在` / `[!] IPv4 离线库未加载` → 检查 xdb 路径/权限；不影响封禁功能。
- `[!] 日志流异常` / `[!] 日志流已中断` → 脚本会在 5 秒后自动重连。
- `日志限速: 5/sec` 是**全局限速**（不是 per-IP）：单个 IP 打满就会让其他来源的扫描不写日志、不进黑名单（但这些包照样被 drop）。需要更强的对抗能力就把 `HASHLIMIT_RATE` 调大，代价是内核日志量同比例上升。

按 Ctrl+C 退出。

---

## 八、systemd 服务化

自动拉起、防意外退出。

### 8.1 创建服务文件

```bash
sudo nano /etc/systemd/system/port-scan-guard.service
```

```ini
[Unit]
Description=Port Scan Guard (nftables)
Documentation=file:///root/port_scan_guard/port_scan_guard_nft.py

# 网络获得 IP 再启动（让在线查询尽早可用）
After=network-online.target
Wants=network-online.target

# 系统级 nftables.service 先执行完，避免它 flush ruleset 清掉我们的表
After=nftables.service
Wants=nftables.service

# 启动限流：10 分钟内最多重启 5 次，防止配置错误导致无限重启
# （systemd 229+ 必须在 [Unit] 节）
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/root/port_scan_guard/venv/bin/python3 /root/port_scan_guard/port_scan_guard_nft.py
WorkingDirectory=/root/port_scan_guard

# 进程退出后等 5 秒再重启
Restart=always
RestartSec=5

# systemctl stop/restart 时给脚本 10 秒优雅退出，超时 SIGKILL
TimeoutStopSec=10

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 8.2 启用

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now port-scan-guard
sudo systemctl status port-scan-guard
```

### 8.3 查看服务日志

```bash
sudo journalctl -u port-scan-guard -f
```

---

## 九、DRY_RUN 观察期

保持 `DRY_RUN = True` 运行 1~3 天。

### 9.1 实时事件

```bash
sudo journalctl -u port-scan-guard -f
```

输出示例：

```
[2026-09-20 10:30:15] dry_run 203.0.113.45:TCP/25 (美国/加利福尼亚/洛杉矶/Level3) [offline]
[2026-09-20 10:30:20] dry_run 203.0.113.45:UDP/161 (美国/加利福尼亚/洛杉矶/Level3) [offline]
[2026-09-20 10:30:31] icmp_probe 203.0.113.45 (美国/加利福尼亚/洛杉矶/Level3) [offline]
```

格式：

- 端口扫描：`[时间] result IP:PROTO/PORT (国家/省/市/ISP) [来源]`
- ICMP 探测：`[时间] icmp_probe IP (国家/省/市/ISP) [来源]`

`result` 取值：`dry_run`（只记录）、`ban`（已封禁）、`ban_failed`（封禁失败）、`icmp_probe`（ICMP 记录）。
`来源` 取值：`offline`、`online`、`offline+online`、`unknown`。

> 内核原始日志（nft log）在 `journalctl -k`，前缀为 `HOST_SCAN:` / `HOST_ICMP:`；服务日志则是脚本处理后的上面这种格式。

### 9.2 检查是否误伤自己

```bash
# 你的公网出口 IP
curl -s https://ipinfo.io/ip

# 数据库里出现过的所有源 IP（仅端口扫描事件）
sqlite3 -header -column /root/port_scan_guard/scan.db \
  "SELECT ip, COUNT(*) AS cnt, MIN(time_str), MAX(time_str) FROM bans \
   WHERE event_type='port_scan' GROUP BY ip ORDER BY cnt DESC LIMIT 30;"
```

发现自己公网 IP 或家宽 IPv6 前缀 → 加入 `EXTRA_WHITELIST` 或注释掉相关端口。

### 9.3 端口热度

```bash
sqlite3 -header -column /root/port_scan_guard/scan.db \
  "SELECT protocol, port, COUNT(*) AS cnt FROM bans \
   WHERE event_type='port_scan' AND port IS NOT NULL \
     AND ts > strftime('%s','now')-86400 \
   GROUP BY protocol, port ORDER BY cnt DESC LIMIT 20;"
```

---

## 十、切换生产模式

把 `DRY_RUN` 改回 `False` 并重启：

```bash
sudo sed -i 's/^DRY_RUN[[:space:]]*=[[:space:]]*True/DRY_RUN    = False/' \
  /root/port_scan_guard/port_scan_guard_nft.py
sudo systemctl restart port-scan-guard
```

验证：

```bash
sudo nft list chain inet port_scan_guard_host prerouting
```

`DRY_RUN=False` 时应看到：黑名单规则末尾有 `drop`，且 TCP/UDP 各多出一条**独立的** drop 规则（无 log）：

```
    ip  saddr @port_scan_guard_host_bl4 counter packets 0 bytes 0 drop
    ip6 saddr @port_scan_guard_host_bl6 counter packets 0 bytes 0 drop
    ip  saddr @port_scan_guard_host_wl4 return
    ip6 saddr @port_scan_guard_host_wl6 return
    icmp type echo-request limit rate 5/second burst 10 packets log prefix "HOST_ICMP: " level info
    icmpv6 type echo-request limit rate 5/second burst 10 packets log prefix "HOST_ICMP: " level info
    tcp dport @port_scan_guard_host_tcp tcp flags syn / syn,ack limit rate 5/second burst 10 packets log prefix "HOST_SCAN: " level warn
    tcp dport @port_scan_guard_host_tcp tcp flags syn / syn,ack drop
    tcp dport @port_scan_guard_host_tcp tcp flags fin ct state invalid,untracked limit rate 5/second burst 10 packets log prefix "HOST_SCAN: " level warn
    tcp dport @port_scan_guard_host_tcp tcp flags fin ct state invalid,untracked drop
    tcp dport @port_scan_guard_host_tcp tcp flags ! fin,syn,rst,psh,ack,urg ct state invalid,untracked limit rate 5/second burst 10 packets log prefix "HOST_SCAN: " level warn
    tcp dport @port_scan_guard_host_tcp tcp flags ! fin,syn,rst,psh,ack,urg ct state invalid,untracked drop
    udp dport @port_scan_guard_host_udp ct state new limit rate 5/second burst 10 packets log prefix "HOST_SCAN: " level warn
    udp dport @port_scan_guard_host_udp drop
```

> 显示格式说明（nft 1.0.x 的渲染习惯，别误以为规则写错了）：
> - 链头实际显示为 `type filter hook prerouting priority dstnat - 10;`，`dstnat - 10` 就是 `-110`。
> - `counter` 会带上计数，显示为 `counter packets N bytes N`。
> - 配置文件里写的 `tcp flags & (syn|ack) == syn`，列出时显示为 `tcp flags syn / syn,ack`（`值 / 掩码` 写法）。
> - `tcp flags & (fin|syn|rst|psh|ack|urg) == 0`（NULL 扫描）显示为 `tcp flags ! fin,syn,rst,psh,ack,urg`。
> - `tcp flags fin` 那两条规则来自 `ENABLE_FLAG_SCAN`（捕获 FIN / XMAS 扫描）；设为 `False` 后这两组规则不会出现。
> - 这两条规则都带 `ct state invalid,untracked`：**扫描包的 conntrack 状态是 `invalid`，正常关闭连接的 FIN+ACK 是 `established`**。靠这个区分，正常回程 FIN（本地临时端口若落在端口清单里）才不会被误封。

> 说明：log 规则与 drop 规则是**拆开的两条**。因为 nft 的 `limit` 是匹配表达式，若写成 `log ... drop` 一行，超速时 limit 不匹配会中断整条规则、连 drop 一起跳过，形成安全漏洞。

---

## 十一、验证封禁 / 解封

### 11.1 模拟攻击

外部机器（非白名单）：

```bash
nc -zv <NAS_IP> 25
```

NAS 上：

```bash
sudo journalctl -u port-scan-guard -f
sudo nft list set inet port_scan_guard_host port_scan_guard_host_bl4
```

应看到攻击 IP 出现在 set 中，timeout 剩余接近 86400 秒。

### 11.2 手动解封

```bash
sudo nft delete element inet port_scan_guard_host port_scan_guard_host_bl4 '{ <IP> }'
```

> nft 表默认不持久化：系统重启后，已被封禁的 IP 不会自动加回。脚本启动时会尝试从**仍存在的** nft set 按剩余时间恢复封禁；若系统级 `nftables.service` 在启动时 flush 了规则，则无法恢复。

---

## 十二、数据库查询速查

数据库：`/root/port_scan_guard/scan.db`，表 `bans`。

字段：`id, ts, time_str, ip, family, port, protocol, country, province, city, isp, source, duration, result, event_type`。

- `event_type`：`port_scan`（端口扫描）/ `icmp`（ICMP 探测）。
- `result`：`dry_run` / `ban` / `ban_failed` / `icmp_probe`。
- `duration`：实际封禁秒数（`ban` 为 `BAN_TIME`）；`dry_run` 与 `icmp_probe` 均为 `0`。
- ICMP 记录的 `port` 为 `NULL`。
- 同一 IP 已在黑名单中时**不会重复写库**（既不续期也不再记录），因此单个攻击者 24 小时内最多留下一条 `ban` 记录。

最近事件：

```bash
sqlite3 -header -column /root/port_scan_guard/scan.db \
  "SELECT time_str, event_type, ip, protocol, port, country, result FROM bans \
   ORDER BY ts DESC LIMIT 20;"
```

最近 24 小时攻击源 Top 20（仅端口扫描）：

```bash
sqlite3 -header -column /root/port_scan_guard/scan.db \
  "SELECT ip, country, isp, COUNT(*) AS hits, \
          GROUP_CONCAT(DISTINCT port) AS ports \
   FROM bans WHERE event_type='port_scan' AND ts > strftime('%s','now')-86400 \
   GROUP BY ip ORDER BY hits DESC LIMIT 20;"
```

端口热度（按协议区分，近 7 天）：

```bash
sqlite3 -header -column /root/port_scan_guard/scan.db \
  "SELECT protocol, port, COUNT(*) AS cnt FROM bans \
   WHERE event_type='port_scan' AND port IS NOT NULL \
     AND ts > strftime('%s','now')-604800 \
   GROUP BY protocol, port ORDER BY cnt DESC LIMIT 20;"
```

只看 UDP：

```bash
sqlite3 -header -column /root/port_scan_guard/scan.db \
  "SELECT time_str, ip, port, country FROM bans \
   WHERE event_type='port_scan' AND protocol='UDP' \
     AND ts > strftime('%s','now')-86400 \
   ORDER BY ts DESC LIMIT 20;"
```

只看 ICMP 探测（谁在 ping 你）：

```bash
sqlite3 -header -column /root/port_scan_guard/scan.db \
  "SELECT time_str, ip, protocol, country, isp, source FROM bans \
   WHERE event_type='icmp' AND ts > strftime('%s','now')-86400 \
   ORDER BY ts DESC LIMIT 50;"
```

按国家统计（仅端口扫描）：

```bash
sqlite3 -header -column /root/port_scan_guard/scan.db \
  "SELECT country, COUNT(*) AS cnt FROM bans \
   WHERE event_type='port_scan' AND ts > strftime('%s','now')-86400 \
   GROUP BY country ORDER BY cnt DESC LIMIT 15;"
```

数据库大小 / 总行数：

```bash
sqlite3 /root/port_scan_guard/scan.db "SELECT COUNT(*) FROM bans;"
ls -lh /root/port_scan_guard/scan.db*
```

---

## 十三、日常运维

### 13.1 自动清理

脚本按 `DB_CLEANUP_INTERVAL`（默认 86400 秒 = 24 小时）检查一次，删除 `DB_RETENTION_DAYS`（默认 180 天）之前的记录；启动时也会立刻清一次。

### 13.2 手动 VACUUM（可选）

```bash
sudo systemctl stop port-scan-guard
sqlite3 /root/port_scan_guard/scan.db "VACUUM;"
sudo systemctl start port-scan-guard
```

> ⚠️ VACUUM 会重写整个数据库，对 eMMC 一次性写入较大。除非空间紧张，一般不用。

### 13.3 备份数据库

```bash
sqlite3 /root/port_scan_guard/scan.db ".backup /root/port_scan_guard/scan.db.bak"
```

### 13.4 更新脚本

```bash
cd /root/port_scan_guard
git stash          # 本地用 sed 改过 DRY_RUN 时必须先暂存，否则 pull 冲突
git pull
git stash pop      # 暂存的改动会重新应用；若上游改了同一行，按提示解决冲突
sudo systemctl restart port-scan-guard
```

> 数据库为 WAL 模式；旧库升级时，脚本会自动 `ALTER TABLE` 补齐 `port` / `protocol` / `event_type` 缺失列。

---

## 十四、故障排查

| 现象 | 可能原因 | 排查 |
| --- | --- | --- |
| 服务启动后无事件 | 内核日志源不可用 | 执行 2.2 节测试；检查 `nf_log_ipv4/ipv6` |
| `[!] 离线库不存在` | xdb 路径/权限错 | `ls -l /root/port_scan_guard/*.xdb` |
| `[!] nft 添加元素失败` | nft 版本/权限/set 满 | `nft --version`；`nft list set inet port_scan_guard_host port_scan_guard_host_bl4` |
| 自己从公网访问被误封 | 公网 IP 未加白名单 | 加入 `EXTRA_WHITELIST` 或注释掉端口 |
| Docker 映射端口连不上 | 链里有 `accept`（应为 `return`） | `nft list chain inet port_scan_guard_host prerouting \| grep wl4` |
| `protocol` 全为 NULL | 旧库升级后的老数据 | 确认当前脚本 `PORT_SCAN_RE` 里 `PROTO` 在 `DPT` 之前 |
| `scan.db` 增长太快 | 被持续扫描 + 去重窗口小 | 调大 `BAN_DEDUP_WINDOW`，或暂时保持 `DRY_RUN=True` |
| 服务反复退出/重启 | nft 配置错误或权限不足（`setup_firewall` 失败会退出） | `journalctl -u port-scan-guard -n 100 --no-pager` |
| 启动时报 `conntrack` 相关错误 | 内核缺 `nf_conntrack` | 设 `UDP_NEW_CONN_ONLY=False`、`ENABLE_FLAG_SCAN=False`，或 `modprobe nf_conntrack` |
| 重启后已封禁 IP 又通了 | 系统级 `nftables.service` 启动时 flush 了规则 | `nft list set inet port_scan_guard_host port_scan_guard_host_bl4`；日志找 `恢复封禁记录: 成功 N 条` |
| 容器内无日志/不封禁 | 未开 `nf_log_all_netns` 或挂载内核日志 | 见[第十五节](#十五容器--macvlan-部署) |

> 注意：日志源本身不可用时，脚本不会退出，而是每 5 秒自动重连；真正导致进程退出的通常是 `setup_firewall` 的 nft 配置/权限失败。

常用命令：

```bash
# 服务状态
sudo systemctl status port-scan-guard

# 最近 100 行服务日志
sudo journalctl -u port-scan-guard -n 100 --no-pager

# 内核原始日志（nft log）
sudo journalctl -k -f | grep -E "HOST_SCAN:|HOST_ICMP:"

# nft 规则全览
sudo nft list table inet port_scan_guard_host

# 规则链
sudo nft list chain inet port_scan_guard_host prerouting

# 黑名单 set
sudo nft list set inet port_scan_guard_host port_scan_guard_host_bl4
sudo nft list set inet port_scan_guard_host port_scan_guard_host_bl6
```

---

## 十五、容器 / macvlan 部署

脚本具备容器自检能力（检测 `/.dockerenv`、`/run/.containerenv`、cgroup），容器内运行需注意：

**1. 权限**

```bash
--cap-add=NET_ADMIN
```

无需 `NET_RAW`。当前进程缺少 `CAP_NET_ADMIN` 时，脚本会告警：`[!] 当前进程缺少 CAP_NET_ADMIN`。

**2. 让容器内 nft 日志写到宿主内核**

宿主机执行：

```bash
sudo sysctl -w net.netfilter.nf_log_all_netns=1
```

容器内自检若发现 `/proc/sys/net/netfilter/nf_log_all_netns != 1`，会告警提示。宿主机自身部署时该值为 0 是正常的。

**3. 挂载内核日志（只读）**

```bash
-v /var/log/kern.log:/var/log/kern.log:ro
```

**4. 前缀与表名：容器和宿主必须区分**

容器与宿主机若防护同一批端口，必须使用**不同**的 `PORT_SCAN_PREFIX` / `ICMP_PROBE_PREFIX`（例如容器用 `CTR_SCAN:` / `CTR_ICMP:`），否则两边会互相把对方流量当成扫描而同时封禁。

表名要不要一起改，取决于网络模式：

| 网络模式 | netns | `NFT_TABLE` 同名 | 说明 |
| --- | --- | --- | --- |
| macvlan / bridge | 独立 | 无害 | 各自 `nft list tables` 只看得到自己的表；建议仍改为 `port_scan_guard_ctr` 之类，排查时不会认错实例 |
| `--network host` | 与宿主共享 | **会互相删除** | 后启动的实例在 `setup_firewall()` 里 `delete table`，直接把宿主的表连同封禁记录一起删掉，必须改名 |

改完以启动时的 `[*] nft 表：inet ...；日志前缀：... / ...` 一行为准。

**5. 端口清单按 netns 实际情况配置**

macvlan 场景下宿主机这些端口通常是空的（服务在容器 netns 里），因此到达宿主机这些端口的包都可视为扫描。若容器与主机防护端口规则不同，需在容器内**独立部署一份**。

---

## 十六、卸载

```bash
sudo systemctl stop port-scan-guard
sudo systemctl disable port-scan-guard
sudo rm /etc/systemd/system/port-scan-guard.service
sudo systemctl daemon-reload

sudo nft delete table inet port_scan_guard_host
sudo rm -rf /root/port_scan_guard
```

只临时停服保留配置：`systemctl stop` 即可。默认 `DESTROY_TABLE_ON_EXIT = False`，停服后 nft 表和黑名单元素保留，但 `prerouting` 链规则被 flush——停服期间不拦截。

---

## 附：一页部署速查

```bash
# 1. 预检
nft --version && python3 --version
sudo apt install -y nftables

# 2. 克隆仓库
cd /root
git clone https://github.com/wishday/port_scan_guard.git port_scan_guard
chmod 700 /root/port_scan_guard
cd /root/port_scan_guard

# 3. venv + 依赖
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt

# 4. IP 库（仓库不含，单独下载）
sudo wget -O ip2region_v4.xdb "https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb"
sudo wget -O ip2region_v6.xdb "https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v6.xdb"
chmod 600 *.xdb

# 5. 脚本权限与语法检查
chmod 700 port_scan_guard_nft.py
venv/bin/python3 -m py_compile port_scan_guard_nft.py

# 6. 首次先开 DRY_RUN 观察（默认是 False！）
sudo sed -i 's/^DRY_RUN[[:space:]]*=[[:space:]]*False/DRY_RUN    = True/' port_scan_guard_nft.py

# 7. 前台测试
sudo /root/port_scan_guard/venv/bin/python3 /root/port_scan_guard/port_scan_guard_nft.py
# Ctrl+C 退出

# 8. systemd
sudo tee /etc/systemd/system/port-scan-guard.service << 'EOF'
[Unit]
Description=Port Scan Guard (nftables)
After=network-online.target nftables.service
Wants=network-online.target nftables.service
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/root/port_scan_guard/venv/bin/python3 /root/port_scan_guard/port_scan_guard_nft.py
WorkingDirectory=/root/port_scan_guard
Restart=always
RestartSec=5
TimeoutStopSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now port-scan-guard
sudo systemctl status port-scan-guard

# 9. 观察
sudo journalctl -u port-scan-guard -f

# 10. 切生产（观察 1~3 天确认无误封后）
sudo sed -i 's/^DRY_RUN[[:space:]]*=[[:space:]]*True/DRY_RUN    = False/' port_scan_guard_nft.py
sudo systemctl restart port-scan-guard

# 11. 验证规则链
sudo nft list chain inet port_scan_guard_host prerouting
```
