# Port Scan Guard（nftables）

基于 nftables 的高危端口扫描防护脚本：监听从指定端口发起的入站新连接，非白名单来源即时拉黑（默认 24 小时）；同时记录 ICMP ping 探测（默认只记录、不封禁、不丢包，可通过开关改为封禁）。

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

- 监听 `TCP_PORTS` / `UDP_PORTS` 清单内的端口，任何**非白名单**来源的入站新连接都会被加入 nft 黑名单（时长 `BAN_TIME`，默认 86400 秒 = 24 小时）。IPv6 来源默认**逐地址**封禁，与 IPv4 语义对称；想让同一前缀共用一个槽位就调 `V6_AGG_PREFIXLEN`。
- 同时记录 ICMP echo-request（ping）探测：默认只写数据库，不加黑名单、不丢包——用于审计"谁在探测 NAS 是否在线"；把 `ENABLE_ICMP_BAN` 设为 `True` 可改为同样拉黑 24 小时。
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
- 回环（`127.0.0.0/8`、`::1`）在用户态与 nft 白名单两侧都放行；未指定/多播源地址不会触发封禁（它们本身不是合法源地址，nft 仍会按扫描规则丢弃）。
- IPv4-mapped IPv6（`::ffff:a.b.c.d`）会自动归一为 IPv4 处理，避免误写入 IPv6 黑名单却拦不住 IPv4 流量。
- IPv6 默认**逐地址**封禁（`V6_AGG_PREFIXLEN = 128`），封谁就是谁，与 IPv4 封一个公网 IP 完全对称，不存在"连带封掉同网段别人"的问题。若确认面临"每包换一个源地址"的扫描压力，可以把 `V6_AGG_PREFIXLEN` 调到 `64` 开启聚合——代价是一次误判会波及整个前缀，详见 [`V6_AGG_PREFIXLEN`](#62-必须确认的配置项)。

---

## 二、环境预检

### 2.1 nftables

```bash
nft --version
```

要求 **≥ 1.0.6**（1.0.9 已实测）。per-IP 日志配额依赖 dynamic set 与 `update @set { ... limit ... }`；低于该版本会加载失败，须先升级 nftables。未安装：

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

`requests` 仅用于离线库缺失国家或 ISP 时的在线补充；未安装时可正常运行（只是没有在线补充）。在线查询失败或限流后熔断 5 分钟，期间完全使用离线结果；`ONLINE_API` 置空可彻底关闭在线查询。

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

> `DRY_RUN` 影响**所有**封禁动作：端口扫描只记不封；ICMP 在 `ENABLE_ICMP_BAN=True` 时同样只写库不拉黑，记录照常。

**`PRIVATE_NETS`（默认私网白名单）**

```python
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
```

这五个网段**永远放行**：不写日志、不封禁，nft 里对应一条 `ip saddr @..._wl4 return`。所以局域网里其他机器扫你的端口不会被封——这是刻意的，否则 NAS 自己的容器网络、同网段设备一扫描就互相拉黑。

回环网段由固定常量 `LOOPBACK_NETS`（`127.0.0.0/8`、`::1/128`）提供，同样并入白名单 set：本机进程访问监测端口不会被拦截，也不会产生封禁记录。

要收紧（比如只想放行某个 `/24`）就直接改 `PRIVATE_NETS`。注意这里用的是 `return` 而不是 `accept`：`return` 只结束本 chain 的处理，包继续按正常路径走，Docker 的 DNAT 端口映射不受影响；写成 `accept` 会跳过整个 PREROUTING hook，把映射打断。

**`EXTRA_WHITELIST`**

```python
EXTRA_WHITELIST = [
    # ipaddress.ip_network("2409:8a00:1234:5678::/64"),  # 你的家宽 IPv6 前缀
]
```

白名单来源访问监测端口也不会被封。

**`BAN_DEDUP_WINDOW`**

默认 10 秒。同一 IP 的**同类事件**（端口扫描 / ICMP 各自独立）在窗口期内只处理一次，避免日志刷屏时反复写库 / 调 nft。库增长太快可调大（如 300）。

**`V6_AGG_PREFIXLEN`（IPv6 聚合前缀，默认 `128` = 不聚合）**

IPv6 的封禁与日志配额按这个前缀长度聚合：`128` 表示**逐地址**（默认，与 IPv4 完全对称）；`64` 表示同一 `/64` 内所有地址共用**一个黑名单槽位**、**一个令牌桶**。

**为什么默认不聚合**：IPv6 换源成本为零，但"一个 `/64` = 一个用户"并不总成立，共享 `/64` 的现实场景不少：

| 场景 | 同一个 `/64` 里还有什么 | 按 `/64` 封的后果 |
| --- | --- | --- |
| 家宽（PPPoE + PD 前缀） | 这一户的全部设备（NAS、手机、电脑） | 基本无损，等价于 IPv4 封一个公网 IP |
| 移动网络（4G/5G） | 只有它自己（3GPP 规定每会话一个 `/64`） | 无影响 |
| **云主机子网** | **同子网内几十上百台其他用户的实例**（AWS 的 VPC 拿 `/56`、每个子网 `/64`；Azure 强制子网为 `/64`） | 可能封掉大量无关租户 |
| PPPoE 接入侧共享链路前缀 | 同 BRAS 下大量其他家宽用户 | 一片用户被封 |
| 公共 WiFi / 校园网 / 企业 NAT 出口 | 一栋楼、一个 SSID、整个企业 | 整个出口被封 |

后三类是默认不聚合的直接理由：逐地址封禁没有误封风险，代价只是抗"随机源扫描"能力弱。

**什么时候该改成 `64`**：日志里出现"同一 `/64` 内每包换一个源地址"的扫描时。逐地址封禁下，黑名单容量就是唯一防线——`524288` 槽在 100 封禁/s 下约 **87 分钟**耗尽，之后新地址一律封不住。聚合能把换源门槛从"单机随意伪造"抬到"要掌握几万个不同子网"，与 IPv4 僵尸网络同一量级。

**语义变化（仅 `V6_AGG_PREFIXLEN < 128` 时生效）**：IPv6 的封禁单位从"单个地址"变成"整个网段"，一次误判会波及同前缀的其他设备。此时日志会同时给出封禁范围与触发地址：

```
[2026-11-17 11:20:19] ban 2001:db8:77::/64:TCP/9999 (触发 2001:db8:77::a1) (...)
```

数据库的 `ip` 字段仍记录**原始触发地址**（`2001:db8:77::a1`），便于审计；nft set 里存的是归一后的网段地址。

白名单按网段匹配（`flags interval`），不受聚合影响。

> **白名单与聚合的交互（只在调成 `< 128` 后才有意义）**：黑名单规则的顺序在**白名单之前**（封禁优先）。所以如果你在 `EXTRA_WHITELIST` 里放的是单个 `/128` 地址（如 `2001:db8:77::a1/128`），而同前缀的另一个地址触发了封禁，整个 `2001:db8:77::/64` 会被 drop——白名单里那个地址也跟着被拦。开启聚合时，v6 的白名单条目建议直接写 `/64` 前缀，与聚合粒度对齐。

| 值 | 效果 |
| --- | --- |
| `128`（默认） | 逐地址封禁，与 IPv4 对称，不会牵连同网段的其他地址 |
| `64` | 同 `/64` 共用一个封禁槽位与配额桶，适合对抗 v6 随机源扫描 |
| `56` / `48` | 更粗，抗灌能力更强，但误封面也更大（可能封掉同一户之外的相邻用户） |

> 允许范围是 `32`–`128`，超出会被配置校验拦下：比 `/32` 更粗的前缀在防护上没有意义，只会把海量无关地址并进同一个封禁槽位。

> **把 `V6_AGG_PREFIXLEN` 从聚合值调回 `128` 时**：set 里原有的元素是归一后的前缀地址（如 `2001:db8:77::`），逐地址匹配下只有"源地址恰好等于该网络地址"的包才会命中，等于失效。启动恢复逻辑（`_restore()`）无法反推出原来的主机地址——那段信息在归一时就已经丢了。影响有限：最多 `BAN_TIME`（24 小时）后自然清空，期间这些来源只是失去"全端口封禁"，监测端口仍由独立的 drop 规则拦截。想立刻清干净就 `nft flush set inet <表名> <表名>_bl6`。

**`SET4_MAXELEM` / `SET6_MAXELEM`（黑名单容量）**

默认两侧都是 `524288`（IPv4 / IPv6，即 2^19）。这是**黑名单 set** 的上限，`size` 只是**上限、不预分配**：每元素约 **200 字节**（IPv4 196B / IPv6 214B，带 timeout 扩展），所以推满的内存是：

| | 容量 | 每元素 | 推满内存 |
| --- | --- | --- | --- |
| IPv4 | `524288` | 196 B | ≈ 98 MB |
| IPv6 | `524288` | 214 B | ≈ 107 MB |

合计约 **205 MB**，但这是"两侧同时装到上限"的情况。

黑名单打满降级后果是温和的：`tcp dport @.._tcp ... drop` 是无条件规则、不依赖黑名单，扫描监测端口的包照样被丢；只是这些 IP 不再获得"全端口封禁"。

**`DB_RETENTION_DAYS`**

默认 180 天。设为 `<= 0` 表示完全不清理（数据库只增不减）。

**`ENABLE_ICMP_LOG` / `ENABLE_ICMP_BAN`（ICMP 策略）**

| 开关 | 默认 | 含义 |
| --- | --- | --- |
| `ENABLE_ICMP_LOG` | `True` | 是否记录非白名单的 ping 探测。设 `False` 则 nft 层不生成 ICMP 日志规则，也就没有后续封禁 |
| `ENABLE_ICMP_BAN` | `False` | 是否对命中的 ping 执行封禁。`False` = 只写库、不碰 nft、不丢包；`True` = 加入黑名单 24 小时，该 IP 的**所有**流量（含 TCP/UDP）一起被丢弃 |

两者都开就是"记录 + 封禁"，只开 `ENABLE_ICMP_LOG` 是纯观察模式。

**ICMP 封禁会误伤吗**：会。正常运维的连通性探测（监控 ping、拨测）每次都是新的源，命中即封 24 小时，且封的是该 IP 的**全部**端口。建议先开记录模式跑一段时间，用[第十二节](#十二数据库查询速查)的 SQL 看看 ping 来源都是谁，再决定是否开 `ENABLE_ICMP_BAN`；确实要开就把监控探针加进 `EXTRA_WHITELIST`。

**ICMP 与 per-IP 配额的关系**：只有在"真会封禁"（`ENABLE_ICMP_BAN=True` 且 `DRY_RUN=False`）时 ICMP 规则才**占**配额，其余情况**不占**。模式差异的原因见[日志配额](#62-必须确认的配置项)一节的说明。开启封禁后有个副作用要知道：同一 IP 的 ping 与端口扫描共用一个配额桶，**ping 之后 1 秒内的扫描可能进不了日志**——但那一刻 ping 已经触发封禁，拦截效果不受影响。

**`ENABLE_FLAG_SCAN`**

默认 `True`：除纯 SYN 扫描外，额外检测 **FIN / XMAS 扫描**（`tcp flags fin`）与**NULL 扫描**（六个标志位全为 0）。两条规则都要求 `ct state invalid,untracked`，因此正常连接关闭时的 FIN 不会被误判；依赖 `nf_conntrack`。设为 `False` 则只保留 SYN 规则。ACK 扫描（`-sA`）不在覆盖范围内，原因见[第一节](#一功能与边界)。

**日志配额（决定"能不能封得住"）**

**每个源 IP 一个令牌桶**（`LOG_QUOTA_RATE = "1/second"`、`burst 2`），谁也不能把别人的日志配额挤掉。

为什么需要它：nft 的 `limit` 默认是"每条规则一个桶、所有来源共享"。一个 IP 就能把桶打满，其他来源的扫描就完全不写日志 → 不进黑名单。分布式扫描（100 个 IP 各扫一次）会只剩前几个被记录，等于被噪音致盲。

配额给小会不会漏封？**不会**。封禁只需要**一条**日志，burst 2 足够触发；单个 IP 首秒最多留 2 条、之后稳态 1 条/秒，日志量比"命中即记"少得多。

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `LOG_QUOTA_RATE` / `LOG_QUOTA_BURST` | `1/second` / `2` | 每个源 IP 的配额。想多留证据可调大到 `2/second` / `5` |
| `LOG_QUOTA_TIMEOUT` | `60s` | 配额元素空闲多久释放；持续扫描的 IP 会一直持有。**不要写 `0s`**：nft 接受但含义是"无超时"，元素永不释放，set 只增不减 |
| `LOG_QUOTA_SET4/6_MAXELEM` | `65536` / `65536` | 能同时跟踪的源数（`V6_AGG_PREFIXLEN < 128` 时 v6 按前缀计，即"前缀数"；默认逐地址时按地址计）。正常不会满（见下），是极端情况的安全边界；**真满了该族的新源完全不写日志、不进黑名单** |
| `LOG_GLOBAL_RATE` / `BURST` | `100/second` / `150` | 每条规则的总量兜底（不区分来源 IP）。实际天花板是「规则条数 × 本值」；它同时是 set 元素的创建速率上限，用户态单线程约几百条/秒就饱和，不宜再调大 |

per-IP 配额依赖 nft 的 dynamic set 与 `update @set { ... limit ... }`（要求 ≥ 1.0.6，1.0.9 已实测），`nft < 1.0.6` 会直接报 `update` 语法错误，须先升级 nftables。限速必须按源 IP 分桶：nft 的 `limit` 是每条规则一个令牌桶、所有来源共享，单个 IP 打满就能让其他来源的日志全部丢失，等于被单点噪音致盲。

**为什么正常不会被灌满**

nft 的规则语句顺序执行、任一 match 失败即中断整条规则，所以超过兜底限速的包**根本走不到 `update`**，不会占用 set 槽位。于是：

- 单条规则的元素创建速率被 `LOG_GLOBAL_RATE`（100/s）封顶
- 但每个协议族有 4 条扫描规则（TCP SYN/FIN/NULL + UDP，开 ICMP 封禁时 5 条），速率是**相加**的
- 稳态元素数上限 ≈ `规则数 × 100/s × LOG_QUOTA_TIMEOUT(60s)` ≈ **24000**（开 ICMP 封禁 ≈ 30000）
- 所以容量取 `65536`（两侧一致），留 2 倍以上余量

**`NFT_TABLE` / 日志前缀（容器场景重点）**

默认表名 `port_scan_guard_host`，日志前缀 `HOST_SCAN:`（端口扫描）与 `HOST_ICMP:`（ICMP）。容器与宿主机必须使用**不同**前缀，否则会同时封禁——详见[第十五节](#十五容器--macvlan-部署)。

启动时的 `[*] nft 表：inet ...；日志前缀：... / ...` 一行会打印**当前生效**的表名与两个前缀，加载失败与恢复失败的告警里也会带上它们。nft 自身的报错只给 `/dev/stdin:38:69` 这类行号，不带表名，靠这行才能确认失败的是哪一个实例。

**启动前会自动校验配置**（`_validate_config()`，在 `setup_firewall()` 之前），非法值直接退出并列出全部问题，不会带着坏配置上生产：

| 校验项 | 为什么 |
| --- | --- |
| 表名只含字母/数字/`_`/`.`/`-` | 含空格等字符会拼出非法 nft 语句 |
| 前缀非空、不含 `"` 与换行、≤120 **字节**（UTF-8 编码后，中文 1 字 3 字节） | 前缀是直接拼进 `log prefix "..."` 的；实测 127 字节 nft 就报 `log prefix is too long` |
| 两个前缀不相等，且 `ICMP_PROBE_PREFIX` 不是 `PORT_SCAN_PREFIX` 的子串 | **这类错误 nft 不会报，只会静默失效**：所有扫描日志都被判成 ICMP 探测，端口扫描永不封禁 |
| `PRIVATE_NETS` / `LOOPBACK_NETS` / `EXTRA_WHITELIST` 的每个元素都是 `ip_network` 对象 | `_build_nft_config()` 需要访问 `.version`；写成字符串时启动校验直接报错并指出具体元素 |
| 端口在 1~65535 内 | 越界值会写进 nft set，整表加载失败 |
| 速率形如 `1/second`、`timeout` 带单位且数值 ≥ 1 | 实测 `timeout 60`（漏单位）直接语法错误，而 nft 的报错只给行号；`rate 0/second` 会被 nft 拒绝导致整表加载失败；`timeout 0s` 语法合法但实测含义是「无超时」——元素永不释放，配额 set 只增不减，满了该族新源就不写日志、不进黑名单，且启动无任何报错 |
| `BAN_TIME` / `burst` 为正整数 | 拼进 `timeout 86400s` / `burst N`，非法值整表加载失败 |
| `LOG_QUOTA_SET4/6_MAXELEM`、`SET4/6_MAXELEM` 为正整数 | `size 0` 时 nft 的报错会**错位到别的行**（实测报的是后面那行的 `unexpected '}'`），根本看不出是 size 写错了。黑名单两项与日志配额是两套 set，各自校验 |
| `V6_AGG_PREFIXLEN` 在 `32`–`128` 内 | 越界会让 `ipaddress` 抛异常；比 `/32` 更粗的前缀会把海量无关地址并进同一个封禁槽位，一次误判等于封掉一大片 |
| `NFT_PREROUTING_PRIORITY` 为整数 | 生成的是 `priority -110;`，写成字符串或 `dstnat - 10` 这类表达式会直接语法错误 |

两类情况只告警、不退出：

- `ENABLE_ICMP_BAN=True` 配 `ENABLE_ICMP_LOG=False`：不影响端口扫描封禁，硬退出会让服务起不来。
- `NFT_PREROUTING_PRIORITY >= -100`：取值本身合法，nft 也接受，但规则会排在 Docker DNAT（`-100`）之后或与之同时——此时 `dport` 已被改写成容器内端口，清单里的宿主机端口一个都匹配不到，**不报任何错，防护静默失效**。非 Docker 环境用 `-10` 属正常，所以只告警。

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
[*] 黑名单容量：IPv4 524288 / IPv6 524288 条（满表约 98MB + 107MB，不预分配）
[*] IPv6 封禁：逐地址（V6_AGG_PREFIXLEN = 128，未聚合）
[*] ICMP：只记录非白名单 echo-request，不封禁、不丢包（不占 per-IP 配额）
[*] 数据库：/root/port_scan_guard/scan.db
[*] 保留策略：最近 180 天，每 24 小时检查一次
[*] DRY_RUN = False：按各开关实际封禁
[*] 日志配额: 每源 IP 1/second / burst 2；每规则兜底 100/second（仅影响 log，不影响 drop）
[*] 配额 set 容量：IPv4 65536 / IPv6 65536 条/族（满了该族新源不再写日志）
[*] UDP 日志仅对 ct state new 生效（依赖 nf_conntrack）
[*] 日志来源: journalctl -k -f
```

`DRY_RUN = True` 时对应行变为：

```
[!] DRY_RUN = True：所有封禁（含 ICMP）只记录不执行
```

关注点：

- `[!] 离线库不存在` / `[!] IPv4 离线库未加载` → 检查 xdb 路径/权限；不影响封禁功能。
- `[!] 日志流异常` / `[!] 日志流已中断` → 脚本 5 秒后自动重连；连续 5 次异常或日志流打开后立即结束（如无权限、日志服务未运行），脚本退出并由 systemd 重启/告警，避免 `active` 状态下实际不封禁。
- `黑名单容量` 显示的是**两侧同时装到上限**的最坏情况，不是启动即占用的内存：`size` 只声明上限、不预分配，实际水位几十到几百条时几乎不占。它的用处是出事时对账——`nft list set inet <表名> <表名>_bl4` 的元素数逼近这个数字，就该调容量或开 v6 聚合（见 [`SET4_MAXELEM`](#62-必须确认的配置项)）。紧跟的 `配额 set 容量` 同理，而且满载更隐蔽：只丢日志、不丢包，库里连痕迹都没有。
- `日志配额: 每源 IP 1/second` 是**按源地址分桶**的：每个 IP 有自己的令牌桶，谁也挤不掉谁。配额给小不影响封禁——**封禁只需要 1 条日志**，burst 2 已足够触发；单个 IP 首秒最多 2 条、之后稳态 1 条/秒，日志量远低于命中即记。后面的 `100/second` 是**每条规则**的总量兜底（不区分来源 IP），防止海量 IP 各刷配额把内核日志打爆，同时也给 set 元素的创建速率封顶；实际天花板是"规则条数 × 100/s"，不是整机 100/s。调参见[日志配额](#62-必须确认的配置项)。
- **ICMP 是否占配额 = 是否"真的会封禁"**，即 `ENABLE_ICMP_BAN=True` **且** `DRY_RUN=False`：
  - 不占配额（默认，或 `DRY_RUN=True`）→ 规则**不带** `update @..._lq4`，只受各自 `100/second` 兜底。因为 ICMP 不封禁，让它占配额会被"每秒 1~2 个 ping"反向利用：同一 IP 的端口扫描将永远写不进日志、永不被封。副作用是 ping flood 时日志上限变成每规则 `100/s`；用户态还有 10 秒去重（同一 IP 每 10 秒最多 1 行），实际写库量远低于此。
  - 占配额（`BAN=True` 且 `DRY_RUN=False`）→ 规则**带** `update @..._lq4`，与 TCP/UDP 共享该 IP 的桶。此时不存在上述绕过（第一个 ping 就把自己封了），配额反而保证"每 IP 至少一条记录"。
  - **`DRY_RUN=True` 时 ICMP 一定不占配额**：那时候 ping 并不会被封，占了配额只会把同一 IP 的扫描日志挤掉，让观察期数据失真（看起来"没人扫我"），而这种失真恰好在切生产前最难发现。

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
- ICMP 探测（仅记录）：`[时间] icmp_probe IP (国家/省/市/ISP) [来源]`
- ICMP 探测（`ENABLE_ICMP_BAN=True`）：`[时间] ban IP:ICMPv6 (国家/省/市/ISP) [来源]`，与端口扫描同一套 `ban` / `dry_run` / `ban_failed` 输出

`result` 取值：`dry_run`（只记录）、`ban`（已封禁）、`ban_failed`（封禁失败）、`icmp_probe`（ICMP 仅记录）。`event_type` 为 `icmp` 时，`result` 可能是 `icmp_probe`（仅记录模式）或 `ban` / `dry_run`（封禁模式）。
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
# IPv4
sudo nft delete element inet port_scan_guard_host port_scan_guard_host_bl4 '{ <IP> }'

# IPv6（默认逐地址封禁，写触发封禁的那个完整地址即可）
sudo nft delete element inet port_scan_guard_host port_scan_guard_host_bl6 '{ <IP> }'
```

> 若把 `V6_AGG_PREFIXLEN` 调成了 `< 128`，set 里存的就是归一后的**网络地址**：想解封 `2001:db8:77::a1` 触发的封禁，要删 `2001:db8:77::`（`/64` 时）——写主机地址会报 `No such file or directory`。不确定存的是什么就先 `nft list set inet port_scan_guard_host port_scan_guard_host_bl6` 看一眼。

> nft 表默认不持久化：系统重启后，已被封禁的 IP 不会自动加回。脚本启动时会尝试从**仍存在的** nft set 按剩余时间恢复封禁；若系统级 `nftables.service` 在启动时 flush 了规则，则无法恢复。

---

## 十二、数据库查询速查

数据库：`/root/port_scan_guard/scan.db`，表 `bans`。

字段：`id, ts, time_str, ip, family, port, protocol, country, province, city, isp, source, duration, result, event_type`。

- `event_type`：`port_scan`（端口扫描）/ `icmp`（ICMP 探测）。
- `result`：`dry_run` / `ban` / `ban_failed` / `icmp_probe`。
- `duration`：实际封禁秒数。`result=ban` 记 `BAN_TIME`（ICMP 封禁同样）；`dry_run`、`ban_failed`、`icmp_probe` 均记 `0`。
- ICMP 记录的 `port` 为 `NULL`（两种模式都是）。
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
  "SELECT time_str, ip, protocol, result, country, isp, source FROM bans \
   WHERE event_type='icmp' AND ts > strftime('%s','now')-86400 \
   ORDER BY ts DESC LIMIT 50;"
```

`result` 为 `icmp_probe` 表示仅记录（默认模式），`ban` / `dry_run` 表示 `ENABLE_ICMP_BAN=True` 下的封禁动作。

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
#备份现有脚本，下载最新脚本，然后重启服务
sudo systemctl restart port-scan-guard
```

---

## 十四、故障排查

| 现象 | 可能原因 | 排查 |
| --- | --- | --- |
| 服务启动后无事件 | 内核日志源不可用 | 执行 2.2 节测试；检查 `nf_log_ipv4/ipv6` |
| `[!] 离线库不存在` | xdb 路径/权限错 | `ls -l /root/port_scan_guard/*.xdb` |
| `[!] nft 添加元素失败` | nft 版本/权限；或 set 已满（此时报的是 `Too many open files in system`，别去查 ulimit） | `nft --version`；`nft list set inet port_scan_guard_host port_scan_guard_host_bl4` 看元素数是否逼近容量 |
| `[!] 恢复封禁记录部分失败：成功 X 条 / 失败 Y 条` | 旧封禁数超过当前 `SET4/6_MAXELEM`，超出的批次写不进去。报错文案同样是 `Too many open files in system` | 调大容量后重启；失败那批的元素信息已随重建前的表一起删除，确需恢复只能按 `bans` 表手工重封 |
| IPv6 明明已封禁，流量却照过（日志里也没有 `ban_failed`） | **仅开启聚合后**（`V6_AGG_PREFIXLEN < 128`）会出现：set 里存的是未归一的主机地址，而匹配是 `ip6 saddr & <mask>`，掩码后查不到——封禁记录躺着但完全不生效，且 nft 不报错 | `nft list set inet port_scan_guard_host port_scan_guard_host_bl6` 看元素形态；重启服务（启动恢复时会把已有元素归一），或按 [11.2](#112-手动解封) 删掉重封 |
| 自己从公网访问被误封 | 公网 IP 未加白名单 | 加入 `EXTRA_WHITELIST` 或注释掉端口 |
| Docker 映射端口连不上 | 链里有 `accept`（应为 `return`） | `nft list chain inet port_scan_guard_host prerouting \| grep wl4` |
| `protocol` 全为 NULL | 数据库里的历史记录（写入时未解析协议） | 当前脚本正常不会产生 NULL，确认 `PORT_SCAN_RE` 里 `PROTO` 在 `DPT` 之前 |
| `scan.db` 增长太快 | 被持续扫描 + 去重窗口小 | 调大 `BAN_DEDUP_WINDOW`，或暂时保持 `DRY_RUN=True` |
| 服务反复退出/重启 | nft 配置错误、权限不足，或连续 5 次拿不到内核日志源（`setup_firewall` / 日志源失败都会退出） | `journalctl -u port-scan-guard -n 100 --no-pager` |
| 启动时报 `conntrack` 相关错误 | 内核缺 `nf_conntrack` | 设 `UDP_NEW_CONN_ONLY=False`、`ENABLE_FLAG_SCAN=False`，或 `modprobe nf_conntrack` |
| 启动报 `update ... syntax error` | nft < 1.0.6，不支持 dynamic set | 升级 nftables 到 ≥ 1.0.6 |
| 某个来源的扫描没被封 | 该 IP 配额在窗口内已用尽（首秒只记前 2 个，之后每秒 1 个） | 属预期：封禁只需 1 条日志；要留更多证据就调大 `LOG_QUOTA_BURST` |
| 前 N 个来源被封，之后的新来源都不封（N 接近 set 容量） | `_lq4` / `_lq6` 被填满，`update` 失败会中断整条 log 规则。正常不会发生：兜底 `limit` 已前置，单条规则的创建速率被封顶在 100/s，4 条规则累加后稳态上限约 24000，对 65536 有 2 倍以上余量 | 用 `nft list set inet <表名> <表名>_lq4` 看元素数；调小 `LOG_QUOTA_TIMEOUT`（如 `10s`）或增大 `LOG_QUOTA_SET4_MAXELEM`；临时处置 `nft flush set inet <表名> <表名>_lq4` |
| 某 IP 一直在扫却始终不封，同时它还在 ping 本机 | `ENABLE_ICMP_BAN=True` 时 ICMP 会占用该 IP 的配额；若这些 ping 恰好没被封（如落在去重窗口或配额之外），扫描仍会被卡住 | 改回 `ENABLE_ICMP_BAN=False`（默认，ICMP 不占配额） |
| 监控/拨测的 ping 把我自己封了 | 开了 `ENABLE_ICMP_BAN=True`，探测源不在白名单 | 把探针 IP 加进 `EXTRA_WHITELIST`，或改回默认的仅记录模式 |
| 重启后已封禁 IP 又通了 | 系统级 `nftables.service` 启动时 flush 了规则 | `nft list set inet port_scan_guard_host port_scan_guard_host_bl4`；日志找 `恢复封禁记录: 成功 N 条` |
| 容器内无日志/不封禁 | 未开 `nf_log_all_netns` 或挂载内核日志 | 见[第十五节](#十五容器--macvlan-部署) |
| 日志里出现 `[!!] nft 表 ... 已不存在` | 有人/别的服务删了整张表（`systemctl restart nftables`、`nft flush ruleset`、Docker 重配网络）。此时**规则和黑名单全没了**，脚本只会写 `ban_failed` | `nft list table inet port_scan_guard_host` 确认；`systemctl restart port-scan-guard` 重建。脚本不会自动重建，详见下方说明 |
| 启动即退出，提示「配置校验未通过」 | 表名/前缀/速率/端口清单有非法值 | 按提示逐条改脚本顶部配置区；`journalctl -u port-scan-guard -n 20 --no-pager` 看完整清单 |

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

> 清理只发生在主动停服（SIGTERM/SIGINT）。进程异常崩溃时 `atexit` 保留 nft 规则不 flush（fail-closed），监测端口的既有防护不中断；恢复由 systemd 重启完成。

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

# 7. 前台测试（横幅会打印黑名单容量 / 配额 set 容量 / IPv6 封禁粒度，对一下 6.2 的预期）
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
