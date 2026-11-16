#!/root/port_scan_guard/venv/bin/python3
# -*- coding: utf-8 -*-
"""
port_scan_guard_nft.py

监听一组高危端口，任意非白名单 IP 尝试连接其中任意一个端口，
立即通过 nftables 原生 set 拉黑 24 小时，支持 IPv4 和 IPv6。

同时监听 ICMP echo-request（ping）：只记录，不封禁，不丢包。
用于审计"谁在探测 NAS 是否在线"，不阻断任何 ping。

规则挂在 PREROUTING 链上，优先级 -110（在 Docker DNAT -100 之前）：
  - 在 DNAT 之前拦截，saddr / dport 都是原始值
  - 能保护宿主机自身端口，也能保护 Docker bridge 映射到容器的端口
  - 白名单 / DRY_RUN 使用 return 或空 verdict，避免 accept 破坏后续 chain

日志源优先级：systemd 系统优先 journalctl -k -f（数据源优先于文件副本），
非 systemd 系统回退到 /var/log/kern.log → messages → syslog。

封禁时查询 IP 归属地（离线库优先，缺失时在线补充），
记录写入 SQLite，方便后续筛选统计。

依赖：nft (nftables v1.0.9+)
      /root/port_scan_guard/venv 里的 py-ip2region + requests

用法：sudo /root/port_scan_guard/venv/bin/python3 \
          /root/port_scan_guard/port_scan_guard_nft.py
"""

import atexit
import ipaddress
import json
import os
import re
import select
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import time

# ============================================================
#                      1. 端口配置区
#  不再防护的端口，在前面加 # 注释即可（整行注释，端口才会失效）。
#  macvlan 场景：宿主机这些端口都是空的（服务在容器 netns 里），
#  任何到达宿主机这些端口的包都是扫描 → 全部纳入防护。
#  如果某端口你从公网访问（如 DDNS 直连 NAS 面板），
#  要么注释掉本行，要么把访问源 IP 加入 EXTRA_WHITELIST。
#  ✔部署到macvlan容器需要确保PORT_SCAN_PREFIX  ，ICMP_PROBE_PREFIX  端口扫描日志前缀（内核 nft log），容器与host区分，否则会同时封禁
#  ✔容器中部署需要打开宿主机内核参数，允许容器nft日志写到内核: sudo sysctl -w net.netfilter.nf_log_all_netns=1，同时需要把内核日志挂载到容器只读: -v /var/log/kern.log:/var/log/kern.log:ro
# ============================================================
TCP_PORTS = [
    21,         # FTP
    22,         # SSH
    23,         # Telnet
    25,         # SMTP
    53,         # DNS (TCP)
    69,         # TFTP
    80,         # HTTP
    110,        # POP3
    111,        # RPCbind
    135,        # MS RPC
    137,        # NetBIOS-NS
    138,        # NetBIOS-DGM
    139,        # NetBIOS-SSN
    143,        # IMAP
    161,        # SNMP
    162,        # SNMP Trap
    389,        # LDAP
    443,        # HTTPS
    445,        # SMB
    465,        # SMTPS
    500,        # ISAKMP
    514,        # Syslog
    515,        # LPD
    548,        # AFP
    554,        # RTSP
    587,        # SMTP Submission
    631,        # IPP/CUPS
    636,        # LDAPS
    873,        # Rsync
    993,        # IMAPS
    995,        # POP3S
    1080,       # SOCKS Proxy
    1194,       # OpenVPN
    1433,       # MSSQL
    1521,       # Oracle DB
    1701,       # L2TP
    1723,       # PPTP
    1883,       # MQTT
    #2017,       # v2raya WebUI
    2049,       # NFS
    2082,       # cPanel
    2083,       # cPanel SSL
    2222,       # SSH 替代
    2323,       # Telnet 替代
    2345,       # 迅雷远程下载
    2375,       # Docker API
    2376,       # Docker TLS
    3000,       # Node/Grafana / MoviePilot
    3260,       # iSCSI
    3306,       # MySQL
    3389,       # RDP
    4444,       # Metasploit
    4533,       # Navidrome
    5000,       # Flask / Synology DSM HTTP
    5001,       # Synology DSM HTTPS
    5244,       # OpenList / AList
    5432,       # PostgreSQL
    5555,       # ADB
    5601,       # Kibana
    5672,       # RabbitMQ
    5900,       # VNC
    5985,       # WinRM HTTP
    5986,       # WinRM HTTPS
    6379,       # Redis
    6443,       # Kubernetes API
    6667,       # IRC
    6881,       # qBittorrent BT
    7001,       # WebLogic
    7002,       # WebLogic SSL
    8000,       # 通用 HTTP
    8006,       # Proxmox VE
    8008,       # 通用 HTTP
    8009,       # AJP/Tomcat
    8069,       # Odoo
    8080,       # HTTP 替代
    8081,       # HTTP 替代
    8082,       # HTTP 替代
    8086,       # InfluxDB
    8088,       # Hadoop YARN
    8090,       # Xiaomusic / 通用 HTTP
    8096,       # Jellyfin HTTP
    8123,       # Home Assistant
    8161,       # ActiveMQ
    8300,       # Emby HTTP
    8384,       # Syncthing WebUI
    8443,       # HTTPS 替代
    8883,       # MQTT TLS
    8888,       # Jupyter
    8920,       # Jellyfin / Emby HTTPS
    8923,       # Qiandao
    9000,       # PHP-FPM / SonarQube
    9001,       # Supervisor
    9042,       # Cassandra
    9090,       # Cockpit / Dashboard
    9091,       # Transmission RPC
    9092,       # Kafka
    9200,       # Elasticsearch
    9300,       # Elasticsearch
    9418,       # Git
   # 9443,      # Portainer
    9999,       # 通用管理
    10000,      # Webmin
    10250,      # Kubelet
    11211,      # Memcached
    15672,      # RabbitMQ 管理
    16601,      # Lucky
    22000,      # Syncthing 数据传输
    26666,     # samwaf
    27017,      # MongoDB
    27018,      # MongoDB 分片
    32400,      # Plex
    50000,      # SAP
    50070,      # Hadoop NameNode
    51413,      # Transmission BT
    61616,      # ActiveMQ
]

# 只提供 UDP 服务的端口。默认全空。
UDP_PORTS = [
    123,        # NTP
    161,        # SNMP
    162,        # SNMP Trap
    1900,       # UPnP/SSDP
    514,        # Syslog
]

# ============================================================
#                      2. 白名单配置区
# ============================================================
# 内网 / 私有网段：永远放行，不记录、不封禁。
# 如需收紧（比如只想放行某个 /24），直接改这里。
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# 额外白名单（公网 IP / 网段）。
# 典型场景：
#   - 家宽有公网 IPv6，你想从手机 5G 访问 NAS → 把家宽 IPv6 前缀填进来
#   - 有 VPS 需要访问 NAS 某端口 → 把 VPS IP 填进来
# 示例：
#   ipaddress.ip_network("203.0.113.45/32"),
#   ipaddress.ip_network("1111:2222:3333:4444::/64"),
EXTRA_WHITELIST = [
    # ipaddress.ip_network("1111:2222:3333:4444::/64"),  # 你的家宽 IPv6 前缀
]

# ============================================================
#                      3. 行为配置区
# ============================================================
BAN_TIME   = 86400              # 封禁时长（秒）= 24 小时

PORT_SCAN_PREFIX  = "HOST_SCAN:"     # 端口扫描日志前缀（内核 nft log），容器与host需要区分，否则会同时封禁
ICMP_PROBE_PREFIX = "HOST_ICMP:"    # ICMP 探测日志前缀，容器与host需要区分，否则会同时封禁

# ICMP 只记录不封禁：
#   - 白名单 IP 的 ping 不记录（nft 层 return 直接放行）
#   - 非白名单 IP 的 ping 只写 SQLite，不加入 nft 黑名单，不丢包
#   - 与端口扫描共用 BAN_DEDUP_WINDOW 去重
# 想关闭 ICMP 记录：改为 False
ENABLE_ICMP_LOG = True

# ★ DRY_RUN 只影响端口扫描的封禁动作，不影响 ICMP 记录
#   - DRY_RUN=True：端口扫描只记不封；ICMP 仍然只记
#   - DRY_RUN=False：端口扫描实际封禁；ICMP 仍然只记
DRY_RUN    = False

# 退出时是否删除整张 nft 表（包括已封禁 IP）。
# False = 保留封禁记录，重启服务后继续生效（推荐）；
# True  = 停服即全部解封，重启后从零开始。
DESTROY_TABLE_ON_EXIT = False

# nft set 最大容量
SET4_MAXELEM = 1048576
SET6_MAXELEM = 262144

# nft 表名（inet 族，与 Docker 的 ip/ip6 族隔离）
NFT_TABLE = "port_scan_guard_host"

# PREROUTING 链优先级：
#   -110 = dstnat(-100) - 10，比 Docker 的 DNAT 更早执行
#   用纯数字，避免旧版 nft 不识别 "dstnat - 10" 表达式
#   改成 filter 优先级（-10 或 0）会在 DNAT 之后，拦不到映射端口
NFT_PREROUTING_PRIORITY = -110

# 日志限速：防止被 DDoS 时内核日志刷爆
# ★ 注意：nft 中 limit 是匹配表达式，超速即"不匹配"并中断当前规则。
#   因此本脚本把 log 和 drop 拆成两条规则：
#     - log 规则受 limit 限速（超速包不写日志）
#     - drop 规则无条件执行（不受 limit 影响，保证安全）
# 关闭后日志量等于命中次数，仅在调试或低流量环境使用
USE_HASHLIMIT    = True
HASHLIMIT_RATE   = "5/sec"
HASHLIMIT_BURST  = 10

# UDP 规则是否只对"新建 conntrack 流"打日志（ct state new）
#   - True：同一 UDP 五元组只有第一个包参与 log 判定，
#           大幅降低日志量；依赖 nf_conntrack（Docker 环境默认可用）
#   - False：每个命中 UDP 端口的包都参与 log 判定（仍受 limit 限速），
#           不依赖 conntrack；日志量高，仅在 conntrack 不可用时使用
# ★ 无论本开关如何，drop 规则都不加 ct state，保证已建立流的后续包也丢弃
UDP_NEW_CONN_ONLY = True

CMD_TIMEOUT = 10                # 单条 nft 命令的超时（秒）

# 同一 IP 在窗口期内只处理一次（避免日志刷屏时反复写库 / 调 nft）
BAN_DEDUP_WINDOW = 10

# 归属地信息内存缓存
IP_INFO_CACHE_TTL  = 3600
IP_INFO_CACHE_MAX  = 10000

# ============================================================
#                      4. 归属地 & 数据库配置
# ============================================================
DB_PATH        = "/root/port_scan_guard/scan.db"
XDB_V4         = "/root/port_scan_guard/ip2region_v4.xdb"
XDB_V6         = "/root/port_scan_guard/ip2region_v6.xdb"

# 在线归属地查询（仅当离线库未命中时使用）
ONLINE_API     = ("http://ip-api.com/json/{ip}"
                  "?lang=zh-CN&fields=status,country,regionName,city,isp")
# ★ 用 (connect, read) 元组，避免单值 5 被解释为"各 5 秒"最坏 10 秒；
#   最坏总耗时 5 秒，远离 STOP_GRACE=8 的强制杀死边界
ONLINE_TIMEOUT = (2, 3)
UNKNOWN        = "未知"

# ---- 数据库保留策略 ----
# DB_RETENTION_DAYS <= 0 时完全不清理（数据库只增不减）
DB_RETENTION_DAYS    = 180       # 保留最近 N 天
DB_CLEANUP_INTERVAL  = 86400     # 清理检查间隔（秒）—— 默认 24 小时
DB_VACUUM_AFTER_CLEANUP = False  # 清理后是否 VACUUM（重写全库，慎用）

# ============================================================
#                      以下为脚本逻辑
# ============================================================

# 端口扫描日志：SRC=x ... PROTO=TCP SPT=n DPT=n
# 命名组，PROTO 在 DPT 之前，与内核日志实际顺序一致
# 内核 netfilter 打印顺序：... SRC=x ... PROTO=TCP SPT=n DPT=n ...
PORT_SCAN_RE = re.compile(
    r"SRC=\[?(?P<src>[0-9A-Fa-f:.]+)\]?"
    r"(?:.*?\bPROTO=(?P<proto>\w+))?"
    r"(?:.*?\bDPT=(?P<dport>\d+))?"
)

# ICMP 探测日志：SRC=x ... PROTO=ICMP TYPE=8 CODE=0
ICMP_PROBE_RE = re.compile(
    r"SRC=\[?(?P<src>[0-9A-Fa-f:.]+)\]?"
    r"(?:.*?\bPROTO=(?P<proto>ICMP(?:v6)?))?"
    r"(?:.*?\bTYPE=(?P<type>\d+))?"
)

# 兼容别名
LOG_RE = PORT_SCAN_RE
LOG_PREFIX = PORT_SCAN_PREFIX

_searcher_v4 = None
_searcher_v6 = None
_db_conn     = None

_recent_bans = {}
_extra_v4    = []
_extra_v6    = []

_ip_info_cache = {}

_firewall_setup_done = False

_shutdown_requested = False
_current_proc       = None

_last_cleanup_ts    = 0.0


# ---------------- 命令执行 ----------------

def sh(cmd, check=False, timeout=CMD_TIMEOUT):
    """执行外部命令，返回 CompletedProcess。失败不抛异常。"""
    if isinstance(cmd, str):
        argv = shlex.split(cmd)
    else:
        argv = list(cmd)
    try:
        return subprocess.run(argv, capture_output=True,
                              text=True, check=check, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[!] 命令超时({timeout}s): {argv}", flush=True)
        return subprocess.CompletedProcess(argv, 1, "", "timeout")
    except Exception as e:
        print(f"[!] 命令异常: {argv} -> {e}", flush=True)
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def _nft(args, check=False):
    return sh(["nft"] + list(args), check=check)


def _nft_load(text):
    """通过 nft -f - 加载配置文本。"""
    try:
        return subprocess.run(
            ["nft", "-f", "-"],
            input=text, capture_output=True, text=True,
            timeout=CMD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print("[!] nft -f 超时", flush=True)
        return subprocess.CompletedProcess(["nft"], 1, "", "timeout")
    except Exception as e:
        print(f"[!] nft -f 异常: {e}", flush=True)
        return subprocess.CompletedProcess(["nft"], 1, "", str(e))


def _nft_table_exists():
    r = _nft(["list", "table", "inet", NFT_TABLE])
    return r.returncode == 0


def _extract_set_elements(set_name):
    """从 nft set 中提取现有元素（用于重建表时恢复封禁）。

    返回 [(ip, expires), ...]。nft JSON 输出的 expires 单位是毫秒，
    调用方需自行 /1000 转为秒。
    """
    r = _nft(["-j", "list", "set", "inet", NFT_TABLE, set_name])
    if r.returncode != 0:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return []

    elements = []
    for obj in data.get("nftables", []):
        s = obj.get("set")
        if not s:
            continue
        for elem in s.get("elem", []):
            if isinstance(elem, str):
                elements.append((elem, None))
            elif isinstance(elem, dict):
                val = elem.get("val")
                exp = elem.get("expires")
                if isinstance(val, str):
                    elements.append((val, exp))
    return elements


def _nft_rate(rate_str):
    """'5/sec' / '5/s' → '5/second'（旧版 nft 不认缩写）"""
    s = rate_str.strip()
    if s.endswith("/second"):
        return s
    if s.endswith("/sec"):
        return s[:-4] + "/second"
    if s.endswith("/s"):
        return s[:-2] + "/second"
    return s


# ---------------- nftables 配置生成 ----------------

def _build_nft_config():
    tcp_ports = sorted(set(TCP_PORTS))
    udp_ports = sorted(set(UDP_PORTS))

    wl4 = [n for n in (PRIVATE_NETS + EXTRA_WHITELIST) if n.version == 4]
    wl6 = [n for n in (PRIVATE_NETS + EXTRA_WHITELIST) if n.version == 6]

    # DRY_RUN 时 verdict 为空字符串（规则只 log / 只 counter，不加 verdict）
    # 这样不会用 accept 跳过 Docker DNAT，包继续流向下一个 chain
    final_verdict = "" if DRY_RUN else "drop"
    bl_verdict    = "" if DRY_RUN else "drop"

    # log 语句（可限速）。★ 只用于独立的 log 规则，
    # 不能和 drop 写在一起（limit 失败会连 drop 一起跳过）
    if USE_HASHLIMIT:
        rate = _nft_rate(HASHLIMIT_RATE)
        log_stmt = (f"limit rate {rate} burst {HASHLIMIT_BURST} packets "
                    f"log prefix \"{PORT_SCAN_PREFIX} \" level warn")
        # ICMP 日志同样限速，避免 ping flood 刷屏
        icmp_log_stmt = (f"limit rate {rate} burst {HASHLIMIT_BURST} packets "
                         f"log prefix \"{ICMP_PROBE_PREFIX} \" level info")
    else:
        log_stmt = f"log prefix \"{PORT_SCAN_PREFIX} \" level warn"
        icmp_log_stmt = f"log prefix \"{ICMP_PROBE_PREFIX} \" level info"

    L = []
    L.append(f"table inet {NFT_TABLE} {{")

    # ---- 黑名单 set（IPv4）----
    L.append(f"    set {NFT_TABLE}_bl4 {{")
    L.append(f"        type ipv4_addr")
    L.append(f"        flags timeout")
    L.append(f"        timeout {BAN_TIME}s")
    L.append(f"        size {SET4_MAXELEM}")
    L.append(f"    }}")

    # ---- 黑名单 set（IPv6）----
    L.append(f"    set {NFT_TABLE}_bl6 {{")
    L.append(f"        type ipv6_addr")
    L.append(f"        flags timeout")
    L.append(f"        timeout {BAN_TIME}s")
    L.append(f"        size {SET6_MAXELEM}")
    L.append(f"    }}")

    # ---- 端口 set ----
    if tcp_ports:
        L.append(f"    set {NFT_TABLE}_tcp {{")
        L.append(f"        type inet_service")
        L.append(f"        elements = {{ {', '.join(map(str, tcp_ports))} }}")
        L.append(f"    }}")

    if udp_ports:
        L.append(f"    set {NFT_TABLE}_udp {{")
        L.append(f"        type inet_service")
        L.append(f"        elements = {{ {', '.join(map(str, udp_ports))} }}")
        L.append(f"    }}")

    # ---- 白名单 set ----
    if wl4:
        elems = ", ".join(str(n) for n in wl4)
        L.append(f"    set {NFT_TABLE}_wl4 {{")
        L.append(f"        type ipv4_addr")
        L.append(f"        flags interval")
        L.append(f"        elements = {{ {elems} }}")
        L.append(f"    }}")

    if wl6:
        elems = ", ".join(str(n) for n in wl6)
        L.append(f"    set {NFT_TABLE}_wl6 {{")
        L.append(f"        type ipv6_addr")
        L.append(f"        flags interval")
        L.append(f"        elements = {{ {elems} }}")
        L.append(f"    }}")

    # ---- PREROUTING 链（在 Docker DNAT 之前）----
    L.append(f"    chain prerouting {{")
    L.append(f"        type filter hook prerouting "
             f"priority {NFT_PREROUTING_PRIORITY}; policy accept;")

    # 黑名单（跟随 DRY_RUN）
    bl_rule = f"ip  saddr @{NFT_TABLE}_bl4 counter"
    if bl_verdict:
        bl_rule += f" {bl_verdict}"
    L.append(f"        {bl_rule}")

    bl_rule6 = f"ip6 saddr @{NFT_TABLE}_bl6 counter"
    if bl_verdict:
        bl_rule6 += f" {bl_verdict}"
    L.append(f"        {bl_rule6}")

    # 白名单：用 return，不能用 accept
    # accept 会跳过整个 PREROUTING hook，破坏 Docker 端口映射
    L.append(f"        ip  saddr @{NFT_TABLE}_wl4 return")
    L.append(f"        ip6 saddr @{NFT_TABLE}_wl6 return")

    # ICMP echo-request：只记录，不加 verdict（包继续走 policy accept）
    # 位置在白名单 return 之后 → 白名单的 ping 不会到达这里
    # 已加 limit 限速，避免 ping flood 刷屏
    if ENABLE_ICMP_LOG:
        L.append(f"        icmp type echo-request {icmp_log_stmt}")
        L.append(f"        icmpv6 type echo-request {icmp_log_stmt}")

    # 端口扫描规则：
    #   1) log 规则（可限速，不 drop）
    #   2) drop 规则（无条件，与 log 限速解耦）
    #   ★ 若合并为一条 "log ... drop"，limit 超速时 limit 失败会中断
    #     整条规则，导致 drop 不执行 —— 安全漏洞。必须拆开。
    # TCP：syn 标志天然只对新建连接触发，日志量本身有天然上限
    if tcp_ports:
        tcp_match = (f"tcp dport @{NFT_TABLE}_tcp "
                     f"tcp flags & (syn|ack) == syn")
        L.append(f"        {tcp_match} {log_stmt}")
        if final_verdict:
            L.append(f"        {tcp_match} {final_verdict}")

    # UDP：无 flags 可过滤，用 ct state new 只对"新建流"打日志
    #   - 单 IP 高频打同一端口 → 只有首包 log，后续 established 不 log
    #   - 端口扫描 → 每个新流仍会 log，由 HASHLIMIT 兜底限速
    #   - drop 规则不加 ct state new：已建立流的后续包同样会被丢弃
    if udp_ports:
        if UDP_NEW_CONN_ONLY:
            udp_log_match = f"udp dport @{NFT_TABLE}_udp ct state new"
        else:
            udp_log_match = f"udp dport @{NFT_TABLE}_udp"
        L.append(f"        {udp_log_match} {log_stmt}")
        if final_verdict:
            L.append(f"        udp dport @{NFT_TABLE}_udp {final_verdict}")

    L.append(f"    }}")
    L.append(f"}}")

    return "\n".join(L) + "\n"


def setup_firewall():
    """加载 nft 配置。

    ★ 采用"先备份 → 删除 → 加载 → 失败回滚"的顺序：
      避免新配置语法错误时旧规则已被删除、端口裸奔。
    """
    global _firewall_setup_done

    if shutil.which("nft") is None:
        sys.exit("[!] 未找到 nft 命令，请先安装：apt install nftables")

    # 备份 + 恢复封禁记录
    backup = None
    if _nft_table_exists():
        # ★ 用 -s (--stateless)：省略 expires / counters 等运行时字段。
        #   否则带 timeout 的 set 元素（形如 "1.2.3.4 timeout 1d expires 23h"）
        #   在回滚时会被 nft -f 拒绝，回滚机制形同虚设。
        r = _nft(["-s", "list", "table", "inet", NFT_TABLE])
        if r.returncode == 0:
            backup = r.stdout
        old_v4 = _extract_set_elements(f"{NFT_TABLE}_bl4")
        old_v6 = _extract_set_elements(f"{NFT_TABLE}_bl6")
    else:
        old_v4, old_v6 = [], []

    # 删除旧表
    _nft(["delete", "table", "inet", NFT_TABLE])

    # 加载新配置
    config = _build_nft_config()
    r = _nft_load(config)
    if r.returncode != 0:
        # ★ 回滚：重新加载备份，保证系统不裸奔
        print(f"[!] 加载 nftables 配置失败:\n{r.stderr}", flush=True)
        if backup:
            print("[!] 正在回滚到旧配置，避免端口裸奔...", flush=True)
            rr = _nft_load(backup)
            if rr.returncode == 0:
                print("[!] 回滚成功，旧规则已恢复", flush=True)
            else:
                print(f"[!] 回滚也失败！系统当前无防护:\n{rr.stderr}",
                      flush=True)
                print("[!] 请立即手动检查: "
                      "nft list table inet port_scan_guard", flush=True)
        else:
            print("[!] 无可回滚的旧配置，系统当前无防护", flush=True)
        sys.exit("[!] 退出（请修复配置后重启）")

    # 恢复封禁记录：按剩余时间恢复，避免重启后封禁被无限续期。
    # nft JSON 输出的 expires 单位是毫秒 → 除以 1000 转秒。
    def _restore(setname, items):
        for ip, exp in items:
            if exp is None:
                t = BAN_TIME
            else:
                try:
                    t = int(exp) // 1000          # 毫秒 → 秒
                except (TypeError, ValueError):
                    t = BAN_TIME
            if t <= 0:
                continue
            if t > BAN_TIME:
                t = BAN_TIME
            _nft(["add", "element", "inet", NFT_TABLE,
                  setname, f"{{ {ip} timeout {t}s }}"])

    _restore(f"{NFT_TABLE}_bl4", old_v4)
    _restore(f"{NFT_TABLE}_bl6", old_v6)

    if old_v4 or old_v6:
        print(f"[*] 恢复封禁记录: v4={len(old_v4)} v6={len(old_v6)}",
              flush=True)

    _firewall_setup_done = True


def cleanup_firewall():
    """退出清理。

    DESTROY_TABLE_ON_EXIT = True  → 删除整张表（封禁记录一起清空）。
    DESTROY_TABLE_ON_EXIT = False → 保留表和集合，只清空 chain 的规则。
    """
    global _firewall_setup_done
    if not _firewall_setup_done:
        return

    if DESTROY_TABLE_ON_EXIT:
        _nft(["delete", "table", "inet", NFT_TABLE])
    else:
        _nft(["flush", "chain", "inet", NFT_TABLE, "prerouting"])

    _firewall_setup_done = False


def open_log_stream():
    """打开内核日志流。

    优先级：
      1. systemd 系统 → journalctl -k -f
         journald 是内核日志的数据源，比文件副本更可靠：
         - 不依赖 rsyslog / syslog-ng 是否安装
         - 不受 zram 日志同步延迟影响
         - 不受 logrotate 轮转 / truncate 影响
      2. 非 systemd 系统 → /var/log/kern.log → messages → syslog

    性能差异可忽略（毫秒级唤醒，NAS 上无感）。
    """
    if os.path.isdir("/run/systemd/system") and shutil.which("journalctl"):
        p = subprocess.Popen(
            ["journalctl", "-k", "-f", "-n", "0", "-o", "cat"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=False, bufsize=0,
        )
        print("[*] 日志来源: journalctl -k -f", flush=True)
        return p

    for path in ("/var/log/kern.log", "/var/log/messages", "/var/log/syslog"):
        if os.path.exists(path):
            p = subprocess.Popen(
                ["tail", "-F", "-n", "0", path],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=False, bufsize=0,
            )
            print(f"[*] 日志来源: tail -F {path}", flush=True)
            return p

    raise RuntimeError("找不到可用的内核日志来源（journalctl / kern.log）")


# ---------------- 白名单 ----------------

def is_whitelisted(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False

    # IPv4-mapped IPv6 归一化，保证与 IPv4 白名单比对一致
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped

    # loopback / 未指定 / 多播，一律放行（不是攻击）
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        return True

    if isinstance(a, ipaddress.IPv4Address):
        if any(a in net for net in _extra_v4):
            return True
    else:
        if any(a in net for net in _extra_v6):
            return True

    return any(a in net for net in PRIVATE_NETS if net.version == a.version)


# ---------------- 离线 / 在线归属地查询 ----------------

def _load_searcher(xdb_path, ip_version):
    if not xdb_path or not os.path.exists(xdb_path):
        print(f"[!] 离线库不存在: {xdb_path!r}", flush=True)
        return None

    try:
        import ip2region.util as util
        import ip2region.searcher as searcher
    except Exception as e:
        print(f"[!] py-ip2region 未安装或导入失败: {e}", flush=True)
        return None

    # 版本常量名在不同版本里不同
    ver_attr = "IPv4" if ip_version == "v4" else "IPv6"
    ver = getattr(util, ver_attr, None)
    if ver is None:
        ver = getattr(util,
                      "XdbIPv4" if ip_version == "v4" else "XdbIPv6", None)
    if ver is None:
        print(f"[!] 无法识别 {ip_version} 版本标识", flush=True)
        return None

    for api_name in ("new_with_file_only", "newWithFileOnly"):
        fn = getattr(searcher, api_name, None)
        if fn is None:
            continue
        try:
            return fn(ver, xdb_path)
        except Exception:
            pass

    try:
        vec = util.loadVectorIndexFromFile(xdb_path)
        for api_name in ("new_with_vector_index", "newWithVectorIndex"):
            fn = getattr(searcher, api_name, None)
            if fn is None:
                continue
            try:
                return fn(ver, xdb_path, vec)
            except Exception:
                pass
    except Exception:
        pass

    print(f"[!] {xdb_path} 无法通过任何已知 API 加载", flush=True)
    return None


def init_ip_lookup():
    global _searcher_v4, _searcher_v6, _db_conn

    _searcher_v4 = _load_searcher(XDB_V4, "v4")
    _searcher_v6 = _load_searcher(XDB_V6, "v6")

    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    _db_conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    _db_conn.execute("PRAGMA journal_mode=WAL")
    _db_conn.execute("PRAGMA synchronous=NORMAL")
    _db_conn.execute("PRAGMA wal_autocheckpoint=10000")   # 约 40MB 才合并回主库
    _db_conn.execute("""
        CREATE TABLE IF NOT EXISTS bans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         REAL    NOT NULL,
            time_str   TEXT    NOT NULL,
            ip         TEXT    NOT NULL,
            family     TEXT    NOT NULL,
            port       INTEGER,
            protocol   TEXT,
            country    TEXT,
            province   TEXT,
            city       TEXT,
            isp        TEXT,
            source     TEXT,
            duration   INTEGER NOT NULL,
            result     TEXT    NOT NULL,
            event_type TEXT    DEFAULT 'port_scan'
        )
    """)

    # 兼容旧库：缺列则 ALTER 补齐
    cols = [r[1] for r in _db_conn.execute("PRAGMA table_info(bans)")]
    if "port" not in cols:
        _db_conn.execute("ALTER TABLE bans ADD COLUMN port INTEGER")
        print("[*] 数据库升级：bans 表新增 port 列", flush=True)
    if "protocol" not in cols:
        _db_conn.execute("ALTER TABLE bans ADD COLUMN protocol TEXT")
        print("[*] 数据库升级：bans 表新增 protocol 列", flush=True)
    if "event_type" not in cols:
        _db_conn.execute(
            "ALTER TABLE bans ADD COLUMN event_type TEXT DEFAULT 'port_scan'")
        print("[*] 数据库升级：bans 表新增 event_type 列", flush=True)

    _db_conn.execute("CREATE INDEX IF NOT EXISTS idx_ip         ON bans(ip)")
    _db_conn.execute("CREATE INDEX IF NOT EXISTS idx_ts         ON bans(ts)")
    _db_conn.execute("CREATE INDEX IF NOT EXISTS idx_country    ON bans(country)")
    _db_conn.execute("CREATE INDEX IF NOT EXISTS idx_isp        ON bans(isp)")
    _db_conn.execute("CREATE INDEX IF NOT EXISTS idx_port       ON bans(port)")
    _db_conn.execute("CREATE INDEX IF NOT EXISTS idx_protocol   ON bans(protocol)")
    _db_conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON bans(event_type)")
    _db_conn.commit()


# ---------------- 数据库清理 ----------------

def _cleanup_db():
    """删除超过 DB_RETENTION_DAYS 的记录。只 DELETE，不 VACUUM。"""
    if DB_RETENTION_DAYS <= 0:
        return

    cutoff = time.time() - DB_RETENTION_DAYS * 86400
    try:
        cur = _db_conn.execute("DELETE FROM bans WHERE ts < ?", (cutoff,))
        deleted = cur.rowcount
        _db_conn.commit()
        if deleted and deleted > 0:
            print(f"[*] 清理旧记录: {deleted} 行 "
                  f"(保留最近 {DB_RETENTION_DAYS} 天)", flush=True)

        if DB_VACUUM_AFTER_CLEANUP:
            print("[*] VACUUM 中…（会重写全库，请稍候）", flush=True)
            _db_conn.execute("VACUUM")
            _db_conn.commit()
            print("[*] VACUUM 完成", flush=True)
    except Exception as e:
        print(f"[!] 清理旧记录失败: {e}", flush=True)


def _maybe_cleanup_db():
    """按 DB_CLEANUP_INTERVAL 节流调用 _cleanup_db()。"""
    global _last_cleanup_ts

    if DB_RETENTION_DAYS <= 0:
        return

    now = time.time()
    if now - _last_cleanup_ts < DB_CLEANUP_INTERVAL:
        return
    _last_cleanup_ts = now
    _cleanup_db()


# ---------------- 归属地查询 ----------------

def _query_offline(ip: str) -> dict:
    searcher = _searcher_v6 if ":" in ip else _searcher_v4
    if searcher is None:
        return {}
    try:
        region = searcher.search(ip)
        if not region:
            return {}
        parts = region.split("|")
        if len(parts) < 5:
            return {}
        return {
            "country":  parts[0] or UNKNOWN,
            "province": parts[2] or UNKNOWN,
            "city":     parts[3] or UNKNOWN,
            "isp":      parts[4] or UNKNOWN,
        }
    except Exception as e:
        print(f"[!] 离线查询失败 {ip}: {e}", flush=True)
        return {}


def _query_online(ip: str) -> dict:
    # 退出中不再发起网络请求，避免拖慢退出
    if _shutdown_requested:
        return {}
    try:
        import requests
    except Exception:
        return {}
    try:
        resp = requests.get(
            ONLINE_API.format(ip=ip),
            timeout=ONLINE_TIMEOUT,
            headers={"User-Agent": "port-scan-guard/1.0"},
        )
        data = resp.json()
        if data.get("status") != "success":
            return {}
        return {
            "country":  data.get("country")    or UNKNOWN,
            "province": data.get("regionName") or UNKNOWN,
            "city":     data.get("city")       or UNKNOWN,
            "isp":      data.get("isp")        or UNKNOWN,
        }
    except Exception as e:
        print(f"[!] 在线查询失败 {ip}: {e}", flush=True)
        return {}


def _cache_get(ip: str):
    now = time.time()
    cached = _ip_info_cache.get(ip)
    if cached and now - cached[0] < IP_INFO_CACHE_TTL:
        return cached[1]
    if cached:
        _ip_info_cache.pop(ip, None)
    return None


def _cache_put(ip: str, info: dict):
    _ip_info_cache[ip] = (time.time(), info)
    if len(_ip_info_cache) > IP_INFO_CACHE_MAX:
        cutoff = time.time() - IP_INFO_CACHE_TTL
        for k in [k for k, v in _ip_info_cache.items() if v[0] < cutoff]:
            _ip_info_cache.pop(k, None)


def get_ip_info(ip: str) -> dict:
    cached = _cache_get(ip)
    if cached is not None:
        return cached

    info = _query_offline(ip)
    source = "offline" if info else "unknown"

    # 退出中：不再发起在线查询，直接用已有信息
    if _shutdown_requested:
        for k in ("country", "province", "city", "isp"):
            info.setdefault(k, UNKNOWN)
        info["source"] = source
        return info

    need_online = (
        not info
        or info.get("country") in (None, "", UNKNOWN)
        or info.get("isp")     in (None, "", UNKNOWN)
    )

    if need_online:
        online = _query_online(ip)
        if online:
            if not info:
                info = online
                source = "online"
            else:
                for k in ("country", "province", "city", "isp"):
                    if not info.get(k) or info.get(k) == UNKNOWN:
                        info[k] = online.get(k, UNKNOWN)
                source = "offline+online"

    for k in ("country", "province", "city", "isp"):
        info.setdefault(k, UNKNOWN)

    info["source"] = source
    _cache_put(ip, info)
    return info


# ---------------- 封禁 ----------------

def _should_skip_dedup(ip: str) -> bool:
    now = time.time()
    last = _recent_bans.get(ip, 0)
    if now - last < BAN_DEDUP_WINDOW:
        return True
    _recent_bans[ip] = now

    if len(_recent_bans) > 100000:
        cutoff = now - BAN_DEDUP_WINDOW
        for k in [k for k, v in _recent_bans.items() if v < cutoff]:
            _recent_bans.pop(k, None)
    return False


def _normalize_ip(ip: str):
    """规范化为 ipaddress 对象。

    ★ 关键：把 IPv4-mapped IPv6（::ffff:a.b.c.d）还原为纯 IPv4，
      否则会加进 bl6 集合，但原始 IPv4 流量匹配不到 ip saddr @bl6，
      封禁记录写入而流量不拦截。

    返回 (ip_str, addr) 或 (None, None) 表示非法。
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr), addr


def ban(ip: str, port: int = None, protocol: str = None):
    # 退出中：放弃本次封禁，避免拖慢退出
    if _shutdown_requested:
        return

    ip, addr = _normalize_ip(ip)
    if addr is None:
        return

    is_v6 = isinstance(addr, ipaddress.IPv6Address)
    setname = f"{NFT_TABLE}_bl6" if is_v6 else f"{NFT_TABLE}_bl4"
    family = "ipv6" if is_v6 else "ipv4"

    skip = _should_skip_dedup(ip)

    if DRY_RUN:
        # DRY_RUN 下也走去重，避免日志狂刷时把库写爆
        if skip:
            return
        result = "dry_run"
    else:
        if skip:
            r = _nft(["get", "element", "inet", NFT_TABLE, setname,
                      f"{{ {ip} }}"])
            if r.returncode == 0:
                return

        _nft(["delete", "element", "inet", NFT_TABLE, setname, f"{{ {ip} }}"])
        r = _nft(["add", "element", "inet", NFT_TABLE, setname,
                  f"{{ {ip} timeout {BAN_TIME}s }}"])
        if r.returncode == 0:
            result = "ban"
        else:
            result = "ban_failed"
            print(f"[!] nft 添加元素失败 {ip}: {r.stderr.strip()}",
                  flush=True)

    info = get_ip_info(ip)

    try:
        _db_conn.execute(
            """INSERT INTO bans
               (ts, time_str, ip, family, port, protocol,
                country, province, city, isp,
                source, duration, result, event_type)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(), time.strftime("%F %T"), ip, family,
                port, protocol,
                info["country"], info["province"], info["city"], info["isp"],
                info["source"], BAN_TIME, result, "port_scan",
            ),
        )
        _db_conn.commit()
    except Exception as e:
        print(f"[!] 写库失败 {ip}: {e}", flush=True)

    tag = ""
    if protocol and port:
        tag = f":{protocol}/{port}"
    elif port:
        tag = f":{port}"
    elif protocol:
        tag = f":{protocol}"

    print(
        f"[{time.strftime('%F %T')}] {result} {ip}{tag} "
        f"({info['country']}/{info['province']}/{info['city']}/{info['isp']}) "
        f"[{info['source']}]",
        flush=True,
    )


def record_icmp_probe(ip: str, protocol: str = "ICMP"):
    """记录 ICMP echo-request 探测。只写数据库，不碰 nft，不丢包。"""
    if _shutdown_requested:
        return

    ip, addr = _normalize_ip(ip)
    if addr is None:
        return

    # 与端口扫描共用去重窗口
    if _should_skip_dedup(ip):
        return

    is_v6 = isinstance(addr, ipaddress.IPv6Address)
    family = "ipv6" if is_v6 else "ipv4"

    info = get_ip_info(ip)

    try:
        _db_conn.execute(
            """INSERT INTO bans
               (ts, time_str, ip, family, port, protocol,
                country, province, city, isp,
                source, duration, result, event_type)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(), time.strftime("%F %T"), ip, family,
                None, protocol,
                info["country"], info["province"], info["city"], info["isp"],
                info["source"], 0, "icmp_probe", "icmp",
            ),
        )
        _db_conn.commit()
    except Exception as e:
        print(f"[!] 写库失败 {ip}: {e}", flush=True)

    print(
        f"[{time.strftime('%F %T')}] icmp_probe {ip} "
        f"({info['country']}/{info['province']}/{info['city']}/{info['isp']}) "
        f"[{info['source']}]",
        flush=True,
    )


# ---------------- 主流程 ----------------

def _handle_sigterm(signum, frame):
    """SIGTERM/SIGINT：只设置标志位。

    ★ 绝对不能在 handler 里碰任何 io 对象（如 proc.stdout.close()）：
      - 主线程可能正阻塞在 proc.stdout 的底层 read() 上，并持有
        BufferedReader 的内部锁；handler 在主线程执行时再去 close()
        同一个对象 → 同线程重入非重入锁 → 死锁。
      - PEP 475 规定 handler 不抛异常时，被 EINTR 打断的 read() 会自动
        重试，因此光设标志也无法唤醒阻塞读；唤醒靠主循环的 select 超时。
    """
    global _shutdown_requested
    _shutdown_requested = True


def _interruptible_sleep(seconds):
    end = time.time() + seconds
    while not _shutdown_requested and time.time() < end:
        time.sleep(0.1)


def _dispatch_log_line(line: str):
    """处理单行日志：分流到端口扫描 / ICMP 记录。"""
    # ---- 端口扫描日志 ----
    if PORT_SCAN_PREFIX in line:
        m = PORT_SCAN_RE.search(line)
        if not m:
            return

        ip = m.group("src").strip("[]")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return

        proto_str = m.group("proto")
        port_str  = m.group("dport")

        try:
            port = int(port_str) if port_str else None
        except (TypeError, ValueError):
            port = None

        protocol = proto_str.upper() if proto_str else None

        if is_whitelisted(ip):
            return
        ban(ip, port, protocol)
        return

    # ---- ICMP 探测日志 ----
    if ENABLE_ICMP_LOG and ICMP_PROBE_PREFIX in line:
        m = ICMP_PROBE_RE.search(line)
        if not m:
            return

        ip = m.group("src").strip("[]")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return

        proto_str = m.group("proto")
        protocol = proto_str if proto_str else "ICMP"

        if is_whitelisted(ip):
            return
        record_icmp_probe(ip, protocol)
        return


def _consume_log_stream(proc):
    """从日志流消费行。

    使用 select 超时轮询 + 非阻塞 os.read + 自维护行缓冲：
      - select 最多等 1 秒，保证 SIGTERM 后 ≤1 秒退出此函数
      - 不用 BufferedReader.readline()，避免 PEP 475 自动重试导致
        信号无法唤醒阻塞读
      - os.read 一次读入多行时，自己按 '\\n' 切分，避免"只处理一行、
        其余滞留缓冲区"的问题
    """
    if proc.stdout is None:
        return
    try:
        fd = proc.stdout.fileno()
    except (OSError, ValueError):
        return

    # 非阻塞：select 报告可读后 os.read 必定立即返回
    try:
        os.set_blocking(fd, False)
    except OSError:
        pass  # 老内核不支持 set_blocking 也能工作（select 已保证可读）

    buf = b""

    while not _shutdown_requested:
        try:
            r, _, _ = select.select([fd], [], [], 1.0)
        except (OSError, ValueError):
            return

        if not r:
            _maybe_cleanup_db()
            continue

        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            continue
        except OSError:
            return

        if not chunk:            # EOF：日志源结束
            return

        buf += chunk

        # 防御：单行极长时避免内存无限增长
        if len(buf) > 1024 * 1024:
            print("[!] 日志缓冲超过 1MB，丢弃旧数据", flush=True)
            buf = buf[-512 * 1024:]

        while b"\n" in buf:
            line_bytes, buf = buf.split(b"\n", 1)
            if _shutdown_requested:
                return
            line = line_bytes.decode("utf-8", errors="replace").rstrip("\r")
            _maybe_cleanup_db()
            _dispatch_log_line(line)


def _in_container() -> bool:
    """判断当前是否运行在容器内。"""
    if os.path.exists("/.dockerenv"):
        return True
    if os.path.exists("/run/.containerenv"):        # Podman
        return True
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
        if any(x in content for x in
               ("docker", "kubepods", "containerd", "lxc")):
            return True
    except Exception:
        pass
    return False


def _startup_selfcheck():
    """启动自检：容器部署容易踩的几条，仅告警不阻塞。"""
    in_ctr = _in_container()

    # nf_log_all_netns 只在容器内需要为 1；
    # 宿主机自己的 nft log 直接写本机内核日志，该参数为 0 是正常的
    if in_ctr:
        try:
            with open("/proc/sys/net/netfilter/nf_log_all_netns", "r") as f:
                v = f.read().strip()
                if v != "1":
                    print(f"[!] nf_log_all_netns = {v}（容器部署应为 1）。"
                          f"宿主执行: sysctl -w net.netfilter.nf_log_all_netns=1",
                          flush=True)
        except Exception:
            pass

    # NET_ADMIN（容器需 --cap-add=NET_ADMIN；无需 NET_RAW）
    if shutil.which("capsh"):
        r = sh(["capsh", "--print"])
        if r.returncode == 0 and "cap_net_admin" not in r.stdout:
            print("[!] 当前进程缺少 CAP_NET_ADMIN，nft 操作可能失败。"
                  "容器需 --cap-add=NET_ADMIN", flush=True)

    # 内核日志可读
    for p in ("/var/log/kern.log", "/var/log/messages", "/var/log/syslog"):
        if os.path.exists(p):
            if not os.access(p, os.R_OK):
                print(f"[!] {p} 存在但不可读，tail 回退可能失败", flush=True)
            break


def main():
    global _extra_v4, _extra_v6, _current_proc

    if os.geteuid() != 0:
        sys.exit("请以 root 权限运行")
    if not TCP_PORTS and not UDP_PORTS:
        sys.exit("TCP_PORTS 与 UDP_PORTS 均为空，请在脚本顶部至少启用一个端口")

    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT,  _handle_sigterm)
    atexit.register(cleanup_firewall)

    _extra_v4 = [n for n in EXTRA_WHITELIST if n.version == 4]
    _extra_v6 = [n for n in EXTRA_WHITELIST if n.version == 6]

    _startup_selfcheck()

    init_ip_lookup()
    setup_firewall()

    print(f"[*] 已就绪：TCP {len(set(TCP_PORTS))} 个 / "
          f"UDP {len(set(UDP_PORTS))} 个端口", flush=True)
    print(f"[*] 链：PREROUTING（优先级 {NFT_PREROUTING_PRIORITY}，"
          f"在 Docker DNAT 之前）", flush=True)
    print(f"[*] 策略：内网 IPv4/IPv6 放行，"
          f"命中端口即封 {BAN_TIME}s", flush=True)
    if ENABLE_ICMP_LOG:
        print("[*] ICMP：只记录非白名单 echo-request，不封禁、不丢包",
              flush=True)
    else:
        print("[*] ICMP：未启用（ENABLE_ICMP_LOG = False）", flush=True)
    print(f"[*] 数据库：{DB_PATH}", flush=True)
    if DB_RETENTION_DAYS > 0:
        print(f"[*] 保留策略：最近 {DB_RETENTION_DAYS} 天，"
              f"每 {DB_CLEANUP_INTERVAL // 3600} 小时检查一次", flush=True)
    else:
        print("[*] 保留策略：不清理（DB_RETENTION_DAYS <= 0）", flush=True)
    if _searcher_v4 is None:
        print("[!] IPv4 离线库未加载，将全部走在线查询", flush=True)
    if _searcher_v6 is None:
        print("[!] IPv6 离线库未加载", flush=True)
    if DRY_RUN:
        print("[!] DRY_RUN = True：端口扫描只记录不封禁", flush=True)
    else:
        print("[*] DRY_RUN = False：端口扫描实际封禁", flush=True)
    if USE_HASHLIMIT:
        print(f"[*] 日志限速: {HASHLIMIT_RATE} / burst {HASHLIMIT_BURST}"
              f"（仅影响 log，不影响 drop）", flush=True)
    else:
        print("[!] 日志限速已关闭：命中即 log，被攻击时可能刷爆内核日志",
              flush=True)
    if UDP_PORTS and UDP_NEW_CONN_ONLY:
        print("[*] UDP 日志仅对 ct state new 生效（依赖 nf_conntrack）",
              flush=True)
    if DESTROY_TABLE_ON_EXIT:
        print("[*] 退出时将删除 nft 表（停服即解封）", flush=True)

    # 启动时立即执行一次清理
    _maybe_cleanup_db()

    while not _shutdown_requested:
        proc = None
        try:
            proc = open_log_stream()
            _current_proc = proc
            _consume_log_stream(proc)
            if not _shutdown_requested:
                print("[!] 日志流已中断，5 秒后重连…", flush=True)
        except Exception as e:
            if not _shutdown_requested:
                print(f"[!] 日志流异常: {e}，5 秒后重连…", flush=True)
        finally:
            _current_proc = None
            if proc is not None and proc.poll() is None:
                try:
                    proc.terminate()
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        try:
                            proc.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                except Exception:
                    pass
        if not _shutdown_requested:
            _maybe_cleanup_db()
            _interruptible_sleep(5)

    print("[*] 正在退出…", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] 已退出")
    finally:
        if _db_conn is not None:
            try:
                _db_conn.close()
            except Exception:
                pass
