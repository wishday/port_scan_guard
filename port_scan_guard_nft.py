#!/root/port_scan_guard/venv/bin/python3
# -*- coding: utf-8 -*-
"""
port_scan_guard_nft.py

监听一组高危端口，任意非白名单 IP 尝试连接其中任意一个端口，
立即通过 nftables 原生 set 拉黑 24 小时，支持 IPv4 和 IPv6。

同时监听 ICMP echo-request（ping）：默认只记录、不封禁、不丢包，
用于审计"谁在探测 NAS 是否在线"；把 ENABLE_ICMP_BAN 设为 True 可改为
同样拉黑 24 小时（该 IP 的全部流量）。

规则挂在 PREROUTING 链上，优先级 -110（在 Docker DNAT -100 之前）：
  - 在 DNAT 之前拦截，saddr / dport 都是原始值
  - 能保护宿主机自身端口，也能保护 Docker bridge 映射到容器的端口
  - 白名单 / DRY_RUN 使用 return 或空 verdict，避免 accept 破坏后续 chain

日志源优先级：systemd 系统优先 journalctl -k -f（数据源优先于文件副本），
非 systemd 系统回退到 /var/log/kern.log → messages → syslog。

封禁时查询 IP 归属地（离线库优先，缺失时在线补充），
记录写入 SQLite，方便后续筛选统计。

依赖：nft (nftables v1.0.6+，1.0.9 已实测)
      /root/port_scan_guard/venv 里的 py-ip2region + requests

用法：sudo /root/port_scan_guard/venv/bin/python3 \
          /root/port_scan_guard/port_scan_guard_nft.py
"""

import atexit
import heapq
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

# 回环网段：与 is_whitelisted() 的回环放行保持一致，本机进程访问监测端口
# （如 127.0.0.1:8080）不会被 nft 拦截。
LOOPBACK_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
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
# 下面三项决定"这套配置跑成什么形态"，也是最常改、改错代价最大的三项
# （同机两套实例撞前缀或撞表名会互相误封），所以提到最前面。
# ★ DRY_RUN 影响所有封禁动作（端口扫描与 ICMP 一致）
#   - DRY_RUN=True：只记事件不封禁（ICMP 的 ENABLE_ICMP_BAN 也会被压住）
#   - DRY_RUN=False：按各自开关实际封禁
DRY_RUN    = False

PORT_SCAN_PREFIX  = "HOST_SCAN:"     # 端口扫描日志前缀（内核 nft log），容器与host需要区分，否则会同时封禁
ICMP_PROBE_PREFIX = "HOST_ICMP:"    # ICMP 探测日志前缀，容器与host需要区分，否则会同时封禁

# nft 表名（inet 族，与 Docker 的 ip/ip6 族隔离）
NFT_TABLE = "port_scan_guard_host"

BAN_TIME   = 86400              # 封禁时长（秒）= 24 小时

# ---- ICMP echo-request（ping）策略 ----
#   - 白名单 IP 的 ping 不记录（nft 层 return 直接放行）
#   - 非白名单 IP 的 ping 写入 SQLite；是否封禁由下面的 ENABLE_ICMP_BAN 决定
#   - 与端口扫描共用 BAN_DEDUP_WINDOW 去重，但 kind 不同，互不吞记录
# 想完全关闭 ICMP 记录：ENABLE_ICMP_LOG = False
ENABLE_ICMP_LOG = True

# 是否对 ICMP 探测执行封禁（默认 False = 只记录，不碰 nft、不丢包）
# ★ 设为 True 后：命中的 ping 会加入黑名单 24 小时，该 IP 的**所有**流量
#   （TCP/UDP 一起）都被丢弃；nft 层 ICMP 规则同时改为占用 per-IP 配额。
# ★ 两种模式的配额为什么不同：
#   per-IP 配额只保证"每个 IP 至少留一条日志"，而配额桶是按源地址共用的。
#   ICMP 仅记录时若占配额，攻击者每秒发 1~2 个 ping 就能占满同一 IP 的桶，
#   让它的端口扫描永远写不进日志、永不被封（实测可复现）。
#   ICMP 封禁时这个绕过不成立——第一个 ping 就把自己封了，所以占配额是安全的，
#   也能让"每 IP 至少一条记录"的保证覆盖 ICMP。
# ★ 需 ENABLE_ICMP_LOG = True 才有意义（无日志就没有封禁触发点）。
ENABLE_ICMP_BAN = False

# 退出时是否删除整张 nft 表（包括已封禁 IP）。
# False = 保留封禁记录，重启服务后继续生效（推荐）；
# True  = 停服即全部解封，重启后从零开始。
DESTROY_TABLE_ON_EXIT = False

# nft set 最大容量（黑名单 set）
# ★ 实测每元素约 200 字节（v4 196B / v6 214B，带 timeout 扩展），
#   且 size 只是**上限、不预分配**：空 set 无论 size 多大都占 0 内存，
#   代价只在真的装到那个数量时产生。所以这是"安全边界"而非日常水位。
#   推满的内存：v4/v6 各 524288 → 98MB + 107MB ≈ 205MB（两侧统一取 2^19）。
#
# ★ 两侧统一取 524288，是抗灌能力与内存估值之间的折中：
#   - v4 没有聚合选项（聚合到 /24 会误封同 C 段邻居），容量是唯一抗灌手段。
#     按 100 封禁/s 的上限估，524288 槽约 1.5 小时才灌满；而实际水位只有
#     几十到几百条，离上限还有三个数量级余量。
#   - v6 加容量收益很低：攻击者换源零成本（一个 /64 就有 2^64 个地址），
#     灌满速度受**封禁速率**限制而非容量，继续翻倍只是把漏封起点往后推。
#     真要抗 v6 换源扫描，有效手段是 V6_AGG_PREFIXLEN < 128。
#   - 两侧取同值便于对账：横幅与 `nft list set` 两边的数字可直接比较。
#   若内存紧张，正确方向是开启聚合 + 把 v6 降到 65536，而不是继续加容量。
SET4_MAXELEM = 524288
SET6_MAXELEM = 524288

# IPv6 封禁 / 日志配额的聚合前缀长度。128 = 不聚合（逐地址封禁，默认）；
# 小于 128 时，同一前缀内的所有地址共用一个黑名单槽位、一个配额桶。
#
# ★ 默认取 128 的理由（优先避免误封）：
#   - 语义与 IPv4 完全对称：封一个 IPv6 地址就是封一个地址，不会牵连别人。
#   - "一个 /64 = 一个用户"并不总成立。共享 /64 的现实场景：
#       云主机子网（AWS VPC 拿 /56，每个子网 /64，同子网多台实例共用）、
#       PPPoE 接入侧共享链路前缀、公共 WiFi、校园网、企业 NAT 出口。
#     这些位置按 /64 聚合会把大量无关用户一起挡在门外。
#   - 家宽 NAS 面对的入站扫描规模有限，逐地址封禁的容量通常够用。
#
# ★ 什么时候该改成 64（或 56）：
#   日志里若出现"同一 /64 内每包换一个源地址"的扫描（IPv6 换源零成本），
#   逐地址封禁会被灌满黑名单 —— 524288 槽在 100 封禁/s 下约 87 分钟耗尽，
#   之后新地址一律封不住。此时按 /64 聚合能把换源门槛从"单机随意伪造"
#   抬到"要掌握几万个不同子网"，与 IPv4 僵尸网络同一量级。
#
# ★ 聚合的语义变化（仅 <128 时生效）：封禁单位从"单个地址"变成"整个
#   网段"，一次误判会波及同前缀的其他设备。白名单按网段匹配（interval
#   set），不受聚合影响。
#
# ★ 掩码必须是 `ffff:ffff:ffff:ffff::`（保留高 64 位、清零低 64 位）。
#   写成 `::ffff:ffff:ffff:ffff` 是保留低 64 位（接口标识），毫无聚合效果：
#   实测 3 个同 /64 源分别产生 3 个元素 `::a1 / ::a2 / ::a3`，而正确掩码
#   只产生 1 个 `2001:db8:77::`。
V6_AGG_PREFIXLEN = 128

# PREROUTING 链优先级：
#   -110 = dstnat(-100) - 10，比 Docker 的 DNAT 更早执行
#   用纯数字而不是 `dstnat - 10` 表达式：后者依赖 nft 的常数运算支持，
#   直接写 -110 在所有版本上都能解析
#   改成 filter 优先级（-10 或 0）会在 DNAT 之后，拦不到映射端口
NFT_PREROUTING_PRIORITY = -110

# ---- 日志限速：per-IP 配额 ----
# ★ nft 中 limit 是匹配表达式，超速即"不匹配"并中断当前规则，因此本脚本
#   把 log 和 drop 拆成两条规则：
#     - log 规则受 limit 限速（超速包不写日志）
#     - drop 规则无条件执行（不受 limit 影响，保证安全）
# 背景：nft 的 limit 是"每条规则一个令牌桶、所有来源共享"，不按源 IP 分。
#   一个 IP 就能把桶打满，让其他来源的扫描完全不写日志 → 不进黑名单，
#   等于被单点噪音"致盲"。per-IP 配额让每个源 IP 持有自己的令牌桶，
#   谁也挤不掉谁；只要有一个包被记录，该 IP 就会被封 24h。
#
# ★ 配额不必给大：封禁只需要 1 条日志。设成 1/second 反而更省日志——
#   单个 IP 首秒最多留 2 条（burst），之后稳态 1 条/秒。
#   实测：连发 6 包只记 2 条，此后每秒 1 包连续 8 秒全部记上。
# ★ 依赖 nft 的 dynamic set + update 语句（要求 >= 1.0.6，1.0.9 已实测）。
#   nft < 1.0.6 不支持这条路径，加载时会直接报 update 语法错误。
# ★ 单开 per-IP 配额会把总日志上限放大成"N 个 IP × 配额"，
#   被海量 IP 扫描时照样能刷爆内核日志 → 必须保留下面的每规则兜底。
LOG_QUOTA_RATE     = "1/second"    # 每个源 IP 的日志配额
LOG_QUOTA_BURST    = 2
LOG_QUOTA_TIMEOUT  = "60s"         # 元素空闲多久释放（update 会刷新）
# set 容量上限。每元素约 200 字节（实测），65536 满表约 13MB。
# ★ 容量要按"该族所有 log 规则的兜底速率之和"估算，不能按单条算：
#   每条规则都有自己的 `limit rate 100/second` 兜底，而 IPv4 / IPv6 各有
#   4 条扫描规则（TCP SYN / FIN / NULL + UDP；开 ICMP 封禁时再各 +1）。
#   稳态元素数上限 ≈ 规则数 × 100/s × LOG_QUOTA_TIMEOUT(60s)
#                    = 4 × 100 × 60 ≈ 24000（开 ICMP 封禁约 30000）。
#   因此两侧都取 65536：对上述上限留 2 倍以上余量。
# ★ 默认 V6_AGG_PREFIXLEN = 128（逐地址）时按"地址数"算；若改成按 /64
#   聚合，一个元素代表一整个前缀，元素数成数量级下降，容量更宽松。
# ★ set 满后的行为**不是"跳过配额、继续 log"**（实测，nft 1.0.9）：
#   `update` 失败会中断整条规则，后面的 `limit` 与 `log` 都不执行。
#   即：该协议族下**新出现的源 IP 完全不写日志、不进黑名单**，直到有元素
#   超时释放；已在 set 里的 IP 不受影响（元素存在时 update 只刷新，不占新槽）。
#   drop 是独立规则，照常丢包 —— 所以是"漏封"，不是"漏拦"。
# ★ 正常流量远达不到这个上限：兜底 limit 已排在 update 之前（见
#   _emit_log_rule 的 ★★ 说明），元素创建速率被压在 LOG_GLOBAL_RATE 以内。
#   这里的容量是极端情况下的安全边界，不是日常水位。
#   真遇到容量告警才需要动它：调小 LOG_QUOTA_TIMEOUT（元素只需覆盖
#   "首包 → 写入黑名单"的几秒窗口），或调大本容量。
LOG_QUOTA_SET4_MAXELEM = 65536
LOG_QUOTA_SET6_MAXELEM = 65536

# 每条 log 规则的总量兜底：在 per-IP 配额之上再压一道**不区分来源 IP** 的
# 上限，防止"大量 IP 各刷自己的配额"把内核日志打爆。
# ★ nft 的 limit 是每规则一个桶，所以实际天花板是「规则条数 × 本值」
#   （默认启用的检测项共 10 条 log 规则：TCP SYN / FIN / NULL 与 UDP 各
#   v4+v6、ICMP v4+v6，各一个桶），不是整机 100/s。关掉 ENABLE_FLAG_SCAN
#   降到 6 条，清空 TCP_PORTS / UDP_PORTS 还会更少。
# ★ 规则里 limit 排在 update 之前，所以本值同时是 lq set 元素的**创建速率
#   上限**——稳态元素数 ≈ 本值 × LOG_QUOTA_TIMEOUT，这是 set 不会被灌满的
#   原因（见 LOG_QUOTA_SET4_MAXELEM 的说明）。
# ★ 取值依据：用户态是单线程，正则解析 + 写库约几百条/秒就饱和，
#   日志缓冲超过 1MB 还会丢弃旧数据。100/s 对应"约 100 个 IP 同时扫描"，
#   再高的量已超出 NAS 的处理能力，压大只会让真正的事件淹在积压里。
LOG_GLOBAL_RATE    = "100/second"
LOG_GLOBAL_BURST   = 150

# UDP 规则是否只对"新建 conntrack 流"打日志（ct state new）
#   - True：同一 UDP 五元组只有第一个包参与 log 判定，
#           大幅降低日志量；依赖 nf_conntrack（Docker 环境默认可用）
#   - False：每个命中 UDP 端口的包都参与 log 判定（仍受 limit 限速），
#           不依赖 conntrack；日志量高，仅在 conntrack 不可用时使用
# ★ 无论本开关如何，drop 规则都不加 ct state，保证已建立流的后续包也丢弃
UDP_NEW_CONN_ONLY = True

# 是否检测"非 SYN"的 TCP 扫描（FIN / XMAS / NULL 扫描）
#   默认规则只匹配 纯 SYN（tcp flags & (syn|ack) == syn），
#   nmap -sF / -sX / -sN 这类扫描因此完全隐形。开启后额外匹配：
#     - tcp flags fin + ct state invalid,untracked            → FIN / XMAS
#     - tcp flags & (fin|syn|rst|psh|ack|urg) == 0 + 同上状态  → NULL
#   ★ ct state 不能省：扫描包是"无 SYN 的首包"，conntrack 判 invalid；
#     正常关闭连接的 FIN+ACK 是 established。省掉会误封回程 FIN（见
#     _build_nft_config 里的实测说明）。
#   ★ 本项依赖 nf_conntrack（Docker 环境默认可用）；conntrack 不可用时
#     配置加载会失败并回滚，此时请改为 False。
#   ★ ACK 扫描（nmap -sA）不在覆盖范围：ACK 包与正常流量无法用标志位区分，
#     只能靠 ct state，而正常 ACK 大量存在。
ENABLE_FLAG_SCAN = True

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

# 在线归属地查询（离线库任一字段缺失时触发；在线成功则整条采用在线值）
# ★ ip-api.com 免费版只提供明文 HTTP（无 HTTPS），且会暴露查询的 IP；
#   介意的话把 ONLINE_API 置空字符串（""）即可完全关闭在线查询。
ONLINE_API     = ("http://ip-api.com/json/{ip}"
                  "?lang=zh-CN&fields=status,message,"
                  "country,regionName,city,isp")
# ★ 用 (connect, read) 元组，避免单值 5 被解释为"各 5 秒"最坏 10 秒；
#   连接/读取最坏共 5 秒。DNS 解析不受此参数约束，由系统 resolver 控制。
ONLINE_TIMEOUT = (2, 3)
# 在线查询失败后的熔断时长（秒）：期间不再发起请求，避免封禁路径被拖慢
ONLINE_FAIL_BACKOFF = 300
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

_searcher_v4 = None
_searcher_v6 = None
_db_conn     = None

_recent_bans = {}
_extra_v4    = []
_extra_v6    = []

_ip_info_cache = {}
_online_fail_until = 0.0        # 在线查询熔断截止时间（time.time 基准）

_firewall_setup_done = False

_shutdown_requested = False

_last_cleanup_ts    = 0.0
_table_lost_warned_ts = 0.0


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


def _expires_to_seconds(exp):
    """把 nft JSON 的 expires 统一转成"剩余秒数"，无法判断时返回 None。

    ★ nft 的 JSON 输出单位是**秒**（实测 1.0.9：120s 元素过 3 秒后为 116，
      文本形式同时显示 expires 1m56s952ms），个别版本给的是毫秒。
      这里以"剩余时间不可能超过 max(BAN_TIME*2, 7 天)"作为判据区分两者。
    """
    if exp is None:
        return None
    try:
        v = float(exp)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return 0
    # 秒值不可能超过 max(BAN_TIME*2, 7 天)；超过即视为毫秒
    if v > max(BAN_TIME * 2, 604800):
        v /= 1000.0
    return int(v)


def _extract_set_elements(set_name):
    """从 nft set 中提取现有元素（用于重建表时恢复封禁）。

    返回 [(ip, 剩余秒数 or None), ...]，秒数已由 _expires_to_seconds 归一。

    ★ nft -j 的元素是**两层嵌套**：
        "elem": [ { "elem": { "val": "1.2.3.4", "expires": 86392 } } ]
      直接读 elem["val"] 永远是 None，会导致重启后封禁全部丢失。
      无 timeout 的普通元素则可能直接是字符串或 {"val": ...}，两种都要兼容。
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
                continue
            if not isinstance(elem, dict):
                continue
            # 兼容 {"elem": {"val":..,"expires":..}} 与 {"val":..,"expires":..}
            node = elem
            if "val" not in node and isinstance(node.get("elem"), dict):
                node = node["elem"]
            val = node.get("val")
            if isinstance(val, str):
                elements.append((val, _expires_to_seconds(node.get("expires"))))
    return elements


def _nft_rate(rate_str):
    """'100/s' / '100/sec' → '100/second'（nft 只认 second/minute/hour 全称）"""
    s = rate_str.strip()
    if s.endswith("/second"):
        return s
    if s.endswith("/sec"):
        return s[:-4] + "/second"
    if s.endswith("/s"):
        return s[:-2] + "/second"
    return s


# ---------------- 配置校验 ----------------

_NFT_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
# ★ 首位限定非零：rate 0 与 timeout 0 都能通过朴素的 "^\d+" 正则，但
#   - `limit rate 0/second` 实测 nft 报 "Could not process rule: Invalid
#     argument"，整份配置加载失败，服务起不来（这个是响的，容易发现）；
#   - `timeout 0s` 语法合法、nft 也接受，实测含义是**无超时**：`nft list
#     set` 里根本不会出现 timeout 行，元素也永远没有 expires（对照
#     `timeout 60s` 会显示 `expires 59s997ms`）。于是配额 set 只增不减，
#     长时间被海量 IP 扫描后填满 65536，满后 update 失败会中断整条 log
#     规则 → 该族新源完全不写日志、不进黑名单，而且启动无任何报错。
#   两者都是改配置时容易手滑写出的值，必须在启动前拦掉。
_RATE_RE     = re.compile(r"^0*[1-9]\d*/(?:second|sec|s|minute|hour)$")
_TIMEOUT_RE  = re.compile(r"^0*[1-9]\d*(?:ms|s|m|h|d)$")    # 必须带单位，实测 "timeout 60" 语法错

# nft 的 log prefix 上限是 127 字节（含结尾 NUL），实测 127 报
# "log prefix is too long"、126 通过。留 6 字节余量给"前缀 + 空格"。
_PREFIX_MAX = 120


def _validate_config():
    """校验配置区常量，非法值直接退出（附中文原因）。

    ★ 为什么必须在启动时校验，而不是等 nft 报错：
      nft 的报错只有 `/dev/stdin:38:69: Error: syntax error`，看不出是哪项
      配置错了；更糟的是有一类错误**不会报错、只会静默失效**：
        - PORT_SCAN_PREFIX == ICMP_PROBE_PREFIX
        - ICMP_PROBE_PREFIX 是 PORT_SCAN_PREFIX 的子串
      两者都会让端口扫描日志在 _dispatch_log_line 里被判成 ICMP 探测，
      结果是"永远不封禁端口扫描"，日志里毫无异常。实测确认。
    """
    errs = []

    # ---- nft 对象名 ----
    if not _NFT_NAME_RE.match(NFT_TABLE or ""):
        errs.append(f"NFT_TABLE={NFT_TABLE!r} 只能含字母、数字、下划线、点、连字符")
    elif len(NFT_TABLE) > 64:
        errs.append(f"NFT_TABLE 过长（{len(NFT_TABLE)} > 64）")

    # ---- 日志前缀 ----
    for name, val in (("PORT_SCAN_PREFIX", PORT_SCAN_PREFIX),
                      ("ICMP_PROBE_PREFIX", ICMP_PROBE_PREFIX)):
        if not isinstance(val, str) or not val:
            errs.append(f"{name} 必须是非空字符串")
            continue
        if '"' in val or "\n" in val or "\r" in val:
            errs.append(f'{name}={val!r} 不能含英文双引号或换行'
                        f'（会破坏 nft 的 log prefix "..." 语法）')
        n_bytes = len(val.encode("utf-8"))      # nft 按字节算，中文 1 字 3 字节
        if n_bytes > _PREFIX_MAX:
            errs.append(f"{name} 过长（{n_bytes} 字节 > {_PREFIX_MAX}）："
                        f"nft 的 log prefix 上限 127 字节，超了整表加载失败")

    if isinstance(PORT_SCAN_PREFIX, str) and isinstance(ICMP_PROBE_PREFIX, str):
        if PORT_SCAN_PREFIX == ICMP_PROBE_PREFIX:
            errs.append(
                "PORT_SCAN_PREFIX 与 ICMP_PROBE_PREFIX 不能相同："
                "所有扫描日志都会被判成 ICMP 探测，端口扫描将永不封禁")
        elif ICMP_PROBE_PREFIX and ICMP_PROBE_PREFIX in PORT_SCAN_PREFIX:
            errs.append(
                f"ICMP_PROBE_PREFIX={ICMP_PROBE_PREFIX!r} 是 "
                f"PORT_SCAN_PREFIX={PORT_SCAN_PREFIX!r} 的子串："
                "每条扫描日志都含 ICMP 前缀，会被判成 ICMP 探测，"
                "端口扫描将永不封禁（两者不要有包含关系）")

    # ---- 端口清单 ----
    for name, ports in (("TCP_PORTS", TCP_PORTS), ("UDP_PORTS", UDP_PORTS)):
        for p in ports:
            if not isinstance(p, int) or isinstance(p, bool) \
                    or not (1 <= p <= 65535):
                errs.append(f"{name} 含非法端口 {p!r}（应为 1~65535 的整数）")

    # ---- 白名单网段 ----
    # _build_nft_config() 会直接访问每个元素的 .version，因此这里要求
    # 元素必须是 ip_network 对象，启动时给出明确报错。
    for name, nets in (("PRIVATE_NETS", PRIVATE_NETS),
                       ("LOOPBACK_NETS", LOOPBACK_NETS),
                       ("EXTRA_WHITELIST", EXTRA_WHITELIST)):
        if not isinstance(nets, (list, tuple)):
            errs.append(f"{name} 必须是列表")
            continue
        for n in nets:
            if not isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                errs.append(
                    f"{name} 含非网段元素 {n!r}：必须用 "
                    f"ipaddress.ip_network(...) 构造，不能直接写字符串")

    # ---- 速率 / 超时 ----
    if not _RATE_RE.match(str(LOG_QUOTA_RATE).strip()):
        errs.append(f"LOG_QUOTA_RATE={LOG_QUOTA_RATE!r} 格式应为 "
                    f"'1/second' 这类「数字/单位」，且数字必须 >= 1"
                    f"（rate 0 会被 nft 拒绝，整份配置加载失败）")
    if not _RATE_RE.match(str(LOG_GLOBAL_RATE).strip()):
        errs.append(f"LOG_GLOBAL_RATE={LOG_GLOBAL_RATE!r} 格式应为 "
                    f"'100/second' 这类「数字/单位」，且数字必须 >= 1"
                    f"（rate 0 会被 nft 拒绝，整份配置加载失败）")
    for name, v in (("LOG_QUOTA_BURST", LOG_QUOTA_BURST),
                    ("LOG_GLOBAL_BURST", LOG_GLOBAL_BURST)):
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            errs.append(f"{name}={v!r} 必须是 >= 1 的整数")
    if not _TIMEOUT_RE.match(str(LOG_QUOTA_TIMEOUT).strip()):
        errs.append(f"LOG_QUOTA_TIMEOUT={LOG_QUOTA_TIMEOUT!r} 必须带单位且"
                    f"数值 >= 1：nft 要求 '60s'、'10m' 这类写法，写 60 会"
                    f"语法错误；写 0s 更隐蔽——实测含义是「无超时」，"
                    f"元素永不释放，配额 set 只增不减，满了该族新源就不再"
                    f"写日志、不进黑名单，且启动无任何报错")
    # ★ size 非法时 nft 的报错会错位：`size 0` 实测报的是后面那行的
    #   "unexpected '}'"，根本看不出是 size 写错了，所以必须前置校验。
    for name, v in (("LOG_QUOTA_SET4_MAXELEM", LOG_QUOTA_SET4_MAXELEM),
                    ("LOG_QUOTA_SET6_MAXELEM", LOG_QUOTA_SET6_MAXELEM)):
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            errs.append(f"{name}={v!r} 必须是 >= 1 的整数"
                        f"（nft 的 size 写 0/负数只会报一条指向别处的"
                        f"语法错，很难定位）")

    # ---- 黑名单 set 容量 ----
    # ★ 黑名单 set 与日志配额是两套 set，这里的容量只影响 bl4/bl6。
    # ★ 同 size 的坑：写 0 时 nft 报的是后面那行的 "unexpected '}'"。
    for name, v in (("SET4_MAXELEM", SET4_MAXELEM),
                    ("SET6_MAXELEM", SET6_MAXELEM)):
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            errs.append(f"{name}={v!r} 必须是 >= 1 的整数"
                        f"（nft 的 size 写 0/负数只会报一条指向别处的"
                        f"语法错，很难定位）")

    # ---- 封禁时长 ----
    if not isinstance(BAN_TIME, int) or isinstance(BAN_TIME, bool) \
            or BAN_TIME < 1:
        errs.append(f"BAN_TIME={BAN_TIME!r} 必须是 >= 1 的整数（秒）")

    # ---- IPv6 聚合前缀 ----
    # ★ 越界会让 _v6_mask() 抛异常（/129 之类），或算出全 0 掩码把整个
    #   IPv6 空间并成一个 key —— 一次误判就封掉全部 v6，必须前置拦。
    # ★ 下限取 32（而不是 1）：/32 已经是一个运营商级前缀，比它更粗的取值
    #   在防护上没有意义，只会把海量无关地址并进同一个封禁槽位。
    if not isinstance(V6_AGG_PREFIXLEN, int) \
            or isinstance(V6_AGG_PREFIXLEN, bool) \
            or not (32 <= V6_AGG_PREFIXLEN <= 128):
        errs.append(f"V6_AGG_PREFIXLEN={V6_AGG_PREFIXLEN!r} 必须是 32~128 的"
                    f"整数（128 = 逐地址，默认；64 = 按 /64 聚合）")

    # ---- PREROUTING 优先级 ----
    # ★ 必须是整数：本项目按纯数字生成 `priority -110;`，写成表达式或字符串
    #   会让 nft 报语法错、整表加载失败。
    # ★ 但更要紧的是「写对了却写晚了」：0 或正数（filter 优先级）在 Docker
    #   DNAT(-100) 之后，此时 dport 已被改写成容器内端口，清单里的宿主机端口
    #   一个都匹配不到 —— nft 不报任何错，只是防护静默失效。这类取值无法
    #   判断是否有意（非 Docker 环境 -10 也合理），所以只告警不退出。
    if not isinstance(NFT_PREROUTING_PRIORITY, int) \
            or isinstance(NFT_PREROUTING_PRIORITY, bool):
        errs.append(f"NFT_PREROUTING_PRIORITY={NFT_PREROUTING_PRIORITY!r} "
                    f"必须是整数（默认 -110）。本项目生成的是 "
                    f"`priority -110;`，字符串或表达式会直接语法错误")
    elif NFT_PREROUTING_PRIORITY >= -100:
        print(f"[!] NFT_PREROUTING_PRIORITY={NFT_PREROUTING_PRIORITY} "
              f"不早于 Docker DNAT(-100)：等于 -100 时同优先级内各 chain "
              f"执行顺序不确定；大于 -100 时 dport 已被改写，清单里的"
              f"宿主机端口可能匹配不到（无 Docker 时无影响）",
              flush=True)

    # ---- 开关组合 ----
    # ★ ENABLE_ICMP_BAN=True + ENABLE_ICMP_LOG=False 只告警不退出：
    #   该组合不影响端口扫描封禁，硬退出会让服务起不来，比"ICMP 不封禁"更糟。
    #   告警统一放在 main() 的启动横幅里，这里不重复打印。

    if errs:
        print("[!] 配置校验未通过：", flush=True)
        for e in errs:
            print(f"    - {e}", flush=True)
        sys.exit("[!] 请修改脚本顶部配置区后重启")


# ---------------- nftables 配置生成 ----------------

def _build_nft_config():
    tcp_ports = sorted(set(TCP_PORTS))
    udp_ports = sorted(set(UDP_PORTS))

    # 去重：用户可能把私网/回环段又写进 EXTRA_WHITELIST
    wl_nets = list(dict.fromkeys(PRIVATE_NETS + LOOPBACK_NETS + EXTRA_WHITELIST))
    wl4 = [n for n in wl_nets if n.version == 4]
    wl6 = [n for n in wl_nets if n.version == 6]

    # DRY_RUN 时 verdict 为空字符串（规则只 log / 只 counter，不加 verdict）
    # 这样不会用 accept 跳过 Docker DNAT，包继续流向下一个 chain
    final_verdict = "" if DRY_RUN else "drop"
    bl_verdict    = "" if DRY_RUN else "drop"

    # 日志语句。★ 只用于独立的 log 规则，不能和 drop 写在一起
    #   （limit 失败会连 drop 一起跳过）。
    #   形状固定为 [每规则兜底 limit] + [per-IP 配额 update] + log，
    #   且每条规则要按 v4/v6 各生成一条（见 _emit_log_rule）。
    def _limit_stmt(rate_str, burst):
        """'100/s' → 'limit rate 100/second burst N packets '"""
        return (f"limit rate {_nft_rate(rate_str)} "
                f"burst {burst} packets ")

    # ★ inet 族里 `ip saddr` 对 IPv6 包不成立，因此 per-IP 配额必须
    #   按协议族拆成两条规则；不拆的话 IPv6 流量完全没有配额。
    # ★ IPv6 的 key 在聚合时才带 `& <mask>`（按 V6_AGG_PREFIXLEN 聚合，
    #   同前缀的所有源共用一个令牌桶）；默认 128 不聚合，key 与 v4 对称，
    #   直接是 `ip6 saddr`。理由见该常量处的说明。
    _k6 = "ip6 saddr" if V6_AGG_PREFIXLEN >= 128 \
        else f"ip6 saddr & {_v6_mask()}"
    FAMILIES = (
        ("ip",  "meta nfproto ipv4", f"{NFT_TABLE}_lq4", "ip saddr"),
        ("ip6", "meta nfproto ipv6", f"{NFT_TABLE}_lq6", _k6),
    )

    L = []
    L.append(f"table inet {NFT_TABLE} {{")

    # ---- 黑名单 set（IPv4）----
    L.append(f"    set {NFT_TABLE}_bl4 {{")
    L.append("        type ipv4_addr")
    L.append("        flags timeout")
    L.append(f"        timeout {BAN_TIME}s")
    L.append(f"        size {SET4_MAXELEM}")
    L.append("    }")

    # ---- 黑名单 set（IPv6）----
    L.append(f"    set {NFT_TABLE}_bl6 {{")
    L.append("        type ipv6_addr")
    L.append("        flags timeout")
    L.append(f"        timeout {BAN_TIME}s")
    L.append(f"        size {SET6_MAXELEM}")
    L.append("    }")

    # ---- 日志配额 set（per-IP 令牌桶）----
    #   flags dynamic：允许从包路径 update（必须）
    #   flags timeout：元素空闲 timeout 后自动释放，避免被扫描时无限增长
    for _fam, _cond, _sname, _key in FAMILIES:
        _type = "ipv4_addr" if _fam == "ip" else "ipv6_addr"
        _size = (LOG_QUOTA_SET4_MAXELEM if _fam == "ip"
                 else LOG_QUOTA_SET6_MAXELEM)
        L.append(f"    set {_sname} {{")
        L.append(f"        type {_type}")
        L.append(f"        size {_size}")
        L.append("        flags dynamic,timeout")
        L.append(f"        timeout {LOG_QUOTA_TIMEOUT}")
        L.append("    }")

    # ---- 端口 set ----
    if tcp_ports:
        L.append(f"    set {NFT_TABLE}_tcp {{")
        L.append("        type inet_service")
        L.append(f"        elements = {{ {', '.join(map(str, tcp_ports))} }}")
        L.append("    }")

    if udp_ports:
        L.append(f"    set {NFT_TABLE}_udp {{")
        L.append("        type inet_service")
        L.append(f"        elements = {{ {', '.join(map(str, udp_ports))} }}")
        L.append("    }")

    # ---- 白名单 set ----
    if wl4:
        elems = ", ".join(str(n) for n in wl4)
        L.append(f"    set {NFT_TABLE}_wl4 {{")
        L.append("        type ipv4_addr")
        L.append("        flags interval")
        L.append(f"        elements = {{ {elems} }}")
        L.append("    }")

    if wl6:
        elems = ", ".join(str(n) for n in wl6)
        L.append(f"    set {NFT_TABLE}_wl6 {{")
        L.append("        type ipv6_addr")
        L.append("        flags interval")
        L.append(f"        elements = {{ {elems} }}")
        L.append("    }")

    # ---- PREROUTING 链（在 Docker DNAT 之前）----
    L.append("    chain prerouting {")
    L.append(f"        type filter hook prerouting "
             f"priority {NFT_PREROUTING_PRIORITY}; policy accept;")

    def _emit_log_rule(match, prefix, level, family=None, quota=True):
        """生成一条（或两条）log 规则。

        family=None → 按 v4/v6 各生成一条，条件里加 meta nfproto 区分；
        family="ip"/"ip6" → 只生成该族一条（调用方的 match 已自带族关键字，
        如 `icmp type ...`），此时不再加 meta nfproto。

        quota=False → 不占 per-IP 配额，只受每规则兜底 limit 约束。
        ★ ICMP 只在"真的会封禁"（ENABLE_ICMP_BAN=True 且 DRY_RUN=False）
          时才传 quota=True；其余情况一律 quota=False：lq set 的 key 只有
          源地址，ICMP 与 TCP/UDP 共用同一个桶。若 ICMP 不封禁却占配额，
          攻击者只要每秒发 1~2 个 ping 就能把该 IP 的配额全部占掉，让同一
          IP 的端口扫描永远写不进日志 → 永不被封。
          实测：先 ping 2 次再扫 4 个端口，TCP 日志计数为 0。
          开启 ICMP 封禁后该绕过不成立（第一个 ping 就被封），此时占配额。

        ★ `meta nfproto ipv4` / `ipv6` 在 `nft list` 输出里**会正常显示**
          （nft 1.0.9 实测），两条规则一眼就能看出族不同。族区分同时体现在
          set 名（`lq4` / `lq6`）上，删掉任一条都会让对应协议族失去配额。

        ★★ 兜底 limit 必须排在 update **之前**（实测 nft 1.0.9）：
          - 若写成 `update @set {...} limit 100/second log`，被兜底丢掉的包
            也已经执行过 update，**照样在 set 里占一个槽**。攻击者用大量
            不同源地址发包即可无上限地灌 set（1000 pps 随机源：65536 槽
            约 65 秒填满），随后该族 `update` 恒失败 → 整条规则中断 →
            新源 IP 完全不写日志、不被封。
            LOG_GLOBAL_RATE 完全保护不到 set，这正是它本该保护的东西。
          - 前置后，单个包必须先过兜底限速才可能创建元素，创建速率被压在
            LOG_GLOBAL_RATE 以内。注意速率是**按规则累加**的：每个族有 4 条
            扫描规则（TCP SYN/FIN/NULL + UDP），稳态元素数上限
            ≈ 4 × 100/s × LOG_QUOTA_TIMEOUT(60s) ≈ 24000，对 65536 的容量
            有 2 倍以上余量，正常运行不会被填满。
          - 实测前置顺序合法，且 per-IP 配额行为不变：连发 20 包，per-IP
            仍只放行 burst 2 个，元素正常创建、timeout 正常刷新。
          - 代价：超兜底限速的包不再创建元素，因此"此刻超速、稍后恢复"的
            源不会被补记。这符合预期——超速意味着总量已过载，该丢就丢。
        """
        tail = f"log prefix \"{prefix} \" level {level}"
        glob = _limit_stmt(LOG_GLOBAL_RATE, LOG_GLOBAL_BURST)
        if not quota:
            # 不占配额时无需分族：调用方的 match 已自带 icmp / icmpv6 关键字
            L.append(f"        {match} {glob}{tail}")
            return
        for fam, cond, sname, key in FAMILIES:
            if family and fam != family:
                continue
            head = "" if family else f"{cond} "
            quota_stmt = (f"update @{sname} {{ {key} "
                          f"{_limit_stmt(LOG_QUOTA_RATE, LOG_QUOTA_BURST)}}} ")
            # glob（兜底 limit）在 update 之前，见 docstring 的 ★★ 说明
            L.append(f"        {head}{match} {glob}{quota_stmt}{tail}")

    # 黑名单（跟随 DRY_RUN）
    # ★ IPv6 侧同样要带掩码，与 ban() 写入的归一地址保持同一坐标系。
    bl_rule = f"ip  saddr @{NFT_TABLE}_bl4 counter"
    if bl_verdict:
        bl_rule += f" {bl_verdict}"
    L.append(f"        {bl_rule}")

    bl_rule6 = f"{_k6} @{NFT_TABLE}_bl6 counter"
    if bl_verdict:
        bl_rule6 += f" {bl_verdict}"
    L.append(f"        {bl_rule6}")

    # 白名单：用 return，不能用 accept
    # accept 会跳过整个 PREROUTING hook，破坏 Docker 端口映射
    L.append(f"        ip  saddr @{NFT_TABLE}_wl4 return")
    L.append(f"        ip6 saddr @{NFT_TABLE}_wl6 return")

    # ICMP echo-request：不加 verdict（包继续走 policy accept）
    # 位置在白名单 return 之后 → 白名单的 ping 不会到达这里
    # icmp / icmpv6 关键字本身已限定协议族，故按单族生成
    # ★ 是否占用 per-IP 配额 = "真的会封禁"时才占：
    #   ENABLE_ICMP_BAN=True 且 DRY_RUN=False。
    #   ★ DRY_RUN=True 时必须按"不占配额"处理：此时 ban() 不写黑名单，
    #     若 ICMP 仍占配额，同一 IP 的 ping 会把它的桶吃光，端口扫描日志
    #     写不进去 → 观察期数据失真（看起来"没人扫我"），且这种失真恰好
    #     在切到生产前最难发现。
    #   其余理由见 _emit_log_rule 的 docstring。
    if ENABLE_ICMP_LOG:
        icmp_quota = ENABLE_ICMP_BAN and not DRY_RUN
        _emit_log_rule("icmp type echo-request",
                       ICMP_PROBE_PREFIX, "info", "ip", quota=icmp_quota)
        _emit_log_rule("icmpv6 type echo-request",
                       ICMP_PROBE_PREFIX, "info", "ip6", quota=icmp_quota)

    # 端口扫描规则：
    #   1) log 规则（可限速，不 drop）
    #   2) drop 规则（无条件，与 log 限速解耦）
    #   ★ 若合并为一条 "log ... drop"，limit 超速时 limit 失败会中断
    #     整条规则，导致 drop 不执行 —— 安全漏洞。必须拆开。
    # TCP：syn 标志天然只对新建连接触发，日志量本身有天然上限
    if tcp_ports:
        tcp_match = (f"tcp dport @{NFT_TABLE}_tcp "
                     f"tcp flags & (syn|ack) == syn")
        _emit_log_rule(tcp_match, PORT_SCAN_PREFIX, "warn")
        if final_verdict:
            L.append(f"        {tcp_match} {final_verdict}")

    # 非 SYN 扫描（nmap -sF/-sX/-sN）：只认纯 SYN 会让这类扫描完全隐形
    #   - FIN / XMAS：带 fin 标志
    #   - NULL：六个标志位全为 0，正常流量不会出现
    #   ★ 必须加 ct state invalid,untracked，原因实测如下：
    #     FIN 扫描是"无 SYN 的首包"，conntrack 判 invalid（校验和正确的
    #     nmap -sF 包实测就是 invalid）；而正常关闭连接的 FIN+ACK 处于
    #     established。不限定状态会误封"回程 FIN+ACK"——本地临时端口若
    #     落在端口清单里（如 50000/50070/51413），正常服务端会被封 24h。
    #   ★ 不能用 `ct state != established,related`：nft 对 ct state 是位图
    #     比较，实测该写法连 established 的包也会命中，等于没排除。
    #   ★ 限定 invalid 不构成新攻击面：伪造源 IP 发一个 SYN 到清单端口
    #     本来就能让第三方被封，FIN+invalid 不比它更强。
    if tcp_ports and ENABLE_FLAG_SCAN:
        flag_matches = (
            f"tcp dport @{NFT_TABLE}_tcp tcp flags fin "
            f"ct state invalid,untracked",
            f"tcp dport @{NFT_TABLE}_tcp "
            f"tcp flags & (fin|syn|rst|psh|ack|urg) == 0 "
            f"ct state invalid,untracked",
        )
        for m in flag_matches:
            _emit_log_rule(m, PORT_SCAN_PREFIX, "warn")
            if final_verdict:
                L.append(f"        {m} {final_verdict}")

    # UDP：无 flags 可过滤，用 ct state new 只对"新建流"打日志
    #   - 单 IP 高频打同一端口 → 只有首包 log，后续 established 不 log
    #   - 端口扫描 → 每个新流仍会 log，由日志配额 / 限速兜底
    #   - drop 规则不加 ct state new：已建立流的后续包同样会被丢弃
    if udp_ports:
        if UDP_NEW_CONN_ONLY:
            udp_log_match = f"udp dport @{NFT_TABLE}_udp ct state new"
        else:
            udp_log_match = f"udp dport @{NFT_TABLE}_udp"
        _emit_log_rule(udp_log_match, PORT_SCAN_PREFIX, "warn")
        if final_verdict:
            L.append(f"        udp dport @{NFT_TABLE}_udp {final_verdict}")

    L.append("    }")
    L.append("}")

    return "\n".join(L) + "\n"


def setup_firewall():
    """加载 nft 配置。

    ★ 采用"先备份 → 删除 → 加载 → 失败回滚"的顺序：
      避免新配置语法错误时旧规则已被删除、端口裸奔。
    """
    global _firewall_setup_done

    if shutil.which("nft") is None:
        sys.exit("[!] 未找到 nft 命令，请先安装：apt install nftables")

    # 先生成完整配置再改动现有表：生成阶段若抛异常，当前规则原样保留，
    # 不会出现无防护窗口。
    config = _build_nft_config()

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

    # 加载新配置（已在改动现有表之前生成）
    r = _nft_load(config)
    if r.returncode != 0:
        # ★ 回滚：重新加载备份，保证系统不裸奔
        # ★ nft 的报错只给 /dev/stdin:38:69 这类行号，看不出是哪张表、
        #   哪套前缀；容器与宿主各部署一份时容易认错实例，这里显式带上
        print(f"[!] 加载 nftables 配置失败（表 inet {NFT_TABLE}，"
              f"前缀 {PORT_SCAN_PREFIX} / {ICMP_PROBE_PREFIX}）:"
              f"\n{r.stderr}", flush=True)
        if backup:
            print("[!] 正在回滚到旧配置，避免端口裸奔...", flush=True)
            rr = _nft_load(backup)
            if rr.returncode == 0:
                print("[!] 回滚成功，旧规则已恢复", flush=True)
            else:
                print(f"[!] 回滚也失败！系统当前无防护:\n{rr.stderr}",
                      flush=True)
                print("[!] 请立即手动检查: "
                      f"nft list table inet {NFT_TABLE}", flush=True)
        else:
            print("[!] 无可回滚的旧配置，系统当前无防护", flush=True)
        if "conntrack" in (r.stderr or "").lower():
            print("[!] 以上错误与 conntrack 相关：内核缺 nf_conntrack 时，"
                  "请把 UDP_NEW_CONN_ONLY 与 ENABLE_FLAG_SCAN 设为 False",
                  flush=True)
        sys.exit("[!] 退出（请修复配置后重启）")

    # 恢复封禁记录：按剩余时间恢复，避免重启后封禁被无限续期。
    # ★ 剩余秒数已由 _extract_set_elements() 归一化，这里直接用。
    # ★ 按批拼成 nft -f 脚本加载：上千条封禁时避免上千次 fork。
    def _restore(pairs):
        lines = []
        for setname, items in pairs:
            for ip, t in items:
                if t is None:
                    t = BAN_TIME
                if t <= 0:
                    continue
                if t > BAN_TIME:
                    t = BAN_TIME
                # ★ 库里存的是封禁时的原始地址，未必已是归一后的前缀；
                #   新表的匹配若带掩码（V6_AGG_PREFIXLEN < 128），必须归一后
                #   再写，否则这些元素躺在表里但永远匹配不到 —— 封禁静默
                #   失效且不报错。默认 128 时归一等于原样，走同一路径无害。
                if setname.endswith("_bl6"):
                    try:
                        ip = _v6_net_key(ipaddress.ip_address(ip))
                    except ValueError:
                        continue
                lines.append(
                    f"add element inet {NFT_TABLE} {setname} "
                    f"{{ {ip} timeout {int(t)}s }}")
        if not lines:
            return 0

        # ★ 分批加载，不要一次性 batch。实测 set 满时 `nft -f` 会返回 ENFILE
        #   并中断整个脚本 —— 一次性提交等于"一条写不进去，全部封禁一起丢"。
        #   分批后超容量的只影响后面的批次，前面已写入的照常生效，把
        #   "全丢"降级成"丢尾部"，也避免超大脚本单次加载的耗时与内存峰值。
        _BATCH = 10000
        restored = 0
        lost = 0
        first_err = ""
        for i in range(0, len(lines), _BATCH):
            chunk = lines[i:i + _BATCH]
            r = _nft_load("\n".join(chunk) + "\n")
            if r.returncode == 0:
                restored += len(chunk)
            else:
                lost += len(chunk)
                if not first_err:
                    first_err = (r.stderr or "").strip()
        if lost:
            hint = ""
            # ★ set 满时报的是 ENFILE 文案，极易被误当成 fd 耗尽。
            if "Too many open files" in first_err:
                hint = (f"（这是 set 满的报错，不是 fd 耗尽：容量 "
                        f"SET4={SET4_MAXELEM} / SET6={SET6_MAXELEM}。"
                        f"旧表已删除，失败那批元素无法自动补回；"
                        f"确需恢复请调大容量后按 bans 表手工重封）")
            print(f"[!] 恢复封禁记录部分失败：成功 {restored} 条 / 失败 {lost} 条"
                  f"（共 {len(lines)} 条，表 inet {NFT_TABLE}）: {first_err}{hint}",
                  flush=True)
        return restored

    restored = _restore(
        [(f"{NFT_TABLE}_bl4", old_v4), (f"{NFT_TABLE}_bl6", old_v6)])

    if old_v4 or old_v6:
        print(f"[*] 恢复封禁记录: 成功 {restored} 条 "
              f"(旧表 v4={len(old_v4)} v6={len(old_v6)})", flush=True)

    _firewall_setup_done = True


def cleanup_firewall():
    """退出清理。

    DESTROY_TABLE_ON_EXIT = True  → 删除整张表（封禁记录一起清空）。
    DESTROY_TABLE_ON_EXIT = False → 保留表和集合，只清空 chain 的规则。
    """
    global _firewall_setup_done
    if not _firewall_setup_done:
        return

    # 仅主动停服（SIGTERM/SIGINT）才清理规则；异常退出时保留规则，
    # 避免监测端口在进程崩溃到重启的窗口内失去防护（fail-closed）。
    if not _shutdown_requested:
        print("[!] 非正常退出：保留 nft 规则（不 flush），"
              "避免监测端口在崩溃窗口内失去防护", flush=True)
        _firewall_setup_done = False
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

    # 回退：手工加载向量索引再建 searcher
    # （兼容 snake_case 与 camelCase 两种 API 命名）
    load_vec = getattr(util, "load_vector_index_from_file", None)
    if load_vec is None:
        load_vec = getattr(util, "loadVectorIndexFromFile", None)
    if load_vec is None:
        print(f"[!] {xdb_path} 无法通过任何已知 API 加载", flush=True)
        return None
    try:
        vec = load_vec(xdb_path)
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

    try:
        _db_conn = sqlite3.connect(DB_PATH, timeout=10,
                                   check_same_thread=False)
    except Exception as e:
        sys.exit(f"[!] 打开数据库失败 {DB_PATH}: {e}")
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

def _region_field(part: str) -> str:
    """归一化 xdb 字段：官方库用 "0"（或空串）表示未知值。"""
    part = (part or "").strip()
    return UNKNOWN if not part or part == "0" else part


def _query_offline(ip: str) -> dict:
    searcher = _searcher_v6 if ":" in ip else _searcher_v4
    if searcher is None:
        return {}
    try:
        region = searcher.search(ip)
        if not region:
            return {}
        # 官方 ip2region_v4/v6.xdb 字段格式：
        #   Country|Province|City|ISP|iso-alpha2-code
        # 即 province=parts[1]、city=parts[2]、ISP=parts[3]。
        parts = region.split("|")
        if len(parts) < 4:
            return {}
        return {
            "country":  _region_field(parts[0]),
            "province": _region_field(parts[1]),
            "city":     _region_field(parts[2]),
            "isp":      _region_field(parts[3]),
        }
    except Exception as e:
        print(f"[!] 离线查询失败 {ip}: {e}", flush=True)
        return {}


def _query_online(ip: str) -> dict:
    # ★ 在线查询在日志消费循环内同步执行，每次最多阻塞 ONLINE_TIMEOUT 秒
    #   （DNS 解析在 requests timeout 之外，解析异常慢时会更久）。离线字段
    #   缺失的 IP 较多时会明显拖慢后续日志处理；失败后额外熔断，避免连续
    #   超时把循环彻底卡住；熔断期间完全使用离线结果。
    global _online_fail_until

    # 退出中不再发起网络请求，避免拖慢退出
    if _shutdown_requested:
        return {}
    if not ONLINE_API:
        return {}
    if time.time() < _online_fail_until:
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
        # ★ 免费额度耗尽时 ip-api 返回 HTTP 429 + 正常 JSON 体，不会抛异常；
        #   不显式 raise 的话下面只能看到 status=fail，熔断永远不触发，
        #   每次封禁仍会继续打网络。
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            _online_fail_until = time.time() + ONLINE_FAIL_BACKOFF
            print(f"[!] 在线查询失败 {ip}: {data.get('message') or data}"
                  f"（{ONLINE_FAIL_BACKOFF}s 内不再尝试在线查询）", flush=True)
            return {}
        return {
            "country":  data.get("country")    or UNKNOWN,
            "province": data.get("regionName") or UNKNOWN,
            "city":     data.get("city")       or UNKNOWN,
            "isp":      data.get("isp")        or UNKNOWN,
        }
    except Exception as e:
        _online_fail_until = time.time() + ONLINE_FAIL_BACKOFF
        print(f"[!] 在线查询失败 {ip}: {e}"
              f"（{ONLINE_FAIL_BACKOFF}s 内不再尝试在线查询）", flush=True)
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
        # ★ 若所有条目都还在 TTL 内，上面一条也删不掉：分布式扫描可在
        #   TTL 窗口内制造远超上限的新 IP，缓存会一直涨。这里按写入时间
        #   丢掉最旧的部分，保证有硬上限（丢掉只是下次重新查询，无副作用）。
        extra = len(_ip_info_cache) - IP_INFO_CACHE_MAX
        if extra > 0:
            # 只取最旧的 extra 条（O(n log k)），避免全量排序。
            for k, _ in heapq.nsmallest(
                    extra, _ip_info_cache.items(), key=lambda kv: kv[1][0]):
                _ip_info_cache.pop(k, None)


def get_ip_info(ip: str) -> dict:
    """离线库优先；任一字段缺失时查询在线，并整条采用在线结果。"""
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
        or any(info.get(k) in (None, "", UNKNOWN)
               for k in ("country", "province", "city", "isp"))
    )

    if need_online:
        online = _query_online(ip)
        if online:
            # 不混用两个数据源：一旦查询成功，整条记录都取在线值
            info = online
            source = "online"

    for k in ("country", "province", "city", "isp"):
        info.setdefault(k, UNKNOWN)

    info["source"] = source
    _cache_put(ip, info)
    return info


# ---------------- 封禁 ----------------

def _should_skip_dedup(ip: str, kind: str = "scan") -> bool:
    """同一 (事件类型, IP) 在窗口期内只处理一次。

    ★ 按 kind 分开去重：端口扫描与 ICMP 探测各自独立，
      否则同一 IP 先扫描再 ping 时，ping 记录会被扫描的去重窗口吞掉。
    """
    now = time.time()
    key = (kind, ip)
    last = _recent_bans.get(key, 0)
    if now - last < BAN_DEDUP_WINDOW:
        return True
    _recent_bans[key] = now

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


def _v6_mask() -> str:
    """V6_AGG_PREFIXLEN 对应的位与常量，如 /64 → 'ffff:ffff:ffff:ffff::'。

    用于 nft 表达式 `ip6 saddr & <mask>`。注意方向：这个常量保留**高**
    prefixlen 位、清零低位，才是"按前缀聚合"；反过来（如
    ::ffff:ffff:ffff:ffff）保留的是接口标识，实测完全没有聚合效果。
    """
    return str(ipaddress.ip_network(f"::/{V6_AGG_PREFIXLEN}").netmask)


def _v6_net_key(addr) -> str:
    """把 IPv6 地址归一到聚合前缀的网络地址，返回字符串。

    ★ 聚合时（V6_AGG_PREFIXLEN < 128）必须归一才能写进 set：nft 侧匹配
      写成 `ip6 saddr & <mask> @bl6`，查询时先用掩码处理包的源地址再查表。
      若表里存的是未归一的完整地址（粒度切换后残留的元素即属此类），
      掩码后永远查不到 —— 封禁记录在表里躺着，流量却照过，且不报任何错。

    V6_AGG_PREFIXLEN=128（默认）时返回原地址，等价于不聚合。
    """
    net = ipaddress.ip_network(f"{addr}/{V6_AGG_PREFIXLEN}", strict=False)
    return str(net.network_address)


def _warn_table_lost():
    """nft 表被外部删除时打一条醒目告警（10 分钟内只打一次）。

    触发场景：systemctl restart nftables、nft flush ruleset、Docker 重配
    网络、别人手工删表。此时**规则和黑名单一起消失**，脚本仍在跑、仍在
    逐条打 `ban_failed`，防护却已经完全没有了 —— 必须让人看得见。
    """
    global _table_lost_warned_ts

    now = time.time()
    if now - _table_lost_warned_ts < 600:
        return
    _table_lost_warned_ts = now
    print("=" * 60, flush=True)
    print(f"[!!] nft 表 inet {NFT_TABLE} 已不存在：防护规则与黑名单全部丢失。",
          flush=True)
    print("[!!] 常见原因：systemctl restart nftables / nft flush ruleset / "
          "Docker 重配网络。", flush=True)
    print("[!!] 当前所有封禁都会失败（库里记 ban_failed），"
          "端口处于无防护状态。", flush=True)
    print("[!!] 请重启本服务以重建规则："
          "systemctl restart port_scan_guard", flush=True)
    print("=" * 60, flush=True)


def ban(ip: str, port: int = None, protocol: str = None,
        kind: str = "scan", event_type: str = "port_scan"):
    """把 IP 加入 nft 黑名单并写库。

    kind / event_type 用于区分来源：
      - 端口扫描：kind="scan"、event_type="port_scan"（默认）
      - ICMP 探测：kind="icmp"、event_type="icmp"（ENABLE_ICMP_BAN=True）
    两者的去重窗口互不吞并（_should_skip_dedup 的 key 是 (kind, ip)）。
    """
    # 退出中：放弃本次封禁，避免拖慢退出
    if _shutdown_requested:
        return

    ip, addr = _normalize_ip(ip)
    if addr is None:
        return

    is_v6 = isinstance(addr, ipaddress.IPv6Address)
    setname = f"{NFT_TABLE}_bl6" if is_v6 else f"{NFT_TABLE}_bl4"
    family = "ipv6" if is_v6 else "ipv4"

    # ★ 开启聚合时（V6_AGG_PREFIXLEN < 128），set 里写入的是归一后的前缀
    #   网络地址；默认 128 时归一等于原样，set 里就是完整地址，与 v4 对称。
    #   去重也用它：聚合时同一前缀内的不同源地址共用一个封禁槽位，若按原始
    #   地址去重会在窗口期过后反复 get/add 同一个元素、反复写库。
    #   数据库与日志仍保留**原始触发地址**，便于审计"具体是谁扫的"。
    set_key = _v6_net_key(addr) if is_v6 else ip

    skip = _should_skip_dedup(set_key, kind)

    if DRY_RUN:
        # DRY_RUN 下也走去重，避免日志狂刷时把库写爆
        if skip:
            return
        result = "dry_run"
    else:
        # 去重窗口内直接返回：不再 fork nft，避免日志刷屏时的进程风暴
        if skip:
            return

        # ★ 已在黑名单中：直接返回，不 delete/add、不写库。
        #   否则持续扫描者每 10 秒（去重窗口）就会把 timeout 重置为 BAN_TIME
        #   → 实际成为永久封禁（与"24 小时"的语义不符），
        #     且单 IP 每天往库里写 8640 行。
        r = _nft(["get", "element", "inet", NFT_TABLE, setname,
                  f"{{ {set_key} }}"])
        if r.returncode == 0:
            return

        r = _nft(["add", "element", "inet", NFT_TABLE, setname,
                  f"{{ {set_key} timeout {BAN_TIME}s }}"])
        if r.returncode == 0:
            result = "ban"
        else:
            result = "ban_failed"
            print(f"[!] nft 添加元素失败 {set_key}"
                  f"（inet {NFT_TABLE} / {setname}）: {r.stderr.strip()}",
                  flush=True)
            # ★ "No such file or directory" 通常不是元素本身的问题，而是
            #   整张表被别人删了（systemctl restart nftables、nft flush
            #   ruleset、Docker 重配网络等）。此时 drop 规则也没了，等于
            #   完全没有防护，而脚本只会不停打 ban_failed —— 必须显式喊出来。
            if "No such file or directory" in (r.stderr or ""):
                _warn_table_lost()
            # ★ "Too many open files in system"（ENFILE）实测是 **set 满** 的
            #   文案，和 fd 耗尽毫无关系。不点破的话运维第一反应是去查
            #   ulimit -n，方向完全跑偏。
            elif "Too many open files" in (r.stderr or ""):
                cap = SET6_MAXELEM if is_v6 else SET4_MAXELEM
                print(f"[!] 上一条不是 fd 耗尽，是黑名单 set 已满"
                      f"（{setname} 容量 {cap}）。新来源将不再被封禁，"
                      f"已封的仍按剩余时间过期释放。扩容：调大 "
                      f"{'SET6' if is_v6 else 'SET4'}_MAXELEM 后重启，"
                      f"或临时 nft flush set inet {NFT_TABLE} {setname}",
                      flush=True)

    info = get_ip_info(ip)

    # 只有真正写进黑名单（result="ban"）才算封禁时长；
    # DRY_RUN 与 ban_failed 都没有实际生效，记 0 以免统计被高估。
    duration = BAN_TIME if result == "ban" else 0

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
                info["source"], duration, result, event_type,
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

    # ★ 聚合封禁时（V6_AGG_PREFIXLEN < 128），日志要把"封禁范围"和"触发
    #   地址"都写出来，否则看到 2001:db8:77::/64 会以为是别人触发的。
    #   默认 128 时 set_key 就是原始地址，不必再缀 /128。
    if is_v6 and V6_AGG_PREFIXLEN < 128:
        shown = f"{set_key}/{V6_AGG_PREFIXLEN}"
    else:
        shown = ip
    trig = f" (触发 {ip})" if is_v6 and set_key != ip else ""

    print(
        f"[{time.strftime('%F %T')}] {result} {shown}{tag}{trig} "
        f"({info['country']}/{info['province']}/{info['city']}/{info['isp']}) "
        f"[{info['source']}]",
        flush=True,
    )


def record_icmp_probe(ip: str, protocol: str = "ICMP"):
    """记录 ICMP echo-request 探测：只写数据库，不碰 nft，不丢包。

    仅在 ENABLE_ICMP_BAN = False（默认）时由 _dispatch_log_line 调用；
    开启 ICMP 封禁后走 ban()，本函数不再参与。
    """
    if _shutdown_requested:
        return

    ip, addr = _normalize_ip(ip)
    if addr is None:
        return

    # 与端口扫描分开去重（kind 不同），互不吞记录
    if _should_skip_dedup(ip, "icmp"):
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
    # ---- ICMP 探测日志（先判断：避免 PORT_SCAN_PREFIX 是它的子串时误走扫描分支）----
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

        # 默认只写库（不碰 nft、不丢包）；ENABLE_ICMP_BAN=True 时改为封禁。
        # 封禁走 ban() 并带 kind="icmp"，与端口扫描各自去重、互不吞记录。
        if ENABLE_ICMP_BAN:
            ban(ip, protocol=protocol, kind="icmp", event_type="icmp")
        else:
            record_icmp_probe(ip, protocol)
        return

    # ---- 端口扫描日志 ----
    if PORT_SCAN_PREFIX in line and ICMP_PROBE_PREFIX not in line:
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
    """判断当前是否运行在容器内。

    ★ cgroup v2 下容器内 /proc/1/cgroup 可能只是 "0::/"，不含运行时关键字，
      因此这里同时看 /proc/1/cgroup 与 /proc/self/cgroup，并覆盖常见运行时名。
      仍判断不出来时返回 False（仅影响一条启动告警，不影响防护）。
    """
    if os.path.exists("/.dockerenv"):
        return True
    if os.path.exists("/run/.containerenv"):        # Podman
        return True
    markers = ("docker", "kubepods", "containerd", "lxc",
               "libpod", "crio", "garden", "podman")
    for path in ("/proc/1/cgroup", "/proc/self/cgroup"):
        try:
            with open(path, "r") as f:
                content = f.read()
        except Exception:
            continue
        if any(x in content for x in markers):
            return True
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
    global _extra_v4, _extra_v6

    if os.geteuid() != 0:
        sys.exit("请以 root 权限运行")
    if not TCP_PORTS and not UDP_PORTS:
        sys.exit("TCP_PORTS 与 UDP_PORTS 均为空，请在脚本顶部至少启用一个端口")

    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT,  _handle_sigterm)
    atexit.register(cleanup_firewall)

    # 必须在 setup_firewall() 之前校验：非法配置若进入 nft 加载，报错只有
    # `/dev/stdin:38:69` 行号；前缀冲突那类错误则完全静默。
    _validate_config()

    _extra_v4 = [n for n in EXTRA_WHITELIST if n.version == 4]
    _extra_v6 = [n for n in EXTRA_WHITELIST if n.version == 6]

    _startup_selfcheck()

    init_ip_lookup()
    setup_firewall()

    print(f"[*] 已就绪：TCP {len(set(TCP_PORTS))} 个 / "
          f"UDP {len(set(UDP_PORTS))} 个端口", flush=True)
    # ★ 表名与日志前缀全部取自配置区常量，容器部署改过之后
    #   启动日志即可自证改动已生效（容器与宿主同时部署时必须不同）
    print(f"[*] nft 表：inet {NFT_TABLE}；日志前缀："
          f"{PORT_SCAN_PREFIX} / {ICMP_PROBE_PREFIX}", flush=True)
    print(f"[*] 链：PREROUTING（优先级 {NFT_PREROUTING_PRIORITY}，"
          f"在 Docker DNAT 之前）", flush=True)
    print(f"[*] 策略：内网 IPv4/IPv6 放行，"
          f"命中端口即封 {BAN_TIME}s", flush=True)
    # ★ 容量是部署时要盯的数字：黑名单满之后**新源封不进去**（漏封，且日志
    #   里只会看到 ENFILE 那句误导性报错），配额 set 满之后该族不写日志（漏记）。
    #   每元素字节数取实测值（带 timeout 扩展）：196B / 214B。size 只是上限、
    #   不预分配，所以日常内存远低于这里的满表估值，不必因数字大而调小。
    _mib4 = SET4_MAXELEM * 196 // (1024 * 1024)
    _mib6 = SET6_MAXELEM * 214 // (1024 * 1024)
    print(f"[*] 黑名单容量：IPv4 {SET4_MAXELEM} / IPv6 {SET6_MAXELEM} 条"
          f"（满表约 {_mib4}MB + {_mib6}MB，不预分配）", flush=True)
    # ★ IPv6 的封禁粒度直接来自配置，启动时自证一遍：运维看到实际粒度，
    #   才会意识到"聚合时一次误判会波及整个前缀"。
    if V6_AGG_PREFIXLEN >= 128:
        print("[*] IPv6 封禁：逐地址（V6_AGG_PREFIXLEN = 128，未聚合）",
              flush=True)
    else:
        print(f"[*] IPv6 封禁：按 /{V6_AGG_PREFIXLEN} 聚合，"
              f"同一前缀共用一个封禁槽位与配额桶", flush=True)
    if not ENABLE_ICMP_LOG:
        print("[*] ICMP：未启用（ENABLE_ICMP_LOG = False）", flush=True)
        if ENABLE_ICMP_BAN:
            print("[!] ENABLE_ICMP_BAN = True 但 ENABLE_ICMP_LOG = False："
                  "没有日志就没有封禁触发点，封禁不会生效", flush=True)
    elif ENABLE_ICMP_BAN and not DRY_RUN:
        print(f"[*] ICMP：记录并封禁非白名单 echo-request"
              f"（封 {BAN_TIME}s，占用 per-IP 配额）", flush=True)
    elif ENABLE_ICMP_BAN and DRY_RUN:
        print("[!] ICMP：DRY_RUN 压住了封禁，只记录不封禁"
              "（不占 per-IP 配额，避免挤掉端口扫描日志）", flush=True)
    else:
        print("[*] ICMP：只记录非白名单 echo-request，不封禁、不丢包"
              "（不占 per-IP 配额）", flush=True)
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
        print("[!] DRY_RUN = True：所有封禁（含 ICMP）只记录不执行",
              flush=True)
    else:
        print("[*] DRY_RUN = False：按各开关实际封禁", flush=True)
    print(f"[*] 日志配额: 每源 IP {LOG_QUOTA_RATE} / burst "
          f"{LOG_QUOTA_BURST}；每规则兜底 {LOG_GLOBAL_RATE}"
          f"（仅影响 log，不影响 drop）", flush=True)
    # 配额 set 是每族一个（v4/v6 各一个，族内各规则共用），满了之后
    # 该族新源一律不写日志——比黑名单满更隐蔽，值得单独打出来。
    print(f"[*] 配额 set 容量：IPv4 {LOG_QUOTA_SET4_MAXELEM} / "
          f"IPv6 {LOG_QUOTA_SET6_MAXELEM} 条/族"
          f"（满了该族新源不再写日志）", flush=True)
    if UDP_PORTS and UDP_NEW_CONN_ONLY:
        print("[*] UDP 日志仅对 ct state new 生效（依赖 nf_conntrack）",
              flush=True)
    if DESTROY_TABLE_ON_EXIT:
        print("[*] 退出时将删除 nft 表（停服即解封）", flush=True)

    # 启动时立即执行一次清理
    _maybe_cleanup_db()

    open_fail_count = 0
    while not _shutdown_requested:
        proc = None
        started = time.monotonic()
        try:
            proc = open_log_stream()
            _consume_log_stream(proc)
            if not _shutdown_requested:
                if time.monotonic() - started < 5:
                    # 打开后立刻 EOF 通常意味着日志源不可用（无权限、服务未运行），
                    # 与打开失败同样计数，避免进程 active 却永远收不到日志。
                    open_fail_count += 1
                    print(f"[!] 日志流立即结束（连续 {open_fail_count} 次），"
                          f"5 秒后重连…", flush=True)
                else:
                    open_fail_count = 0
                    print("[!] 日志流已中断，5 秒后重连…", flush=True)
        except Exception as e:
            open_fail_count += 1
            if not _shutdown_requested:
                print(f"[!] 日志流异常（连续 {open_fail_count} 次）: {e}，"
                      f"5 秒后重连…", flush=True)
        finally:
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
            if open_fail_count >= 5:
                # 没有可用的日志源 = 永远不会触发封禁。继续以 active 状态
                # 空转只会掩盖故障；退出后由 systemd 的 Restart/启动限流暴露。
                sys.exit("[!] 连续 5 次无法使用内核日志源，退出。"
                         "请检查 journalctl / kern.log 后重启服务")
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
