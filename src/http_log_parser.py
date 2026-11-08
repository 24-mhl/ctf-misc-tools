#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web 访问日志解析：把 Apache/Nginx 的 access.log 变成一份可读的应急初筛报告

用法:
    python http_log_parser.py ../../samples/sample_access.log
    python http_log_parser.py access.log --top 5

它回答四个问题（应急时最先要问的四个）：
    1. 谁在打？        —— 按 IP 聚合，失败率高的排前面
    2. 打了什么？      —— SQL 注入 / 路径穿越 / 命令注入 / 敏感文件探测
    3. 用什么打的？    —— 扫描器与自动化工具的 User-Agent
    4. 打成功了没？    —— 200 与 4xx/5xx 的分布

这是初筛，不是定论：日志能被伪造，命中规则 ≠ 一定被攻破。
真正定案要结合服务端错误日志、文件完整性、进程与网络连接。
"""

import argparse
import re
import sys
from collections import Counter, defaultdict

# Windows 下把输出接给管道/重定向时，Python 会退回 GBK 编码，
# 遇到 GBK 里没有的符号（比如 ⚠）直接抛 UnicodeEncodeError 把程序打断。
# 两个处理：① 输出符号只用 GBK 能表示的；② 万一还有漏网的，降级成 "?" 而不是崩掉。
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

# Apache/Nginx combined 格式
LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# 规则表：(名称, 正则)。顺序即输出顺序。
RULES = [
    ("SQL 注入", re.compile(r"(?i)(union[\s+%20]+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\s*\(|benchmark\s*\()")),
    ("路径穿越", re.compile(r"(\.\./|%2e%2e%2f|\.\.\\|%5c\.\.)", re.I)),
    ("命令注入", re.compile(r"(?i)([;|]\s*(cat|ls|id|whoami|uname|curl|wget)\b|\$\(|`[^`]+`)")),
    ("敏感文件探测", re.compile(r"(?i)(/\.env|/\.git|/\.svn|/wp-admin|/phpmyadmin|/config\.php|/backup\.|/server-status|/xmlrpc\.php|/console)")),
    ("目录扫描", re.compile(r"(?i)(admin\.php|login\.php\?id=|/admin/|/manager/html)")),
    ("管理接口探测", re.compile(r"(?i)(/admin|/manager/html|/console|/api/users|/api/admin|/dashboard)")),
    ("扫描器特征", re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|wpscan|zgrab|python-requests|curl/)")),
]


def parse_line(line: str):
    """解析一行，返回 dict 或 None。"""
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    d["status"] = int(d["status"])
    d["ua"] = d.get("ua") or ""
    d["path"] = d["path"]
    return d


def match_rules(entry) -> list:
    """返回这条请求命中的规则名列表。UA 单独也查一遍，扫器常靠 UA 露馅。"""
    target = entry["path"] + " " + entry["ua"]
    return [name for name, rx in RULES if rx.search(target)]


def main() -> int:
    ap = argparse.ArgumentParser(description="Web 访问日志初筛")
    ap.add_argument("logfile", help="access.log 路径")
    ap.add_argument("--top", type=int, default=5, help="每个榜单显示前 N 条，默认 5")
    args = ap.parse_args()

    total = ok = bad = 0
    ip_stat = defaultdict(lambda: {"total": 0, "err": 0, "hits": Counter(), "ua": Counter(), "win": []})
    rule_stat = Counter()
    auth_fail = defaultdict(Counter)   # ip -> path -> 401/403 次数，用于判断爆破

    try:
        fh = open(args.logfile, "r", encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"[!] 打不开文件：{e}", file=sys.stderr)
        return 1

    with fh:
        for line in fh:
            total += 1
            e = parse_line(line)
            if e is None:
                bad += 1
                continue
            ok += 1

            ip = e["ip"]
            st = ip_stat[ip]
            st["total"] += 1
            st["ua"][e["ua"]] += 1
            if e["status"] >= 400:
                st["err"] += 1

            hits = match_rules(e)
            for name in hits:
                st["hits"][name] += 1
                rule_stat[name] += 1

            # 得手判定一：2xx 且命中实质规则（扫描器特征太泛，单独排除）
            strong = [h for h in hits if h != "扫描器特征"]
            if e["status"] < 300 and strong:
                st["win"].append(f'{e["status"]} {e["method"]} {e["path"][:55]}  [{"/".join(strong)}]')

            # 得手判定二：爆破成功 —— 同一 IP 对同一路径先失败 ≥3 次，随后 2xx
            if e["status"] in (401, 403):
                auth_fail[ip][e["path"]] += 1
            elif e["status"] < 300 and auth_fail[ip][e["path"]] >= 3:
                n = auth_fail[ip][e["path"]]
                st["win"].append(f'{e["status"]} {e["method"]} {e["path"][:55]}  [此前 {n} 次 401/403，疑爆破成功]')

    if ok == 0:
        print("[!] 没有一行解析成功，检查日志格式是否为 combined（前面有没有自定义字段）", file=sys.stderr)
        return 1

    print("=" * 56)
    print(f"解析：{total} 行 → 成功 {ok}，格式不符跳过 {bad}")
    print(f"独立 IP：{len(ip_stat)} 个")
    print("=" * 56)

    # 榜单 0：可能已得手 —— 最该先看的
    wins = [(ip, s) for ip, s in ip_stat.items() if s["win"]]
    print("\n【可能已得手：可疑请求拿到了 2xx/3xx】")
    if wins:
        for ip, s in sorted(wins, key=lambda kv: len(kv[1]["win"]), reverse=True):
            print(f"  {ip}  （{len(s['win'])} 条）")
            for w in s["win"][:6]:
                print(f"    ├─ {w}")
            if len(s["win"]) > 6:
                print(f"    └─ 另有 {len(s['win']) - 6} 条")
    else:
        print("  （无）日志范围内没有可疑请求拿到成功状态码")

    # 榜单 1：可疑 IP（有成功的优先，其次命中规则多的）
    ranked = sorted(
        ip_stat.items(),
        key=lambda kv: (bool(kv[1]["win"]), sum(kv[1]["hits"].values()), kv[1]["err"]),
        reverse=True,
    )
    print(f"\n【可疑 IP Top {args.top}】")
    shown = 0
    for ip, s in ranked:
        score = sum(s["hits"].values())
        if score == 0:
            continue
        rate = s["err"] / s["total"] * 100
        kinds = "、".join(k for k, _ in s["hits"].most_common())
        flag = "[!]" if s["win"] else "   "
        print(f"{flag} {ip:<16} 请求 {s['total']:>3}  失败 {s['err']:>3}（{rate:>5.1f}%）  命中 {score} 次")
        print(f"  {'':16} └─ {kinds}")
        shown += 1
        if shown >= args.top:
            break
    if shown == 0:
        print("  （无）")

    # 榜单 2：规则命中统计
    print("\n【攻击类型分布】")
    if rule_stat:
        for name, cnt in rule_stat.most_common():
            print(f"  {name:<10} {cnt:>3} 次  {'█' * min(cnt, 30)}")
    else:
        print("  （无命中）")

    # 榜单 3：正常业务 IP，用来做对照
    clean = [(ip, s) for ip, s in ip_stat.items() if sum(s["hits"].values()) == 0]
    if clean:
        print("\n【未命中规则的 IP】（对照，不排除伪装）")
        for ip, s in clean[:args.top]:
            print(f"  {ip:<16} 请求 {s['total']:>3}  UA: {list(s['ua'])[0][:50]}")

    print("\n提示：命中规则只代表请求长得像攻击，不代表成功。")
    print("      要定案，去看 200 响应的那几条请求，以及服务端 error.log。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
