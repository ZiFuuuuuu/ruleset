#!/usr/bin/env python3
"""
从 ruleset.skk.moe 下载 SukkaW Surge List 规则并转换为 dae 可用的 DAT 构建源文件
支持：
  - List/domainset/*.conf   -> domain-list-community (domain/suffix)
  - List/non_ip/*.conf      -> domain-list-community (domain/suffix/keyword/regexp)
  - List/ip/*.conf          -> geoip text (CIDR 列表)

不支持的规则类型（自动跳过并记录）：
  PROCESS-NAME, USER-AGENT, URL-REGEX, DOMAIN-SET, AND, OR, NOT
"""
import sys
import json
import re
import ipaddress
import urllib.request
import urllib.error
from pathlib import Path

BASE_URL = "https://ruleset.skk.moe/List"

# 需要下载并转换的规则文件列表（按需增删）
DOMAINSET_FILES = [
    "apple_cdn.conf",
    "cdn.conf",
    "download.conf",
    "game-download.conf",
    "icloud_private_relay.conf",
    "reject.conf",
    "reject_extra.conf",
    "reject_phishing.conf",
    "reject_sukka.conf",
    "speedtest.conf",
]

NON_IP_FILES = [
    "ai.conf",
    "apple_cdn.conf",
    "apple_cn.conf",
    "apple_intelligence.conf",
    "apple_services.conf",
    "cdn.conf",
    "direct.conf",
    "domestic.conf",
    "download.conf",
    "global.conf",
    "global_plus.conf",
    "gitlab.conf",
    "lan.conf",
    "microsoft_cdn.conf",
    "microsoft.conf",
    "my_direct.conf,
    "my_git.conf",
    "my_plus.conf",
    "my_proxy.conf",
    "my_reject.conf",
    "my_tw.conf",
    "my_us.conf",
    "neteasemusic.conf",
    "reject.conf",
    "reject-drop.conf",
    "reject-no-drop.conf",
    "reject-url-regex.conf",
    "sogouinput.conf",
    "stream.conf",
    "stream_biliintl.conf",
    "stream_eu.conf",
    "stream_hk.conf",
    "stream_jp.conf",
    "stream_kr.conf",
    "stream_tw.conf",
    "stream_us.conf",
    "telegram.conf",
]

IP_FILES = [
    "ai.conf",
    "apple_services.conf",
    "cdn.conf",
    "china_ip.conf",
    "china_ip_ipv6.conf",
    "domestic.conf",
    "download.conf",
    "lan.conf",
    "neteasemusic.conf",
    "reject.conf",
    "stream.conf",
    "stream_biliintl.conf",
    "stream_eu.conf",
    "stream_hk.conf",
    "stream_jp.conf",
    "stream_kr.conf",
    "stream_tw.conf",
    "stream_us.conf",
    "telegram.conf",
]

# SukkaW 的水印域名，domain-list-community 会拒绝（含下划线）
WATERMARKS = [
    "7h15_ru1353t_1s_m4d3_by_5ukk4w.skk.moe",
    "this_rule_set_is_made_by_sukkaw",
]


def is_valid_domain_label(label: str) -> bool:
    """校验域名 label 是否合法（RFC 1123）"""
    if not label or len(label) > 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return bool(re.fullmatch(r"[a-zA-Z0-9-]+", label))


def is_valid_domain(domain: str) -> bool:
    """校验完整域名是否合法（用于 domain/suffix）"""
    if not domain or len(domain) > 253:
        return False
    if domain in WATERMARKS:
        return False
    labels = domain.split(".")
    for label in labels:
        if label == "*":
            continue
        if not is_valid_domain_label(label):
            return False
    return True


def is_valid_dlc_chars(value: str) -> bool:
    """
    domain-list-community 的 validateDomainChars 等价校验。
    只允许 a-z, 0-9, ., -（domain/full/keyword 类型通用）
    """
    if not value:
        return False
    for c in value.lower():
        if 'a' <= c <= 'z' or '0' <= c <= '9' or c in '.-':
            continue
        return False
    return True


def is_watermark(value: str) -> bool:
    """检查是否包含 SukkaW 水印特征（下划线是主要标志）"""
    if "_" in value:
        return True
    for wm in WATERMARKS:
        if wm in value:
            return True
    return False


def download(url: str) -> str:
    """下载文本内容"""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; dae-ruleset-builder/1.0)"
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def wildcard_to_regex(pattern: str) -> str:
    """
    将 Surge DOMAIN-WILDCARD 转换为正则表达式。
    Surge 通配符语义：* 匹配任意字符序列，? 匹配单个字符。
    """
    ph_star = "\x00STAR\x00"
    ph_qmark = "\x00QMARK\x00"
    temp = pattern.replace("*", ph_star).replace("?", ph_qmark)
    temp = re.escape(temp)
    temp = temp.replace(ph_star, ".*").replace(ph_qmark, ".")
    if not temp.startswith("^"):
        temp = "^" + temp
    if not temp.endswith("$"):
        temp = temp + "$"
    return temp


def convert_domainset(content: str) -> str:
    """domainset 是纯域名列表，.example.com 表示 suffix"""
    lines = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("."):
            domain = line[1:]
            if is_valid_domain(domain):
                # domain-list-community 默认类型就是 domain（suffix 语义），省略前缀
                lines.append(domain)
        else:
            if is_valid_domain(line):
                # 完整域名匹配
                lines.append(f"full:{line}")
    return "\n".join(lines)


def convert_non_ip(content: str, filename: str):
    """non_ip 包含多种规则，只提取 dae 支持的域名类规则"""
    lines = []
    dropped = []
    invalid = 0
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("DOMAIN,"):
            domain = line[7:].strip()
            if is_valid_domain(domain):
                lines.append(f"full:{domain}")
            else:
                invalid += 1

        elif line.startswith("DOMAIN-SUFFIX,"):
            domain = line[14:].strip()
            if is_valid_domain(domain):
                # domain-list-community 默认类型即 domain（suffix 语义），省略前缀
                lines.append(domain)
            else:
                invalid += 1

        elif line.startswith("DOMAIN-KEYWORD,"):
            keyword = line[15:].strip()
            if is_valid_dlc_chars(keyword) and not is_watermark(keyword):
                lines.append(f"keyword:{keyword}")
            else:
                invalid += 1

        elif line.startswith("DOMAIN-WILDCARD,"):
            pattern = line[16:].strip()
            if is_watermark(pattern):
                invalid += 1
                continue
            regex = wildcard_to_regex(pattern)
            try:
                re.compile(regex)
                lines.append(f"regexp:{regex}")
            except re.error as e:
                print(f"  [{filename}] 跳过非法正则: {regex} ({e})")
                dropped.append(line)

        elif line.startswith("IP-CIDR,") or line.startswith("IP-CIDR6,"):
            dropped.append(line)

        else:
            dropped.append(line)

    if dropped:
        print(f"  [{filename}] 跳过 {len(dropped)} 条不支持的规则")
        for d in dropped[:5]:
            print(f"    - {d}")
        if len(dropped) > 5:
            print(f"    ... 还有 {len(dropped) - 5} 条")
    if invalid:
        print(f"  [{filename}] 过滤 {invalid} 条非法域名/关键字（含水印）")

    return "\n".join(lines)


def convert_ip(content: str) -> str:
    """提取 IP-CIDR / IP-CIDR6 为纯 CIDR 列表，跳过 no-resolve 等后缀"""
    lines = []
    dropped = []
    invalid = 0
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("DOMAIN,"):
            continue

        cidr = None
        if line.startswith("IP-CIDR,"):
            parts = line.split(",")
            if len(parts) >= 2:
                cidr = parts[1].strip()
        elif line.startswith("IP-CIDR6,"):
            parts = line.split(",")
            if len(parts) >= 2:
                cidr = parts[1].strip()

        if cidr:
            try:
                ipaddress.ip_network(cidr, strict=False)
                lines.append(cidr)
            except ValueError:
                invalid += 1
                dropped.append(line)
        elif line.startswith("IP-ASN,"):
            dropped.append(line)
        elif not line.startswith("DOMAIN,"):
            dropped.append(line)

    if dropped:
        total_dropped = len(dropped)
        print(f"  [ip] 跳过 {total_dropped} 条不支持的规则")
        for d in dropped[:5]:
            print(f"    - {d}")
        if total_dropped > 5:
            print(f"    ... 还有 {total_dropped - 5} 条")
    if invalid:
        print(f"  [ip] 过滤 {invalid} 条非法 CIDR")

    return "\n".join(lines)


def generate_geoip_config(ip_dir: Path) -> dict:
    """为 v2fly/geoip 生成 config.json"""
    inputs = []
    for f in sorted(ip_dir.glob("*.txt")):
        tag = f.stem
        inputs.append({
            "type": "text",
            "action": "add",
            "args": {
                "name": tag,
                "uri": str(f.resolve())
            }
        })

    return {
        "input": inputs,
        "output": [
            {
                "type": "v2rayGeoIPDat",
                "action": "output",
                "args": {
                    "outputName": "sukka-ip.dat",
                    "outputDir": "./"
                }
            }
        ]
    }


def fetch_and_convert(category: str, files: list, converter, out_subdir: Path):
    """批量下载并转换"""
    for fname in files:
        url = f"{BASE_URL}/{category}/{fname}"
        # domain-list-community 的 list name 只能包含 A-Z, 0-9, -, !
        # 因此把文件名中的下划线替换为连字符
        tag = Path(fname).stem.replace("_", "-")
        try:
            content = download(url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f"[跳过] {url} (404)")
                continue
            raise

        result = converter(content, tag) if category == "non_ip" else converter(content)
        if not result:
            print(f"[空]   {fname} -> 无可转换规则")
            continue

        if category == "ip":
            out_path = out_subdir / f"{tag}.txt"
        else:
            out_path = out_subdir / tag

        # 如果同名文件已存在（domainset 与 non_ip 重叠），追加合并而非覆盖
        if out_path.exists():
            existing = out_path.read_text(encoding="utf-8")
            combined = existing + "\n" + result
            out_path.write_text(combined, encoding="utf-8")
            total_lines = len(combined.splitlines())
            new_lines = len(result.splitlines())
            print(f"[{category:9s}] {fname} -> {out_path.name} (追加 {new_lines} 条, 共 {total_lines} 条)")
        else:
            out_path.write_text(result, encoding="utf-8")
            print(f"[{category:9s}] {fname} -> {out_path.name} ({len(result.splitlines())} 条)")


def main():
    out = Path("data")
    out.mkdir(exist_ok=True)
    (out / "domains").mkdir(exist_ok=True)
    (out / "ips").mkdir(exist_ok=True)

    print(f"规则源: {BASE_URL}")
    print("=" * 50)

    fetch_and_convert("domainset", DOMAINSET_FILES, convert_domainset, out / "domains")
    fetch_and_convert("non_ip", NON_IP_FILES, convert_non_ip, out / "domains")
    fetch_and_convert("ip", IP_FILES, convert_ip, out / "ips")

    config = generate_geoip_config(out / "ips")
    (out / "geoip-config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[geoip]     已生成 geoip-config.json ({len(config['input'])} 个 IP 集合)")

    print("\n转换完成，输出目录: data/")


if __name__ == "__main__":
    main()
