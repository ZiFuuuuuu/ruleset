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
import urllib.request
import urllib.error
from pathlib import Path

BASE_URL = "https://ruleset.skk.moe/List"

# 需要下载并转换的规则文件列表
# 你可以根据需要增删
DOMAINSET_FILES = [
    "apple_cdn.conf",
    "cdn.conf",
    "download.conf",
    "icloud_private_relay.conf",
    "reject.conf",
    "reject_extra.conf",
    "reject_phishing.conf",
    "speedtest.conf",
]

NON_IP_FILES = [
    "ai.conf",
    "apple_cdn.conf",
    "apple_cn.conf",
    "apple_services.conf",
    "cdn.conf",
    "direct.conf",
    "domestic.conf",
    "download.conf",
    "global.conf",
    "lan.conf",
    "microsoft_cdn.conf",
    "microsoft.conf",
    "reject.conf",
    "reject-drop.conf",
    "reject-no-drop.conf",
    "stream.conf",
    "stream_eu.conf",
    "stream_hk.conf",
    "stream_jp.conf",
    "stream_kr.conf",
    "stream_tw.conf",
    "stream_us.conf",
    "telegram.conf",
]

IP_FILES = [
    "china_ip.conf",
    "domestic.conf",
    "lan.conf",
    "reject.conf",
    "stream.conf",
    "stream_eu.conf",
    "stream_hk.conf",
    "stream_jp.conf",
    "stream_kr.conf",
    "stream_tw.conf",
    "stream_us.conf",
    "telegram.conf",
]


def download(url: str) -> str:
    """下载文本内容"""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; dae-ruleset-builder/1.0)"
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def convert_domainset(content: str) -> str:
    """domainset 是纯域名列表，.example.com 表示 suffix"""
    lines = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("."):
            lines.append(f"suffix:{line[1:]}")
        else:
            lines.append(f"domain:{line}")
    return "\n".join(lines)


def convert_non_ip(content: str, filename: str):
    """non_ip 包含多种规则，只提取 dae 支持的域名类规则"""
    lines = []
    dropped = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("DOMAIN,"):
            lines.append(f"domain:{line[7:].strip()}")

        elif line.startswith("DOMAIN-SUFFIX,"):
            lines.append(f"suffix:{line[14:].strip()}")

        elif line.startswith("DOMAIN-KEYWORD,"):
            lines.append(f"keyword:{line[15:].strip()}")

        elif line.startswith("DOMAIN-WILDCARD,"):
            pattern = line[16:].strip()
            regex = pattern.replace(".", r"\.").replace("*", ".*")
            if not regex.startswith("^"):
                regex = "^" + regex
            if not regex.endswith("$"):
                regex = regex + "$"
            lines.append(f"regexp:{regex}")

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

    return "\n".join(lines)


def convert_ip(content: str) -> str:
    """提取 IP-CIDR / IP-CIDR6 为纯 CIDR 列表"""
    lines = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("IP-CIDR,"):
            lines.append(line[8:].strip())
        elif line.startswith("IP-CIDR6,"):
            lines.append(line[9:].strip())
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
        "output": {
            "type": "v2rayGeoIPDat",
            "action": "output",
            "args": {
                "outputName": "sukka-ip.dat",
                "outputDir": "./"
            }
        }
    }


def fetch_and_convert(category: str, files: list, converter, out_subdir: Path):
    """批量下载并转换"""
    for fname in files:
        url = f"{BASE_URL}/{category}/{fname}"
        tag = Path(fname).stem
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

    # 生成 geoip 配置
    config = generate_geoip_config(out / "ips")
    (out / "geoip-config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[geoip]     已生成 geoip-config.json ({len(config['input'])} 个 IP 集合)")

    print("\n转换完成，输出目录: data/")


if __name__ == "__main__":
    main()
