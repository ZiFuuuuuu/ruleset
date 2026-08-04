#!/usr/bin/env python3
"""
将 SukkaW/Surge List 规则转换为 dae 可用的 DAT 构建源文件
支持：
  - List/domainset/*.conf   -> domain-list-community (domain/suffix)
  - List/non_ip/*.conf      -> domain-list-community (domain/suffix/keyword/regexp)
  - List/ip/*.conf          -> geoip text (CIDR 列表)

不支持的规则类型（自动跳过并记录）：
  PROCESS-NAME, USER-AGENT, URL-REGEX, DOMAIN-SET, IP-CIDR(出现在 non_ip 中)
"""
import sys
import json
from pathlib import Path


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
            # 转义点号，将 * 替换为 .*，并添加锚点
            regex = pattern.replace(".", r"\.").replace("*", ".*")
            if not regex.startswith("^"):
                regex = "^" + regex
            if not regex.endswith("$"):
                regex = regex + "$"
            lines.append(f"regexp:{regex}")

        elif line.startswith("IP-CIDR,") or line.startswith("IP-CIDR6,"):
            # non_ip 中偶尔混有 IP 规则，建议归入 ip 文件夹；这里记录并跳过
            dropped.append(line)

        else:
            # 包括 PROCESS-NAME, USER-AGENT, URL-REGEX, DOMAIN-SET, AND, OR, NOT 等
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


def main():
    surge = Path("SukkaW-Surge/List")
    if not surge.exists():
        print("错误: 未找到 SukkaW-Surge/List 目录，请先 clone SukkaW/Surge")
        sys.exit(1)

    out = Path("data")
    out.mkdir(exist_ok=True)
    (out / "domains").mkdir(exist_ok=True)
    (out / "ips").mkdir(exist_ok=True)

    # --- domainset ---
    domainset_dir = surge / "domainset"
    if domainset_dir.exists():
        for f in sorted(domainset_dir.glob("*.conf")):
            tag = f.stem
            content = convert_domainset(f.read_text(encoding="utf-8"))
            (out / "domains" / tag).write_text(content, encoding="utf-8")
            print(f"[domainset] {f.name} -> domains/{tag} ({len(content.splitlines())} 条)")

    # --- non_ip ---
    non_ip_dir = surge / "non_ip"
    if non_ip_dir.exists():
        for f in sorted(non_ip_dir.glob("*.conf")):
            tag = f.stem
            content = convert_non_ip(f.read_text(encoding="utf-8"), f.name)
            if content:
                (out / "domains" / tag).write_text(content, encoding="utf-8")
                print(f"[non_ip]    {f.name} -> domains/{tag} ({len(content.splitlines())} 条)")
            else:
                print(f"[non_ip]    {f.name} -> 无可转换规则，已跳过")

    # --- ip ---
    ip_dir = surge / "ip"
    if ip_dir.exists():
        for f in sorted(ip_dir.glob("*.conf")):
            tag = f.stem
            content = convert_ip(f.read_text(encoding="utf-8"))
            if content:
                (out / "ips" / f"{tag}.txt").write_text(content, encoding="utf-8")
                print(f"[ip]        {f.name} -> ips/{tag}.txt ({len(content.splitlines())} 条)")
            else:
                print(f"[ip]        {f.name} -> 无 IP 规则，已跳过")

    # --- geoip config ---
    config = generate_geoip_config(out / "ips")
    (out / "geoip-config.json").write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[geoip]     已生成 geoip-config.json ({len(config['input'])} 个 IP 集合)")

    print("\n转换完成，输出目录: data/")


if __name__ == "__main__":
    main()
