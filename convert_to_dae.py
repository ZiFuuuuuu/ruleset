#!/usr/bin/env python3
"""
将 SukkaLab/ruleset.skk.moe 的 Surge List 规则递归转换为 dae 兼容格式。
支持内核版本：dae 2026.07.31-r4
"""

import os
import sys
from pathlib import Path


def convert_ruleset(src_dir: str, dst_dir: str):
    src = Path(src_dir)
    dst = Path(dst_dir)

    # 清理旧输出
    if dst.exists():
        import shutil
        shutil.rmtree(dst)
    dst.mkdir(parents=True)

    routing_rules = []

    for subdir in ["non_ip", "domainset", "ip"]:
        src_sub = src / subdir
        dst_sub = dst / subdir
        if not src_sub.exists():
            print(f"[WARN] {src_sub} 不存在，跳过")
            continue
        dst_sub.mkdir(parents=True, exist_ok=True)

        for conf_file in src_sub.rglob("*.conf"):
            rel = conf_file.relative_to(src_sub)
            print(f"[INFO] 正在转换: {conf_file}")

            if subdir == "domainset":
                convert_domainset(conf_file, dst_sub / rel, routing_rules)
            elif subdir == "non_ip":
                convert_non_ip(conf_file, dst_sub, rel, routing_rules)
            elif subdir == "ip":
                convert_ip(conf_file, dst_sub / rel, routing_rules)

    # 生成路由配置模板
    routing_file = dst / "routing.dae"
    with open(routing_file, "w", encoding="utf-8") as f:
        f.write("// ============================================\n")
        f.write("// dae routing 配置参考模板\n")
        f.write("// 请将这些规则按需复制到你的 dae.conf routing 段中\n")
        f.write("// 并根据实际需求修改动作（proxy / direct / block）\n")
        f.write("// ============================================\n\n")
        f.write("routing {\n")
        for rule in sorted(set(routing_rules)):
            f.write(f"    {rule}\n")
        f.write("    // fallback 规则请自行补充\n")
        f.write("    // fallback: proxy\n")
        f.write("}\n")

    print(f"\n[SUCCESS] 转换完成，输出目录: {dst.absolute()}")
    print(f"[SUCCESS] 路由模板: {routing_file.absolute()}")


def convert_domainset(src: Path, dst: Path, routing_rules: list):
    """domainset: 纯域名列表 → dae domain 列表（精确匹配）"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    domains = []

    with open(src, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)

    if not domains:
        return

    with open(dst, "w", encoding="utf-8") as f:
        for d in domains:
            f.write(d + "\n")

    rel = dst.relative_to(dst.parent.parent.parent)
    routing_rules.append(f"domain('{rel}') -> proxy  // {dst.name}")


def convert_non_ip(src: Path, dst_sub: Path, rel: Path, routing_rules: list):
    """
    non_ip: Surge RULE-SET 按类型拆分为多个 dae 纯列表文件。
    输出文件名示例: reject_domain.conf / reject_domain_suffix.conf / reject_domain_keyword.conf
    """
    base_name = rel.stem
    out_dir = dst_sub / rel.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    domains = []
    suffixes = []
    keywords = []
    unsupported = []

    with open(src, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("DOMAIN-SUFFIX,"):
                suffixes.append(line.split(",", 1)[1].strip())
            elif line.startswith("DOMAIN,"):
                domains.append(line.split(",", 1)[1].strip())
            elif line.startswith("DOMAIN-KEYWORD,"):
                keywords.append(line.split(",", 1)[1].strip())
            elif line.startswith("URL-REGEX,") or line.startswith("USER-AGENT,") or line.startswith("PROCESS-NAME,"):
                unsupported.append(line)
            else:
                # 兜底解析
                parts = line.split(",")
                if len(parts) >= 2:
                    t, v = parts[0], parts[1]
                    if t == "DOMAIN-SUFFIX":
                        suffixes.append(v)
                    elif t == "DOMAIN":
                        domains.append(v)
                    elif t == "DOMAIN-KEYWORD":
                        keywords.append(v)
                    else:
                        unsupported.append(line)
                else:
                    unsupported.append(line)

    rel_base = out_dir.relative_to(dst_sub.parent.parent)

    if domains:
        p = out_dir / f"{base_name}_domain.conf"
        with open(p, "w", encoding="utf-8") as f:
            for d in domains:
                f.write(d + "\n")
        routing_rules.append(f"domain('{rel_base}/{base_name}_domain.conf') -> proxy")

    if suffixes:
        p = out_dir / f"{base_name}_domain_suffix.conf"
        with open(p, "w", encoding="utf-8") as f:
            for d in suffixes:
                f.write(d + "\n")
        routing_rules.append(f"domain_suffix('{rel_base}/{base_name}_domain_suffix.conf') -> proxy")

    if keywords:
        p = out_dir / f"{base_name}_domain_keyword.conf"
        with open(p, "w", encoding="utf-8") as f:
            for d in keywords:
                f.write(d + "\n")
        routing_rules.append(f"domain_keyword('{rel_base}/{base_name}_domain_keyword.conf') -> proxy")

    if unsupported:
        p = out_dir / f"{base_name}_unsupported.conf"
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"// 以下 {len(unsupported)} 条规则 dae 不支持，已跳过\n")
            for line in unsupported:
                f.write(f"// {line}\n")
        print(f"  [WARN] {len(unsupported)} 条不支持规则已跳过 -> {p.name}")


def convert_ip(src: Path, dst: Path, routing_rules: list):
    """ip: Surge IP RULE-SET → dae ip_cidr 列表"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    cidrs = []

    with open(src, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("IP-CIDR,") or line.startswith("IP-CIDR6,"):
                cidrs.append(line.split(",", 1)[1].strip())
            else:
                cidrs.append(line)

    if not cidrs:
        return

    with open(dst, "w", encoding="utf-8") as f:
        for cidr in cidrs:
            f.write(cidr + "\n")

    rel = dst.relative_to(dst.parent.parent.parent)
    routing_rules.append(f"ip_cidr('{rel}') -> proxy  // {dst.name}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <源List目录> <输出目录>")
        sys.exit(1)
    convert_ruleset(sys.argv[1], sys.argv[2])
