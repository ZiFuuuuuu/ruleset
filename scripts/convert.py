#!/usr/bin/env python3
"""
从 ruleset.skk.moe 下载 SukkaW Surge List 规则并转换为 dae 可用的 DAT 构建源文件

文件列表通过解析站点首页的目录树自动获取（支持官方站、镜像站、上游 dist 仓库索引），
只有自动获取完全失败时才退回脚本内置的硬编码列表，因此上游新增/删除规则文件后
无需再手工维护清单。

支持：
  - List/domainset/*.conf   -> domain-list-community (domain/suffix)
  - List/non_ip/*.conf      -> domain-list-community (domain/suffix/keyword/regexp)
  - List/ip/*.conf          -> geoip text (CIDR 列表)

不支持的规则类型（自动跳过并记录）：
  PROCESS-NAME, USER-AGENT, URL-REGEX, DOMAIN-SET, AND, OR, NOT
"""
import os
import json
import re
import shutil
import ipaddress
import urllib.request
import urllib.error
from pathlib import Path

DEFAULT_BASE_URL = "https://ruleset.skk.moe"
MIRROR_BASE_URL = "https://ruleset-mirror.skk.moe"
# 上游发布仓库（由 SukkaW/Surge 的构建流程推送），可作为文件与索引的备用源
RAW_DIST_BASE_URL = "https://raw.githubusercontent.com/SukkaLab/ruleset.skk.moe/master"

# 允许通过环境变量指定首选规则源，例如在无法直连 ruleset.skk.moe 时使用镜像：
#   RULESET_BASE_URL=https://ruleset-mirror.skk.moe python3 scripts/convert.py
BASE_URL = (os.environ.get("RULESET_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")

CATEGORIES = ("domainset", "non_ip", "ip")

# 硬编码兜底列表：仅在自动解析上游目录完全失败时使用。
# 正常情况下会自动发现上游新增文件，这里不需要再手动同步。
FALLBACK_FILES = {
    "domainset": [
        "apple_cdn.conf", "cdn.conf", "download.conf", "game-download.conf",
        "icloud_private_relay.conf", "reject.conf", "reject_extra.conf",
        "reject_phishing.conf", "reject_sukka.conf", "speedtest.conf",
    ],
    "non_ip": [
        "ai.conf", "apple_cdn.conf", "apple_cn.conf", "apple_intelligence.conf",
        "apple_services.conf", "cdn.conf", "cloudmounter.conf", "direct.conf",
        "domestic.conf", "domestic_cdn.conf", "download.conf", "gitlab.conf",
        "global.conf", "global_plus.conf", "lan.conf", "microsoft.conf",
        "microsoft_cdn.conf", "my_direct.conf", "my_git.conf", "my_plus.conf",
        "my_proxy.conf", "my_reject.conf", "my_tw.conf", "my_us.conf",
        "neteasemusic.conf", "reject-drop.conf", "reject-no-drop.conf",
        "reject-url-regex.conf", "reject.conf", "sogouinput.conf", "stream.conf",
        "stream_biliintl.conf", "stream_eu.conf", "stream_hk.conf", "stream_jp.conf",
        "stream_kr.conf", "stream_tw.conf", "stream_us.conf", "telegram.conf",
    ],
    "ip": [
        "ai.conf", "apple_services.conf", "cdn.conf", "china_ip.conf",
        "china_ip_ipv6.conf", "domestic.conf", "download.conf", "lan.conf",
        "neteasemusic.conf", "reject.conf", "stream.conf", "stream_biliintl.conf",
        "stream_eu.conf", "stream_hk.conf", "stream_jp.conf", "stream_kr.conf",
        "stream_tw.conf", "stream_us.conf", "telegram.conf", "telegram_asn.conf",
        "teleproto.conf",
    ],
}

# SukkaW 的水印域名，domain-list-community 会拒绝（含下划线）
WATERMARKS = [
    "7h15_ru1353t_1s_m4d3_by_5ukk4w.skk.moe",
    "this_rule_set_is_made_by_sukkaw",
]

# 索引页缓存 / 下载源健康状态
_INDEX_CACHE = None
_ALIVE_BASES = set()
_DEAD_BASES = set()
_BASES_USED = set()
_HTML_WARNED = set()


class RuleNotFound(Exception):
    """所有镜像都返回 404 时抛出"""


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
        "User-Agent": "Mozilla/5.0 (compatible; dae-ruleset-builder/1.0)",
        "Accept": "text/plain, text/html, */*",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8-sig", errors="replace")


def is_html_response(text: str) -> bool:
    """判断内容是否是 HTML 页面（用于识别镜像/代理返回的错误页）"""
    head = text.lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<html" in head


def index_sources():
    """首页索引地址（按优先级排列，同一地址只保留一次）"""
    candidates = [
        (BASE_URL, BASE_URL + "/"),
        (DEFAULT_BASE_URL, DEFAULT_BASE_URL + "/"),
        (MIRROR_BASE_URL, MIRROR_BASE_URL + "/"),
        (RAW_DIST_BASE_URL, RAW_DIST_BASE_URL + "/index.html"),
    ]
    sources = []
    seen = set()
    for base, url in candidates:
        if not base or url in seen:
            continue
        seen.add(url)
        sources.append((base, url))
    return sources


def fetch_index_pages():
    """
    下载并缓存各索引页。
    站点首页是一棵 HTML 目录树（历史上也曾是 Markdown），这里只关心其中
    /List/{category}/*.conf 形式的链接，因此直接对页面文本做链接匹配，
    不依赖具体的 HTML/Markdown 结构。
    """
    global _INDEX_CACHE
    if _INDEX_CACHE is not None:
        return _INDEX_CACHE

    pages = []
    for base, url in index_sources():
        try:
            text = download(url)
        except Exception as e:
            print(f"[索引] 无法获取 {url}: {e}")
            _DEAD_BASES.add(base)
            continue

        if "/List/" not in text:
            print(f"[索引] {url} 中未找到规则列表，已忽略")
            continue

        _ALIVE_BASES.add(base)
        pages.append((url, text))
        print(f"[索引] 已加载 {url}")

    _INDEX_CACHE = pages
    return pages


def extract_conf_names(text: str, category: str):
    """从索引页文本中提取指定分类下的 .conf 文件名"""
    # 兼容 Markdown 转义（apple\_cdn.conf）
    text = text.replace(r"\_", "_")
    pattern = re.compile(
        r"""(?:^|["'(/])List/""" + re.escape(category)
        + r"""/([A-Za-z0-9][A-Za-z0-9._-]*\.conf)\b""",
        re.IGNORECASE | re.MULTILINE,
    )
    return {m.group(1) for m in pattern.finditer(text)}


def list_remote_files(category: str):
    """
    自动发现指定分类下的所有 .conf 文件。
    返回 (文件名列表, 成功提供该分类文件的索引页列表)。
    """
    files = set()
    used_sources = []
    for url, text in fetch_index_pages():
        found = extract_conf_names(text, category)
        if found:
            files.update(found)
            used_sources.append(url)
    return sorted(files), used_sources


def rule_bases():
    """规则文件下载源（优先使用已验证可访问的源）"""
    bases = []
    for base in (BASE_URL, DEFAULT_BASE_URL, MIRROR_BASE_URL, RAW_DIST_BASE_URL):
        if base and base not in bases:
            bases.append(base)

    if _ALIVE_BASES:
        alive = [b for b in bases if b in _ALIVE_BASES]
        if alive:
            bases = alive

    return [b for b in bases if b not in _DEAD_BASES]


def download_rule(category: str, fname: str) -> str:
    """按优先级从多个镜像下载单个规则文件"""
    bases = rule_bases()
    if not bases:
        raise RuntimeError("所有规则下载源均不可用")

    last_error = None
    not_found = 0
    for base in bases:
        url = f"{base}/List/{category}/{fname}"
        try:
            content = download(url)
            if is_html_response(content):
                # 镜像/代理返回了错误页，换下一个源
                last_error = RuntimeError("返回的是 HTML 页面而不是规则文本")
                if base not in _HTML_WARNED:
                    print(f"[警告] {base} 返回 HTML 页面而不是规则文本，已跳过该源")
                    _HTML_WARNED.add(base)
                continue
            _BASES_USED.add(base)
            return content
        except urllib.error.HTTPError as e:
            last_error = e
            if e.code == 404:
                not_found += 1
                continue
            if e.code in (401, 403, 429) or e.code >= 500:
                # 源站拒绝/限流/故障：本次运行内不再尝试该源，避免每个文件都报错
                if base not in _DEAD_BASES:
                    print(f"[警告] {base} 返回 HTTP {e.code}，本次运行不再使用该源")
                    _DEAD_BASES.add(base)
            else:
                print(f"[警告] {url} 返回 HTTP {e.code}")
        except Exception as e:
            last_error = e
            # 连接级错误：本次运行内不再尝试该源，避免反复超时
            if base not in _DEAD_BASES:
                print(f"[警告] 无法连接 {base}: {e}")
                _DEAD_BASES.add(base)

    if not_found == len(bases):
        raise RuleNotFound(f"{category}/{fname}")
    raise RuntimeError(f"无法下载 {category}/{fname}: {last_error}")


def resolve_files(category: str, fallback):
    """
    合并“自动发现的上游文件列表”与“硬编码兜底列表”。
    自动发现成功时以它为主，兜底列表用于避免上游索引临时残缺时漏掉规则；
    自动发现失败时完全使用硬编码列表。
    """
    discovered, used_sources = list_remote_files(category)

    if not discovered:
        print(f"[回退] {category}: 自动获取失败，使用硬编码列表（{len(fallback)} 个文件）")
        return list(fallback)

    merged = sorted(set(discovered) | set(fallback))
    added = sorted(set(discovered) - set(fallback))
    extra = sorted(set(fallback) - set(discovered))

    print(f"[发现] {category}: 上游共 {len(discovered)} 个文件"
          f"（来源: {', '.join(used_sources)}）")
    if added:
        print(f"[发现] {category}: 新增 {len(added)} 个 -> {', '.join(added)}")
    if extra:
        print(f"[提示] {category}: 硬编码兜底中 {len(extra)} 个文件未出现在上游索引，"
              f"仍会尝试下载（404 自动跳过）: {', '.join(extra)}")
    return merged


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
        # domain-list-community 的 list name 只能包含 A-Z, 0-9, -, !
        # 因此把文件名中的下划线替换为连字符
        tag = Path(fname).stem.replace("_", "-")
        try:
            content = download_rule(category, fname)
        except RuleNotFound:
            print(f"[跳过] {category}/{fname} (所有源均 404)")
            continue

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


def main(out_dir: str = "data"):
    out = Path(out_dir)
    # 每次运行前清空 data 目录，避免历史 commit 的数据累积导致重复
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(exist_ok=True)
    (out / "domains").mkdir(exist_ok=True)
    (out / "ips").mkdir(exist_ok=True)

    print(f"首选规则源: {BASE_URL}")
    print("=" * 50)

    # 自动发现上游文件列表；失败时回退到 FALLBACK_FILES
    files = {}
    for category in CATEGORIES:
        files[category] = resolve_files(category, FALLBACK_FILES[category])

    print("=" * 50)
    print(f"[domainset] 共 {len(files['domainset'])} 个文件")
    print(f"[non_ip]    共 {len(files['non_ip'])} 个文件")
    print(f"[ip]        共 {len(files['ip'])} 个文件")
    print("=" * 50)

    fetch_and_convert("domainset", files["domainset"], convert_domainset, out / "domains")
    fetch_and_convert("non_ip", files["non_ip"], convert_non_ip, out / "domains")
    fetch_and_convert("ip", files["ip"], convert_ip, out / "ips")

    config = generate_geoip_config(out / "ips")
    (out / "geoip-config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[geoip]     已生成 geoip-config.json ({len(config['input'])} 个 IP 集合)")

    if _BASES_USED:
        print(f"[源]        实际使用: {', '.join(sorted(_BASES_USED))}")
    print(f"\n转换完成，输出目录: {out}/")


if __name__ == "__main__":
    main()
