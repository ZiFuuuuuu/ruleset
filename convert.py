#!/usr/bin/env python3

from pathlib import Path
import shutil
import subprocess

REPO = "ruleset.skk.moe"

if Path(REPO).exists():
    shutil.rmtree(REPO)

subprocess.run([
    "git",
    "clone",
    "--depth",
    "1",
    "https://github.com/SukkaLab/ruleset.skk.moe.git"
], check=True)

SRC = Path(REPO) / "List"
DST = Path("output") / "List"

if DST.exists():
    shutil.rmtree(DST)

SUPPORTED = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "IP-CIDR",
    "IP-CIDR6"
}


def convert(line: str):

    line = line.strip()

    if not line:
        return None

    if line.startswith("#"):
        return None

    if line.startswith("//"):
        return None

    parts = [x.strip() for x in line.split(",")]

    if len(parts) < 2:
        return None

    t = parts[0].upper()
    value = parts[1]

    if t not in SUPPORTED:
        return None

    if t == "DOMAIN":
        return f"domain(full:{value})"

    if t == "DOMAIN-SUFFIX":
        return f"domain(suffix:{value})"

    if t == "DOMAIN-KEYWORD":
        return f"domain(keyword:{value})"

    if t == "DOMAIN-WILDCARD":
        return f"domain(regex:{value.replace('*','.*')})"

    if t == "IP-CIDR":
        return f"ip({value})"

    if t == "IP-CIDR6":
        return f"ip({value})"

    return None


count_file = 0
count_rule = 0

for src in SRC.rglob("*"):

    if not src.is_file():
        continue

    relative = src.relative_to(SRC)

    dst = (DST / relative).with_suffix(".txt")

    dst.parent.mkdir(parents=True, exist_ok=True)

    count_file += 1

    with open(src, encoding="utf-8") as fin, \
         open(dst, "w", encoding="utf-8", newline="\n") as fout:

        for line in fin:

            newline = convert(line)

            if newline:

                fout.write(newline + "\n")

                count_rule += 1

print(f"Converted Files : {count_file}")
print(f"Converted Rules : {count_rule}")
