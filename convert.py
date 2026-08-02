#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert SukkaLab/ruleset.skk.moe Surge rules
to dae local rule files.

Input:
    ruleset.skk.moe/List/

Output:
    output/

Supported:
    DOMAIN
    DOMAIN-SUFFIX
    DOMAIN-KEYWORD
    DOMAIN-WILDCARD
    IP-CIDR
    IP-CIDR6
"""

from pathlib import Path
import shutil
import subprocess
import sys


SOURCE_REPO = "https://github.com/SukkaLab/ruleset.skk.moe.git"

REPO_DIR = Path("ruleset.skk.moe")
SOURCE_DIR = REPO_DIR / "List"

OUTPUT_DIR = Path("output")


SUPPORTED_SUFFIX = {
    ".list",
    ".conf",
    ".txt",
}


def run(cmd):
    subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.DEVNULL
    )


def clone_source():

    if REPO_DIR.exists():
        shutil.rmtree(REPO_DIR)

    print("[+] Clone ruleset repository")

    run([
        "git",
        "clone",
        "--depth",
        "1",
        SOURCE_REPO,
        str(REPO_DIR)
    ])


def clean_output():

    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)

    OUTPUT_DIR.mkdir()


def convert_rule(line):

    line = line.strip()

    if not line:
        return None

    # comments
    if line.startswith("#"):
        return None

    if line.startswith("//"):
        return None


    # Surge format:
    # TYPE,value

    parts = [
        x.strip()
        for x in line.split(",")
    ]


    if len(parts) < 2:
        return None


    rule_type = parts[0].upper()
    value = parts[1]


    if rule_type == "DOMAIN":

        return (
            f"full:{value}"
        )


    elif rule_type == "DOMAIN-SUFFIX":

        return (
            f"suffix:{value}"
        )


    elif rule_type == "DOMAIN-KEYWORD":

        return (
            f"keyword:{value}"
        )


    elif rule_type == "DOMAIN-WILDCARD":

        wildcard = (
            value
            .replace(".", r"\.")
            .replace("*", ".*")
        )

        return (
            f"regex:{wildcard}"
        )


    elif rule_type in (
        "IP-CIDR",
        "IP-CIDR6"
    ):

        return value


    # unsupported:
    return None



def convert_file(src: Path):

    relative = src.relative_to(
        SOURCE_DIR
    )


    # keep directory tree

    dst = (
        OUTPUT_DIR
        /
        relative
    ).with_suffix(".dae")


    dst.parent.mkdir(
        parents=True,
        exist_ok=True
    )


    rules = set()

    ignored = 0


    with open(
        src,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        for line in f:

            rule = convert_rule(line)

            if rule:

                rules.add(rule)

            else:

                ignored += 1


    with open(
        dst,
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:

        for rule in sorted(rules):

            f.write(
                rule
                +
                "\n"
            )


    return (
        len(rules),
        ignored
    )



def main():

    clone_source()

    clean_output()


    total_files = 0
    total_rules = 0


    for file in SOURCE_DIR.rglob("*"):

        if not file.is_file():

            continue


        if file.suffix.lower() not in SUPPORTED_SUFFIX:

            continue


        total_files += 1


        rules, ignored = convert_file(file)

        total_rules += rules


        print(
            f"[OK] {file} "
            f"rules={rules} "
            f"ignored={ignored}"
        )


    print()
    print("======================")
    print(
        f"Files : {total_files}"
    )

    print(
        f"Rules : {total_rules}"
    )

    print("======================")


if __name__ == "__main__":

    try:
        main()

    except Exception as e:

        print(
            "[ERROR]",
            e
        )

        sys.exit(1)
