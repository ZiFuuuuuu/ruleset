#!/usr/bin/env python3

import os
import glob
import re


SRC = "ruleset/List"

OUT_DOMAIN = "domain-list-community/data"

OUT_GEOIP = "geoip/data"


def add_rule(group, rule):

    os.makedirs(
        OUT_DOMAIN,
        exist_ok=True
    )

    path = os.path.join(
        OUT_DOMAIN,
        group
    )

    with open(
        path,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            rule + "\n"
        )


def add_ip(group, ip):

    os.makedirs(
        OUT_GEOIP,
        exist_ok=True
    )

    path = os.path.join(
        OUT_GEOIP,
        group
    )

    with open(
        path,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            ip + "\n"
        )


def clean_domain(d):

    d=d.strip()

    if d.startswith("."):
        d=d[1:]

    return d.lower()



def convert_domainset(line):

    d=clean_domain(line)

    if d:

        return "domain:" + d



def wildcard_convert(d):

    d=d.strip()


    # *.example.com
    if d.startswith("*."):

        return (
            "domain:"
            +
            d[2:]
        )


    # 普通通配
    pattern=re.escape(d)

    pattern=pattern.replace(
        r"\*",
        ".*"
    )


    return (
        "regexp:^"
        +
        pattern
        +
        "$"
    )



def convert_non_ip(line):

    p=line.split(",")

    if len(p)<2:
        return None


    t=p[0].upper()

    d=p[1].strip()



    if t=="DOMAIN":

        return (
            "full:"
            +
            clean_domain(d)
        )


    if t=="DOMAIN-SUFFIX":

        return (
            "domain:"
            +
            clean_domain(d)
        )


    if t=="DOMAIN-KEYWORD":

        return (
            "keyword:"
            +
            d
        )


    if t=="DOMAIN-WILDCARD":

        return wildcard_convert(d)


    # 不支持
    return None



def convert_ip(line):

    p=line.split(",")

    if len(p)<2:
        return None


    if p[0].upper() in (
        "IP-CIDR",
        "IP-CIDR6"
    ):

        return p[1]


def main():


    # 清空旧文件

    for d in (
        OUT_DOMAIN,
        OUT_GEOIP
    ):

        if os.path.exists(d):

            for f in glob.glob(
                d+"/*"
            ):

                os.remove(f)



    for root,dirs,files in os.walk(SRC):

        for file in files:


            if not file.endswith(".conf"):
                continue



            path=os.path.join(
                root,
                file
            )


            rel=os.path.relpath(
                path,
                SRC
            )


            category=rel.split(
                os.sep
            )[0]


            tag=os.path.splitext(
                file
            )[0]


            print(
                "Processing:",
                path
            )


            with open(
                path,
                encoding="utf-8"
            ) as f:


                for line in f:


                    line=line.strip()


                    if not line:
                        continue


                    if category=="domainset":

                        r=convert_domainset(
                            line
                        )

                        if r:
                            add_rule(
                                tag,
                                r
                            )


                    elif category=="non_ip":

                        r=convert_non_ip(
                            line
                        )

                        if r:
                            add_rule(
                                tag,
                                r
                            )


                    elif category=="ip":

                        r=convert_ip(
                            line
                        )

                        if r:

                            add_ip(
                                tag,
                                r
                            )



    print("Done")


if __name__=="__main__":

    main()
