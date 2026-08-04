#!/usr/bin/env python3

import os
import glob
import re


SRC = "ruleset/List"

DOMAIN_OUT = "data"

GEOIP_OUT = "geoip_data"



def reset_dir(path):

    if os.path.exists(path):

        for f in glob.glob(
            path + "/*"
        ):

            if os.path.isfile(f):

                os.remove(f)

    else:

        os.makedirs(path)



def write_rule(tag, rule):

    path = os.path.join(
        DOMAIN_OUT,
        tag
    )

    with open(
        path,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            rule + "\n"
        )



def write_ip(tag, ip):

    path = os.path.join(
        GEOIP_OUT,
        tag
    )

    with open(
        path,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            ip + "\n"
        )



def clean_domain(domain):

    domain = domain.strip()


    if domain.startswith("."):

        domain = domain[1:]


    return domain.lower()



def convert_domainset(line):

    line=line.strip()


    if not line:

        return None


    # domainset全部按后缀处理

    return (
        "domain:"
        +
        clean_domain(line)
    )



def convert_wildcard(domain):

    domain=domain.strip()


    # *.example.com

    if domain.startswith("*."):

        return (
            "domain:"
            +
            clean_domain(
                domain[2:]
            )
        )


    pattern=re.escape(domain)


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

    parts=line.split(",")


    if len(parts)<2:

        return None



    rule=parts[0].upper()

    value=parts[1].strip()



    if rule=="DOMAIN":

        return (
            "full:"
            +
            clean_domain(value)
        )


    elif rule=="DOMAIN-SUFFIX":

        return (
            "domain:"
            +
            clean_domain(value)
        )


    elif rule=="DOMAIN-KEYWORD":

        return (
            "keyword:"
            +
            value
        )


    elif rule=="DOMAIN-WILDCARD":

        return convert_wildcard(value)



    # 以下 Surge 规则 V2Ray 不支持

    elif rule in (
        "PROCESS-NAME",
        "USER-AGENT",
        "URL-REGEX",
        "DST-PORT",
        "SRC-IP-CIDR"
    ):

        return None


    return None



def convert_ip(line):

    parts=line.split(",")


    if len(parts)<2:

        return None



    rule=parts[0].upper()


    if rule in (
        "IP-CIDR",
        "IP-CIDR6"
    ):

        return parts[1].strip()


    return None



def main():


    reset_dir(
        DOMAIN_OUT
    )


    reset_dir(
        GEOIP_OUT
    )



    for root, dirs, files in os.walk(SRC):


        for filename in files:


            if not filename.endswith(".conf"):

                continue



            path=os.path.join(
                root,
                filename
            )



            relative=os.path.relpath(
                path,
                SRC
            )


            category=relative.split(
                os.sep
            )[0]


            tag=os.path.splitext(
                filename
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



                    result=None



                    if category=="domainset":

                        result=convert_domainset(
                            line
                        )


                        if result:

                            write_rule(
                                tag,
                                result
                            )



                    elif category=="non_ip":


                        result=convert_non_ip(
                            line
                        )


                        if result:

                            write_rule(
                                tag,
                                result
                            )



                    elif category=="ip":


                        result=convert_ip(
                            line
                        )


                        if result:

                            write_ip(
                                tag,
                                result
                            )



    print(
        "Conversion finished"
    )



if __name__=="__main__":

    main()
