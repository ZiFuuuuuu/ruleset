import os
import requests


BASE = "https://raw.githubusercontent.com/SukkaLab/ruleset.skk.moe/master/List"


OUT = "output"


os.makedirs(
    OUT + "/domain",
    exist_ok=True
)

os.makedirs(
    OUT + "/ip",
    exist_ok=True
)


def convert_line(line):

    line=line.strip()


    if not line:
        return None


    if line.startswith("#"):
        return None


    # Surge格式

    if line.startswith("DOMAIN-SUFFIX,"):

        domain=line.split(",",1)[1]

        return (
            "domain_suffix",
            domain
        )


    if line.startswith("DOMAIN,"):

        domain=line.split(",",1)[1]

        return (
            "domain",
            domain
        )


    if line.startswith("IP-CIDR,"):

        ip=line.split(",",1)[1]

        return (
            "ip",
            ip
        )


    if line.startswith("IP-CIDR6,"):

        ip=line.split(",",1)[1]

        return (
            "ip",
            ip
        )


    # domainset纯域名

    if "." in line and "/" not in line:

        return (
            "domain_suffix",
            line
        )


    return None



def process_file(url):

    name=url.split("/")[-1]

    data=requests.get(
        url,
        timeout=30
    ).text


    domains=[]

    ips=[]


    for line in data.splitlines():

        r=convert_line(line)


        if not r:
            continue


        typ,value=r


        if typ in (
            "domain",
            "domain_suffix"
        ):

            domains.append(
                f"{typ} {value}"
            )


        elif typ=="ip":

            ips.append(value)



    if domains:

        with open(
            f"{OUT}/domain/{name}",
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                "\n".join(
                    sorted(
                        set(domains)
                    )
                )
            )


    if ips:

        with open(
            f"{OUT}/ip/{name}",
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                "\n".join(
                    sorted(
                        set(ips)
                    )
                )
            )



def walk(path=""):

    url=f"{BASE}/{path}"


    r=requests.get(
        url
    )

    # GitHub raw不能列目录
    # 后续改为clone仓库方式

