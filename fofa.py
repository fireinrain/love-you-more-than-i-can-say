from fofa_hack import fofa


FoFaQueryRules = [
    'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country=="KR"',
    'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country=="JP"',
    'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && region=="TW"',
    'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && region=="HK"',
    'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && region=="MO"',
    'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country=="SG"',
    'server=="cloudflare" && header="Forbidden" && asn="906" && country=="US"'
]


def query_proxy_ip(query_rule: str, count: int) -> []:
    pass


def main():
    result_generator = fofa.api(FoFaQueryRules[6], endcount=10)
    for data in result_generator:
        print(data)


if __name__ == '__main__':
    main()
