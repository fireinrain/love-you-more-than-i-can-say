import asyncio
import json

from fofa_hack import fofa
from redis_tool import r
import notify

import checker

FoFaQueryRules = {
    'KR': 'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country=="KR" && "http"',
    'JP': 'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country=="JP" && "http"',
    'TW': 'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && region=="TW" && "http"',
    'HK': 'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && region=="HK" && "https"',
    'MO': 'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && region=="MO" && "http"',
    'SG': 'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country=="SG" && "http"',
    'CN': 'server=="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country=="CN" && "https"',
    'US': 'server=="cloudflare" && header="Forbidden" && asn="906" && country=="US" && "https"'
}


def query_proxy_ip(query_rule: str, count: int) -> [()]:
    result_generator = fofa.api(query_rule, endcount=count)
    result = set()
    result_list = []
    for data in result_generator:
        for ipinfo in data:
            result.add(ipinfo)

    for i in result:
        ip_str = i.split("//")[1]
        ip = None
        port = None
        if ":" in ip_str:
            ip = ip_str.split(":")[0]
            port = int(ip_str.split(":")[1])
        else:
            ip = ip_str
            port = 443
        result_list.append((ip, port))
    return result_list


def store_proxy_ip2redis(iptests, region: str):
    # 除了US 906 之外的us ip 都不需要
    dont_need_dc = ['North America', 'Europe']

    for server in iptests:
        ip = server['ip']
        port = server['port']
        loc = server['region']

        if server['download_speed'] == '0 kB/s' or (loc in dont_need_dc and region != 'US'):
            continue
        server_info_json = json.dumps(server)

        r.hsetnx('snifferx-result', f'fofa-{region.lower()}:{ip}:{port}', server_info_json)


async def main():
    # 发送TG消息开始
    msg_info = f"FoFa查找: fofa规则数量: {len(FoFaQueryRules)}"
    telegram_notify = notify.pretty_telegram_notify("🍻🍻Fofa-Find-Proxy运行开始",
                                                    f"fofa-find-proxy fofa",
                                                    msg_info)
    telegram_notify = notify.clean_str_for_tg(telegram_notify)
    success = notify.send_telegram_message(telegram_notify)

    if success:
        print("Start fofa message sent successfully!")
    else:
        print("Start fofa message failed to send.")
    fofa_static = {}
    for region, rule in FoFaQueryRules.items():
        print(f"find rule: {rule}")
        proxy_ips = query_proxy_ip(rule, 50)
        proxy_ip_list = []
        for proxy_ip in proxy_ips:
            check_info = await checker.check_if_cf_proxy(proxy_ip[0], proxy_ip[1])
            if check_info[0]:
                print(f"ip: {proxy_ip[0]},port:{proxy_ip[1]}, cf-proxy:{check_info}")
                proxy_ip_list.append(check_info[1])
        fofa_static[region] = len(proxy_ip_list)
        store_proxy_ip2redis(proxy_ip_list, region)
        print("--------------------------------")
        await asyncio.sleep(30)

    end_msg_info = f"统计信息: {fofa_static}"
    telegram_notify = notify.pretty_telegram_notify("🎉🎉Fofa-Find-Proxy运行结束",
                                                    f"fofa-find-proxy fofa",
                                                    end_msg_info)
    telegram_notify = notify.clean_str_for_tg(telegram_notify)
    success = notify.send_telegram_message(telegram_notify)

    if success:
        print("Start fofa find message sent successfully!")
    else:
        print("Start fofa find message failed to send.")


if __name__ == '__main__':
    asyncio.run(main())
