import asyncio

import checker


async def test_check_list():
    ips = ['https://46.3.105.217:10049', 'http://www.kerangwincare.art', 'https://www.kerangwincare.art',
           'http://kerangwincare.art', 'https://kerangwincare.art', 'https://www.kerangwinfest.vip',
           'http://www.kerangwinfest.vip', 'https://kerangwinfest.vip', 'http://kerangwinfest.vip',
           'https://61.93.47.11:50000', 'https://103.229.54.151:9527', 'https://203.184.131.22:20000',
           'https://46.3.105.217:10043', 'https://46.3.105.217:10040', 'https://46.3.105.217:10036',
           'https://47.76.62.62:8443', 'https://46.3.105.217:10034', 'https://46.3.105.217:10033',
           'https://47.76.252.161:10002', 'https://149.104.24.14:2096', 'https://203.184.131.22:20000',
           'https://46.3.105.217:10043', 'https://46.3.105.217:10040', 'https://46.3.105.217:10036',
           'https://47.76.62.62:8443', 'https://46.3.105.217:10034', 'https://46.3.105.217:10033',
           'https://47.76.252.161:10002', 'https://149.104.24.14:2096', 'https://149.104.29.178',
           'https://47.76.94.15:8443', 'https://210.0.158.18:20000', 'https://46.3.105.217:10029',
           'https://46.3.106.170:10029', 'https://46.3.105.217:10028', 'https://46.3.106.170:10028',
           'https://8.217.49.34:2087', 'https://8.218.3.12:2087', 'https://47.76.37.57:2096',
           'https://46.3.106.170:10027']

    for i in ips:
        ip_str = i.split("//")[1]
        ip = None
        port = None
        if ":" in ip_str:
            ip = ip_str.split(":")[0]
            port = ip_str.split(":")[1]
        else:
            ip = ip_str
            port = '443'
        cloudflare_proxy = await checker.check_if_cf_proxy(ip, port)
        print(f"ip: {ip},port:{port}, cf-proxy:{cloudflare_proxy}")
        await asyncio.sleep(1)


async def test_check_one():
    c2 = await checker.check_if_cf_proxy('132.226.22.3', 9999)
    print(f"cloudflare_proxy: {c2}")


async def main():
    # await test_check_list()
    await test_check_one()


if __name__ == '__main__':
    asyncio.run(main())
    # a = ('abc',12)
    # b = ('abc',12)
    # aa = set()
    # aa.add(a)
    # aa.add(b)
    # if a in aa:
    #     print(f"cloud")
    # print(len(aa))
