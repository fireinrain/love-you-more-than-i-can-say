import json
import os
import time

import requests

ASN_Map = {
    "932": "AS932 XNNET LLC,16128",
    "15169": "AS15169 Google LLC,9134336",
    "17858": "AS17858 LG POWERCOMM,10301440",
    "45102": "AS45102 Alibaba (US) Technology Co.Ltd.,3347200",
    "135377": "AS135377 UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED,158976",
    "19527": "AS19527 Google LLC,1952768",
    "2497": "AS2497 Internet Initiative Japan Inc,3928576",
    "31898": "AS31898 Oracle Corporation,3044608",
    "3462": "AS3462 Data Communication Business Group HINET,12237056",
    "396982": "AS396982 Google LLC GOOGLE-CLOUD-PLATFORM,14720256",
    "4609": "AS4609 Companhia de Telecomunicacoes de Macau SARL CTM-MO,265216",
    "4760": "AS4760 HKT Limited,1831936",
    "8075": "AS8075 Microsoft Corporation,58105088",
    "906": "AS906 DMIT Cloud Services,30208",
    "9312": "AS9312 xTom,20224",
    "9689": "AS9689 SK Broadband Co Ltd,291840",
    "4785": "AS4785 xTom,13568",
    "2914": "AS2914 NTT America Inc,7000832",
    "3258": "AS3258 xTom Japan,22016",
    "4713": "AS4713 NTT Communications Corporation Japan,28692736",
    "16625": "AS16625 Akamai Technologies,5514240",
    "21859": "AS21859 Zenlayer Inc,649728"
}
# 每天运行2个，凌晨一个 中午一个
Wanted_ASN = ['906', '4760', '31898', '135377', '3462', '4609', '4760',
              '9312', '4785', '3258', '21859', '4809', '45102', '132203']

CountryASN = {
    'HK': ['4515', '9269', '4760', '9304', '10103', '17444', '9381', '135377'],
    'MO': ['4609', '7582', '64061', '133613'],
    'SG': ['45102', '139070', '139190'],
    'TW': ['4609'],
    'KR': ['31898'],
    'JP': ['2497'],
    'US': ['906']
}


def get_cidr_ips(asn):
    # 确保 asn 目录存在
    asn_dir = "asn"
    os.makedirs(asn_dir, exist_ok=True)

    file_path = os.path.join(asn_dir, f"{asn}")

    # 检查是否存在对应的 ASN 文件
    if os.path.exists(file_path):
        # 如果文件存在，读取文件内容
        with open(file_path, 'r') as file:
            cidrs = json.load(file)
        print(f"CIDR data for ASN {asn} loaded from file.")
    else:
        # 如果文件不存在，请求 API 数据
        url = f'https://api.bgpview.io/asn/{asn}/prefixes'
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Cookie": "cf_clearance=QGTGcYnHuiA.9rho9oE4t8qMiyEOZbTbSISclJRmL2A-1720255983-1.0.1.1-Mf0yAeogUfsanJBjw3qpZKalVLAfsN8AyPnjlQDzT0PvEFBOO7Ypp9NyQ4WCWHIAaeCAYaqpVE_Aa6z3s8AIpA; _ga=GA1.2.16443840.1721715301; _gid=GA1.2.1729940749.1721936545; _ga_7YFHLCZHVM=GS1.2.1721936545.5.1.1721937177.55.0.0"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        cidrs = [prefix['prefix'] for prefix in data['data']['ipv4_prefixes']]

        # 将数据写入文件
        with open(file_path, 'w') as file:
            json.dump(cidrs, file)
        print(f"CIDR data for ASN {asn} fetched from API and saved to file.")

    return cidrs


if __name__ == '__main__':
    for asn in Wanted_ASN:
        get_cidr_ips(asn)
        time.sleep(2)
    # get_cidr_ips("21859")
