import concurrent.futures as futures
import datetime
import json
import random
import re
import urllib3
import aiohttp
import asyncio
import time
import socket

from aiohttp import ClientTimeout, TCPConnector
from redis_tool import r
import requests
import locations

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pool_executor = futures.ThreadPoolExecutor()


def random_sleep(max_sleep: int = 1):
    sleep_time = random.uniform(0, max_sleep)
    # 生成一个介于 0 和 1 之间的随机小数
    time.sleep(sleep_time)


def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        # Further check to ensure each segment is between 0 and 255
        segments = ip.split('.')
        if all(0 <= int(segment) <= 255 for segment in segments):
            return True
    return False


def get_ip_address(domain_str: str) -> str:
    try:
        # 获取IPv4地址
        ipv4 = socket.gethostbyname(domain_str)
        print(f"IPv4 address of {domain_str}: {ipv4}")
        return ipv4
    except socket.gaierror:
        print(f"Could not resolve {domain_str} to an IPv4 address")

    try:
        # 获取IPv6地址
        ipv6_info = socket.getaddrinfo(domain_str, None, socket.AF_INET6)
        ipv6_addresses = [info[4][0] for info in ipv6_info]
        # 去重
        ipv6_addresses = list(set(ipv6_addresses))
        for ipv6 in ipv6_addresses:
            print(f"IPv6 address of {domain_str}: {ipv6}")
        return ipv6_addresses[0]
    except socket.gaierror:
        print(f"Could not resolve {domain_str} to an IPv6 address")
    return ""


class IPChecker:
    @staticmethod
    def check_port_open(host: socket, port: str | int) -> bool:
        sock = None
        port = int(port)
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set timeout to 1 second
            sock.settimeout(2.5)
            # Connect to the host and port
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f">>> Port {port} is open on {host}")
                return True
            else:
                print(f">>> Port {port} is closed on {host}")

        except Exception as e:
            print(f"Error checking port: {e}")
        finally:
            sock.close()
        return False

    @staticmethod
    def check_port_open_with_retry(host: socket, port: str | int, retry: int = 1) -> bool:
        for i in range(retry):
            with_retry = IPChecker.check_port_open(host, port)
            if with_retry:
                return True
            random_sleep(15)
        return False

    @staticmethod
    def check_band_with_gfw_with_retry(host: str, port: str | int, check_count: int) -> bool:
        host = host.strip()
        if check_count <= 0:
            raise ValueError("min_pass must be smaller than check_count")
        for i in range(check_count):
            gfw = IPChecker.check_baned_with_gfw(host, port)
            if not gfw:
                return False
            time.sleep(15)
        # 使用v2接口再次检测一下
        ipv_ = is_valid_ipv4(host)
        if not ipv_:
            host = get_ip_address(host)
        is_ban = IPChecker.check_baned_with_gfw_v2(host, port)
        if not is_ban:
            return False
        return True

    # 检测ip端口是否被gfw ban
    @staticmethod
    def check_baned_with_gfw(host: str, port: str | int) -> bool:

        request_url = f"https://www.toolsdaquan.com/toolapi/public/ipchecking/{host}/{port}"
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh,en;q=0.9,zh-TW;q=0.8,zh-CN;q=0.7,ja;q=0.6",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": "https://www.toolsdaquan.com/ipcheck/",
            "Sec-Ch-Ua": "\"Google Chrome\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\"",
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "\"macOS\"",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "X-Requested-With": "XMLHttpRequest"
        }
        random_user_agent = IPChecker.get_random_user_agent()
        headers['User-Agent'] = random_user_agent

        try:
            resp = requests.get(request_url, headers=headers)
            resp.raise_for_status()

            response_data = resp.json()

            if response_data['icmp'] == "success" and response_data['tcp'] == "success":
                print(f">>> ip: {host}:{port} is ok in China!")
                return False
            else:
                print(f">>> ip: {host}:{port} is banned in China!")
                return True
        except Exception as e:
            print(">>> Error request for ban check:", e, "check_baned_with_gfw")
            return True

    @staticmethod
    def check_baned_with_gfw_v2(host: str, port: str | int) -> bool:
        import subprocess
        import json

        # 1716887992202
        timestamp_ = int(datetime.datetime.timestamp(datetime.datetime.now()) * 1000)
        data = {
            "idName": f"itemblockid{timestamp_}",
            "ip": f"{host}"
        }
        random_user_agent = IPChecker.get_random_user_agent()

        curl_command = [
            'curl', 'https://www.vps234.com/ipcheck/getdata/',
            '-H', 'Accept: */*',
            '-H', 'Accept-Language: zh,en;q=0.9,zh-TW;q=0.8,zh-CN;q=0.7,ja;q=0.6',
            '-H', 'Cache-Control: no-cache',
            '-H', 'Connection: keep-alive',
            '-H', 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
            '-H', 'Origin: https://www.vps234.com',
            '-H', 'Pragma: no-cache',
            '-H', 'Referer: https://www.vps234.com/ipchecker/',
            '-H', 'Sec-Fetch-Dest: empty',
            '-H', 'Sec-Fetch-Mode: cors',
            '-H', 'Sec-Fetch-Site: same-origin',
            '-H',
            f'User-Agent: {random_user_agent}',
            '-H', 'X-Requested-With: XMLHttpRequest',
            '-H', 'sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            '-H', 'sec-ch-ua-mobile: ?0',
            '-H', 'sec-ch-ua-platform: "macOS"',
            '--data-raw', f'idName={data["idName"]}&ip={data["ip"]}'
        ]

        try:
            # Execute the curl command
            result = subprocess.run(curl_command, capture_output=True, text=True)

            # Print the output
            # print(result.stdout)
            response_data = json.loads(str(result.stdout))

            if response_data['data']['data']['innerTCP'] == True and response_data['data']['data'][
                'outTCP'] == True:
                print(f">>> ip: {host}:{port} is ok in China!")
                return False
            else:
                print(f">>> ip: {host}:{port} is banned in China!")
                return True
        except Exception as e:
            print(">>> Error request for ban check:", e, "check_baned_with_gfw_v2")
            return True

    @staticmethod
    def get_random_user_agent() -> str:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
        ]

        return random.choice(user_agents)

    @staticmethod
    def detect_cloudflare_location(ip_addr: str, port: int | str, body: str, tcpDuration: str) -> dict | None:
        # {"ip": "60.246.230.77", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific",
        # "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "0 kB/s"}
        if 'uag=Mozilla/5.0' in body:
            matches = re.findall('colo=([A-Z]+)', body)
            if matches:
                dataCenter = matches[0]  # Get the first match
                loc = locations.CloudflareLocationMap.get(dataCenter)
                if loc:
                    print(f"发现有效IP {ip_addr} 端口 {port} 位置信息 {loc['city']} 延迟 {tcpDuration} 毫秒,速度未知")
                    # Append a dictionary to resultChan to simulate adding to a channel
                    return {
                        "ip": ip_addr,
                        "port": port,
                        "enable_tls": True,
                        "data_center": dataCenter,
                        "region": loc['region'],
                        "city": loc['city'],
                        "latency": f"{tcpDuration} ms",

                    }
                print(f"发现有效IP {ip_addr} 端口 {port} 位置信息未知 延迟 {tcpDuration} 毫秒,速度未知")
                # Append a dictionary with some empty fields to resultChan
                return {
                    "ip": ip_addr,
                    "port": port,
                    "enable_tls": True,
                    "data_center": dataCenter,
                    "region": "",
                    "city": "",
                    "latency": f"{tcpDuration} ms",
                }

        return None


class CustomResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{
            'hostname': host,
            'host': self.ip,
            'port': self.port,
            'family': family,
            'proto': 0,
            'flags': 0,
        }]

    async def close(self):
        pass


async def cf_speed_download(ip: str, port: int) -> (float, {}):
    url_string = f"https://speed.cloudflare.com/__down?bytes={1024 * 1024 * 1024}"
    trace_url = f"https://speed.cloudflare.com/cdn-cgi/trace"
    timeout = ClientTimeout(total=60)

    resolver = CustomResolver(ip, port)
    connector = TCPConnector(resolver=resolver)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        try:
            async with session.get(url_string) as response:
                data_len = 0
                start_time = time.monotonic()
                while True:
                    chunk = await response.content.read(1024)
                    if not chunk:
                        break
                    elapsed_time = time.monotonic() - start_time
                    if elapsed_time <= 5:
                        data_len += len(chunk)
                    else:
                        data_len += len(chunk)
                        break
                # print("data_len: ", data_len)
                # print("elapsed_time: ", elapsed_time)
                if elapsed_time - 5.0 < 0:
                    download_speed = 0.0
                else:
                    download_speed = data_len / elapsed_time

            headers = {
                'Host': 'speed.cloudflare.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36'
            }
            start_time = time.time()
            async with session.get(trace_url, headers=headers) as response:
                resp_text = await response.text()
                total_duration = f'{(time.time() - start_time) * 1000:.2f}'

                location = IPChecker.detect_cloudflare_location(ip, port, resp_text, str(total_duration))
                location['download_speed'] = f"{(download_speed / 1024.0):.2f} kB/s"

            return download_speed, location
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0.0, ""


async def check_if_cf_proxy(ip: str, port: int) -> (bool, {}):
    url = f"http://{ip}:{port}/cdn-cgi/trace"

    host = url.replace("http://", "").replace("/cdn-cgi/trace", "")
    headers = {
        "User-Agent": "curl/7.64.1",
        "Host": host,
    }
    timeout = aiohttp.ClientTimeout(total=3.5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get(url, headers=headers, allow_redirects=False, ssl=False) as response:
                text = await response.text()
                # print(response_text_)
            if (
                    "400 The plain HTTP request was sent to HTTPS port" in text and "cloudflare" in text) or "visit_scheme=http" in text:
                speed, location = await cf_speed_download(ip, port)
                if speed - 0.1 > 0:
                    return True, location
        except Exception as e:
            print(f"Request Error: {e}")
    return False, {}


def clean_dead_ip():
    keys = r.hkeys('snifferx-result')
    dont_need_dc = ['North America', 'Europe']
    # For each key, get the value and store in Cloudflare KV
    for key in keys:
        value = r.hget('snifferx-result', key)

        # Prepare the data for Cloudflare KV
        # kv_key = key.decode('utf-8')
        kv_value = json.loads(value.decode('utf-8'))

        ip = kv_value['ip']
        port = kv_value['port']
        tls = kv_value['enable_tls']
        datacenter = kv_value['data_center']
        region = kv_value['region']

        if region in dont_need_dc and '906' not in str(key):
            # delete ip
            r.hdel('snifferx-result', key)
            print(f"已删除: {key} {kv_value}")
        port_open = IPChecker.check_port_open_with_retry(ip, port, 10)
        if not port_open:
            print(f">>> 当前优选IP端口已失效: {ip}:{port},进行移除...")
            r.hdel('snifferx-result', key)

        # 判断当前是否为周日 如果是 则进行gfw ban检测
        today = datetime.datetime.today()
        is_sunday = today.weekday() == 6

        if is_sunday:
            baned_with_gfw = IPChecker.check_band_with_gfw_with_retry(ip, port, 3)
            print(f"Proxy id: {ip}:{port} gfwban status: {baned_with_gfw}")

            time.sleep(5)
            if baned_with_gfw:
                print(f">>> 当前优选IP端口已被墙: {ip}:{port},进行移除...")
                r.hdel('snifferx-result', key)


async def main():
    # ips = ['https://8.222.134.170:2096', 'https://47.236.117.48:2096', 'http://154.219.5.235:2095',
    #        'http://154.219.5.248:2095', 'http://154.219.5.199:2095', 'http://154.219.5.190:2095',
    #        'http://154.219.5.222:2095', 'http://47.236.144.48:2095', 'https://8.219.158.157', 'https://www.bb999.app',
    #        'http://www.bb999.app', 'https://bb999.app', 'https://8.219.210.171:2087', 'http://8.219.87.30:2095',
    #        'http://8.219.124.227:2095', 'http://154.219.5.135:2095', 'http://154.219.5.63:2095',
    #        'http://154.219.5.184:2095', 'http://154.219.5.252:2095', 'http://154.219.5.108:2095']
    #
    # for i in ips:
    #     ip_str = i.split("//")[1]
    #     ip = None
    #     port = None
    #     if ":" in ip_str:
    #         ip = ip_str.split(":")[0]
    #         port = ip_str.split(":")[1]
    #     else:
    #         ip = ip_str
    #         port = '443'
    #     cloudflare_proxy = await check_if_cf_proxy(ip, port)
    #     print(f"ip: {ip},port:{port}, cf-proxy:{cloudflare_proxy}")
    #     time.sleep(1)

    c2 = await check_if_cf_proxy('27.50.48.117', 8880)
    print(f"cloudflare_proxy: {c2}")


if __name__ == '__main__':
    # clean_dead_ip()

    asyncio.run(main())
