import os
from datetime import datetime

import redis


def test_env_injection():
    redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    redis_pass = os.getenv("REDIS_PASS", "mypass")

    print("Environment injection")
    print(redis_host)
    print(redis_port)
    print(redis_pass)

    # 初始化 Redis 连接
    r = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_pass,
        db=0,
        ssl=False
    )
    ping = r.ping()
    print(f"Resp from redis: {ping}")


def test_ip_file():
    from main import parse_masscan_output
    parse_masscan_output("masscan_results/45.59.184.0-24_temp.txt", "masscan_results/45.59.184.0-24_ip.txt")


def get_current_weekday_plus():
    now = datetime.now()
    current_time = now.time()
    current_day = now.weekday()  # Monday is 0, Sunday is 6

    # Define time ranges
    morning_start = datetime.strptime("01:00", "%H:%M").time()
    morning_end = datetime.strptime("11:00", "%H:%M").time()
    afternoon_start = datetime.strptime("12:00", "%H:%M").time()
    afternoon_end = datetime.strptime("23:00", "%H:%M").time()

    # Check each day and time range
    for day in range(7):  # 0 to 6, representing Monday to Sunday
        if current_day == day:
            if morning_start <= current_time < morning_end:
                return day * 2
            elif afternoon_start <= current_time < afternoon_end:
                return day * 2 + 1

    # If not in any specified range, return -1 or handle as needed
    return 0


import unittest
from unittest.mock import patch
import pytz

# class TestGetCurrentWeekdayPlus(unittest.TestCase):
#     @patch('datetime.datetime')
#     def test_monday_morning(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 24, 8, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 0)
#
#     @patch('datetime.datetime')
#     def test_monday_afternoon(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 24, 13, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 1)
#
#     @patch('datetime.datetime')
#     def test_sunday_morning(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 30, 9, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 12)
#
#     @patch('datetime.datetime')
#     def test_sunday_afternoon(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 30, 15, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 13)
#
#     @patch('datetime.datetime')
#     def test_edge_case_morning(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 25, 11, 59).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 2)
#
#     @patch('datetime.datetime')
#     def test_edge_case_afternoon(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 25, 12, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 3)
#
#     @patch('datetime.datetime')
#     def test_midnight(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 26, 0, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 0)  # Assuming it falls outside the defined ranges
#

import requests
import socket


def new_check_cf_proxy(ip: str, port: int | str) -> str | bool:
    """
    向给定IP和端口发送GET请求，返回特定响应或超时指示。

    参数:
    ip: 表示IP地址的字符串。
    port: 表示端口号的整数。

    返回:
    表示结果的字符串（'https_error' 或 'timeout'）。
    """
    url = f"https://{ip}:{port}/cdn-cgi/trace"
    try:
        # 禁用重定向，并设置超时为 1.5 秒
        response = requests.get(url, timeout=3, allow_redirects=False, verify=False)
        if (
                "400 The plain HTTP request was sent to HTTPS port" in response.text and "cloudflare" in response.text) or "visit_scheme=http" in response.text:
            return True

        # if response.status_code == 403 and '403 Forbidden' in response.text:
        #     return True
    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.RequestException:
        return False
    return False


if __name__ == '__main__':
    # refresh_markdown("ports_results")
    # test_env_injection()

    # test_ip_file()

    # print(get_current_weekday_plus())
    # unittest.main()

    # proxy_ip = "47.56.196.176"
    # proxy_port = "9443"
    proxy_ip = '154.17.22.207'
    proxy_port = '443'

    result = new_check_cf_proxy(proxy_ip, proxy_port)
    if result:
        print("The proxy appears to be valid for speed.cloudflare.com")
    else:
        print("The proxy does not appear to be valid for speed.cloudflare.com")
