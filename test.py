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

if __name__ == '__main__':
    # refresh_markdown("ports_results")
    # test_env_injection()

    # test_ip_file()

    print(get_current_weekday_plus())