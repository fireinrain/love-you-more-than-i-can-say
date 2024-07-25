import os

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
    parse_masscan_output("masscan_results/45.59.184.0-24_temp.txt","masscan_results/45.59.184.0-24_ip.txt")

if __name__ == '__main__':
    # refresh_markdown("ports_results")
    # test_env_injection()

    test_ip_file()