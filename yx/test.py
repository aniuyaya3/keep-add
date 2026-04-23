#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import socket
import requests

# =========================
# 配置
# =========================
IP_URL = "https://raw.githubusercontent.com/xinyitang3/rules/refs/heads/main/ip.txt"

TOP_N = 2
PORT = 443
TIMEOUT = 3
RETRY = 2

# =========================
# 路径（绝对路径）
# =========================


BASE_DIR = os.getcwd()     # 当前仓库根目录
OUTPUT_DIR = os.path.join(BASE_DIR, "yx")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "mobile_best.txt")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# =========================
# 获取 IP 列表
# =========================
def get_ip_list():
    print("获取 IP 列表...")

    r = requests.get(IP_URL, timeout=20)
    r.raise_for_status()

    ips = []

    for line in r.text.splitlines():
        line = line.strip()

        if not line:
            continue

        # 只提取 IP
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            ips.append(m.group(1))

    # 去重
    return list(dict.fromkeys(ips))


# =========================
# TCP 延迟测试
# =========================
def ping(ip):
    values = []

    for _ in range(RETRY):
        try:
            start = time.time()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((ip, PORT))
            sock.close()

            delay = int((time.time() - start) * 1000)

            if delay > 0:
                values.append(delay)

        except:
            pass

    if values:
        return min(values)

    return 9999


# =========================
# 主程序
# =========================
def main():
    ips = get_ip_list()

    results = []

    for ip in ips:
        delay = ping(ip)

        if delay != 9999:
            print(f"{ip} -> {delay}ms")
            results.append((ip, delay))
        else:
            print(f"{ip} -> timeout")

    results.sort(key=lambda x: x[1])

    best = results[:TOP_N]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for ip, delay in best:
            f.write(f"{ip} {delay}ms\n")

    print("\nTOP2：")
    for ip, delay in best:
        print(f"{ip} {delay}ms")

    print(f"\n已保存：{OUTPUT_FILE}")


if __name__ == "__main__":
    main()
