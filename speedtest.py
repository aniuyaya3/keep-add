import os
import re
import socket
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
SUBSCRIBE_URL = "https://api.nmm.us.ci/edgetunnel/HK"
TEST_URL = "https://speed.cloudflare.com/__down?bytes=5000000" # 5MB 测速文件
MAX_THREADS = 20 # 并发线程数
TOP_COUNT = 5 # 筛选前 5 名

def fetch_ips(url):
    """抓取链接并使用正则表达式提取所有 IPv4 地址"""
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        # 匹配标准的 IPv4 正则
        ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', response.text)
        # 去重
        return list(set(ips))
    except Exception as e:
        print(f"提取 IP 失败: {e}")
        return []

def test_ip(ip):
    """测试单个 IP 的 443 端口延迟与下载速度"""
    port = 443
    # 1. 测试 TCP 延迟
    delay = 9999.0
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0) # 2秒超时
        sock.connect((ip, port))
        delay = (time.time() - start_time) * 1000 # 转为毫秒
        sock.close()
    except Exception:
        # 端口不通直接返回失败
        return {"ip": ip, "delay": 9999.0, "speed": 0.0, "valid": False}

    # 2. 测试下载速度 (只有延迟达标的才测速，节省资源)
    speed = 0.0
    try:
        # 修改 hosts，强制将测速域名的 IP 解析为当前测试的 IP
        session = requests.Session()
        # 提取域名用于 Host 头
        host_header = "speed.cloudflare.com"
        url = TEST_URL.replace("speed.cloudflare.com", ip)
        
        start_download = time.time()
        # 限制 3 秒内能下载多少数据
        res = session.get(url, headers={"Host": host_header}, timeout=3.0, stream=True)
        
        size = 0
        for chunk in res.iter_content(chunk_size=1024 * 64):
            if time.time() - start_download > 3.0: # 最多测速3秒
                break
            if chunk:
                size += len(chunk)
                
        duration = time.time() - start_download
        if duration > 0 and size > 0:
            speed = (size / 1024 / 1024) / duration # MB/s
    except Exception:
        speed = 0.0

    return {"ip": ip, "delay": delay, "speed": speed, "valid": speed > 0}

def main():
    print("正在获取 IP 列表...")
    raw_ips = fetch_ips(SUBSCRIBE_URL)
    print(f"成功获取到 {len(raw_ips)} 个独立 IP，开始进行 443 端口并发测试...")

    results = []
    # 使用线程池并发测试
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(test_ip, ip): ip for ip in raw_ips}
        for future in as_completed(futures):
            res = future.result()
            if res["valid"]:
                results.append(res)
                print(f"IP: {res['ip']} | 延迟: {res['delay']:.1f}ms | 速度: {res['speed']:.2f} MB/s")

    if not results:
        print("未检测到任何可用的 443 端口优选 IP。")
        return

    # 综合排序算法：优先按速度降序，如果速度接近则按延迟升序
    # 这里采用标准：速度越大越好（负号代表降序），延迟越小越好
    results.sort(key=lambda x: (-x["speed"], x["delay"]))

    # 挑选前 5 个
    top_5 = results[:TOP_COUNT]

    print("\n===== 筛选出的最优 5 个 IP =====")
    with open("ip.txt", "w") as f:
        for idx, item in enumerate(top_5, 1):
            log_line = f"{item['ip']} (延迟: {item['delay']:.1f}ms, 速度: {item['speed']:.2f} MB/s)"
            print(f"{idx}. {log_line}")
            # 只写入 IP 到 ip.txt
            f.write(f"{item['ip']}\n")
            
    print("\n结果已写入 ip.txt")

if __name__ == "__main__":
    main()
