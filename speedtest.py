import os
import re
import socket
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
SUBSCRIBE_URL = "https://api.nmm.us.ci/edgetunnel/HK"
MAX_THREADS = 50 # 提高并发线程数，加快测试速度
TOP_COUNT = 5 

def fetch_ips(url):
    """抓取链接并提取所有 IPv4 地址"""
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        text = response.text
        
        # 匹配标准的 IPv4 正则
        ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', text)
        return list(set(ips))
    except Exception as e:
        print(f"提取 IP 失败: {e}")
        return []

def test_ip_latency(ip):
    """仅仅测试 443 端口的 TCP 握手延迟"""
    port = 443
    # 尝试连接 3 次取平均值，结果更准确
    test_count = 3
    delays = []
    
    for _ in range(test_count):
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5) # 1.5秒超时
            sock.connect((ip, port))
            delay = (time.time() - start_time) * 1000 # 转为毫秒
            delays.append(delay)
            sock.close()
            time.sleep(0.05) # 微小停顿
        except Exception:
            # 只要有一次不通，或者超时，就视为无效
            return {"ip": ip, "delay": 9999.0, "valid": False}
            
    # 取平均延迟
    avg_delay = sum(delays) / len(delays)
    return {"ip": ip, "delay": avg_delay, "valid": True}

def main():
    # 兜底操作：先确保当前目录下有一个空的 ip.txt
    with open("ip.txt", "a") as f:
        pass

    print("正在获取 IP 列表...")
    raw_ips = fetch_ips(SUBSCRIBE_URL)
    
    if not raw_ips:
        print("警告：未能从该链接提取到任何 IP 地址！")
        return

    print(f"成功获取到 {len(raw_ips)} 个独立 IP，开始进行 443 端口并发延迟测试...")

    results = []
    # 使用线程池并发测试 TCP 延迟
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(test_ip_latency, ip): ip for ip in raw_ips}
        for future in as_completed(futures):
            res = future.result()
            if res["valid"]:
                results.append(res)
                print(f"IP: {res['ip']} | 443端口延迟: {res['delay']:.1f}ms")

    if not results:
        print("【错误】所有 IP 的 443 端口在 GitHub 环境下均无法连通！")
        print("这通常是因为这些 IP 开启了严格的防火墙，或者 GitHub 节点的出海路由无法直接连接它们。")
        return

    # 排序：按延迟升序排列（越小越快）
    results.sort(key=lambda x: x["delay"])
    top_5 = results[:TOP_COUNT]

    print("\n===== 筛选出延迟最低的 5 个 IP =====")
    with open("ip.txt", "w") as f:
        for idx, item in enumerate(top_5, 1):
            log_line = f"{item['ip']} (延迟: {item['delay']:.1f}ms)"
            print(f"{idx}. {log_line}")
            f.write(f"{item['ip']}\n")
            
    print("\n结果已成功覆盖写入 ip.txt")

if __name__ == "__main__":
    main()
