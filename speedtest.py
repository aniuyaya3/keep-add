import os
import re
import socket
import time
import base64
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
SUBSCRIBE_URL = "https://api.nmm.us.ci/edgetunnel/HK"
TEST_URL = "https://speed.cloudflare.com/__down?bytes=5000000" # 5MB 测速文件
MAX_THREADS = 20 
TOP_COUNT = 5 

def fetch_ips(url):
    """抓取链接，支持自动 Base64 解码，并提取所有 IPv4 地址"""
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        text = response.text.strip()
        
        # 尝试检测是否为 Base64 加密（节点订阅常见格式）
        try:
            # 补齐 Base64 填充
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)
            decoded_text = base64.b64decode(text).decode('utf-8', errors='ignore')
            print("检测到 Base64 加密，已成功解密。")
            text = decoded_text
        except Exception:
            print("数据未加密，直接解析纯文本。")

        # 匹配标准的 IPv4 正则
        ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', text)
        return list(set(ips))
    except Exception as e:
        print(f"提取 IP 失败: {e}")
        return []

def test_ip(ip):
    """测试单个 IP 的 443 端口延迟与下载速度"""
    port = 443
    delay = 9999.0
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        delay = (time.time() - start_time) * 1000
        sock.close()
    except Exception:
        return {"ip": ip, "delay": 9999.0, "speed": 0.0, "valid": False}

    speed = 0.0
    try:
        session = requests.Session()
        host_header = "speed.cloudflare.com"
        url = TEST_URL.replace("speed.cloudflare.com", ip)
        
        start_download = time.time()
        res = session.get(url, headers={"Host": host_header}, timeout=3.0, stream=True)
        
        size = 0
        for chunk in res.iter_content(chunk_size=1024 * 64):
            if time.time() - start_download > 3.0:
                break
            if chunk:
                size += len(chunk)
                
        duration = time.time() - start_download
        if duration > 0 and size > 0:
            speed = (size / 1024 / 1024) / duration
    except Exception:
        speed = 0.0

    return {"ip": ip, "delay": delay, "speed": speed, "valid": speed > 0}

def main():
    # 兜底操作：先确保当前目录下有一个空的 ip.txt，防止后续 Git 找不到文件报错
    with open("ip.txt", "a") as f:
        pass

    print("正在获取 IP 列表...")
    raw_ips = fetch_ips(SUBSCRIBE_URL)
    
    if not raw_ips:
        print("警告：未能从该链接提取到任何 IP 地址！")
        return

    print(f"成功获取到 {len(raw_ips)} 个独立 IP，开始进行 443 端口并发测试...")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(test_ip, ip): ip for ip in raw_ips}
        for future in as_completed(futures):
            res = future.result()
            if res["valid"]:
                results.append(res)
                print(f"IP: {res['ip']} | 延迟: {res['delay']:.1f}ms | 速度: {res['speed']:.2f} MB/s")

    if not results:
        print("未检测到任何可用的 443 端口优选 IP，ip.txt 将保持为空。")
        return

    # 排序：速度降序，延迟升序
    results.sort(key=lambda x: (-x["speed"], x["delay"]))
    top_5 = results[:TOP_COUNT]

    print("\n===== 筛选出的最优 5 个 IP =====")
    with open("ip.txt", "w") as f:
        for idx, item in enumerate(top_5, 1):
            log_line = f"{item['ip']} (延迟: {item['delay']:.1f}ms, 速度: {item['speed']:.2f} MB/s)"
            print(f"{idx}. {log_line}")
            f.write(f"{item['ip']}\n")
            
    print("\n结果已成功覆盖写入 ip.txt")

if __name__ == "__main__":
    main()
