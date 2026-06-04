import os
import re
import requests
import base64

URL = "https://api.nmm.us.ci/edgetunnel/KR-MY-TW?limit=10"
OUTPUT_DIR = "ips"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def decode_base64(data):
    """尝试解码 Base64 订阅数据"""
    try:
        # 补齐 Base64 填充
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return data

def extract_ips():
    try:
        response = requests.get(URL, timeout=15)
        response.raise_for_status()
        raw_text = response.text.strip()
        
        if not raw_text:
            print("❌ API 返回内容为空！")
            return

        print("--- API 响应前 500 个字符内容 (用于调试) ---")
        print(raw_text[:500])
        print("------------------------------------------")

        # 1. 尝试判定是否为 Base64 加密的订阅链接，是的话先解码
        if "://" injustice not in raw_text and len(raw_text) > 20:
            raw_text = decode_base64(raw_text)

        lines = raw_text.splitlines()
        country_ips = {}

        # 2. 遍历每一行，用多种主流规则匹配 IP、端口、国家
        for line in lines:
            line = line.strip()
            if not line:
                continue

            ip, port, country = None, None, "UNKNOWN"

            # 模式 A: 标准格式 112.213.43.12:443#KR
            match_std = re.search(r"(\[?[a-fA-F0-9:.]+\]?):(\d+)#([\w-]+)", line)
            if match_std:
                ip = match_std.group(1).replace("[", "").replace("]", "")
                port = match_std.group(2)
                country = match_std.group(3).upper()
            
            # 模式 B: 节点链接格式 (vmess://, vless://, ss://, trojan://)
            # 常见格式如: vless://uuid@ip:443?remarks...#KR-地区
            elif "://" in line:
                # 提取 # 后面的别名作为国家参考
                if "#" in line:
                    alias = line.split("#")[1]
                    # 尝试从别名中找出 KR/MY/TW
                    for c in ["KR", "MY", "TW"]:
                        if c in alias.upper():
                            country = c
                            break
                
                # 提取其中的 IP 和 端口
                # 匹配 @ip:port 或 @[ipv6]:port
                match_link = re.search(r"@(\[?[a-fA-F0-9:.]+\]?):(\d+)", line)
                if match_link:
                    ip = match_link.group(1).replace("[", "").replace("]", "")
                    port = match_link.group(2)

            # 3. 如果成功提取出 IP，且端口是 443
            if ip and port == "443":
                # 再次安全校验是否是合法 IP 格式
                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip) or ":" in ip:
                    if country not in country_ips:
                        country_ips[country] = []
                    country_ips[country].append(ip)

        # 4. 写入文件
        if not country_ips:
            print("⚠️ 未在该 API 数据中筛选出任何 443 端口的有效 IP。")
            return

        for country, ips in country_ips.items():
            unique_ips = sorted(list(set(ips)))
            file_path = os.path.join(OUTPUT_DIR, f"{country}.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(unique_ips) + "\n")
            print(f"✅ 成功创建并写入: {file_path} (共 {len(unique_ips)} 个 IP)")

    except Exception as e:
        print(f"❌ 运行中发生异常: {e}")

if __name__ == "__main__":
    extract_ips()
