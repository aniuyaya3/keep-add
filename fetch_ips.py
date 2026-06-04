import os
import re
import requests

# 目标 URL
URL = "https://api.nmm.us.ci/edgetunnel/KR-MY-TW?limit=10"
# 创建存储结果的目录
OUTPUT_DIR = "ips"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def fetch_and_process():
    try:
        response = requests.get(URL, timeout=15)
        response.raise_for_status()
        lines = response.text.splitlines()

        # 用于存储按国家分类的 IP 列表
        # 格式: { 'KR': ['1.1.1.1', '2.2.2.2'], 'MY': [...] }
        country_ips = {}

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # 正则匹配标准格式: IP:端口#国家 (支持 IPv4 和 IPv6)
            # 例如: 112.213.43.12:443#KR 或者 [2001:db8::1]:443#TW
            match = re.match(r"^(\[?[a-fA-F0-9:.]+\]?):(\d+)#([\w-]+)", line)
            if match:
                ip = match.group(1).replace("[", "").replace("]", "")
                port = match.group(2)
                country = match.group(3).upper()  # 统一转大写

                # 严格筛选 443 端口
                if port == "443":
                    if country not in country_ips:
                        country_ips[country] = []
                    country_ips[country].append(ip)

        # 写入单独的 txt 文件
        for country, ips in country_ips.items():
            # 去重保持唯一性
            unique_ips = list(set(ips))
            file_path = os.path.join(OUTPUT_DIR, f"{country}.txt")

            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(unique_ips) + "\n")

            print(
                f"成功写入 {country}.txt，共 {len(unique_ips)} 个 443 端口 IP"
            )

    except Exception as e:
        print(f"运行出错: {e}")


if __name__ == "__main__":
    fetch_and_process()
