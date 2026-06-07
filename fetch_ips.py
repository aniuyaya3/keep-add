import os
import re
import requests

URL = "https://api.nmm.us.ci/edgetunnel/KR-MY-JP-TW?limit=10"
OUTPUT_DIR = "ips"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 中文国家/地区映射表
COUNTRY_MAP = {
    "韩国": "KR",
    "马来西亚": "MY",
    "台湾": "TW",
    "日本": "JP"
}

def extract_ips():
    try:
        response = requests.get(URL, timeout=15)
        response.raise_for_status()
        raw_text = response.text.strip()
        
        if not raw_text:
            print("❌ API 返回内容为空！")
            return

        lines = raw_text.splitlines()
        country_ips = {}

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # 匹配你的数据格式: 129.154.50.159:443#🇰🇷 韩国 129.154.50.159:443
            # 提取最前面的 IP 和 端口，以及 # 后面的中文国家名
            match = re.search(r"^([\d.]+):(\d+)#.*?\s+([\u4e00-\u9fa5]+)", line)
            
            if match:
                ip = match.group(1)
                port = match.group(2)
                country_name = match.group(3) # 提取出 "韩国", "马来西亚", "台湾"

                # 严格筛选 443 端口
                if port == "443":
                    # 将中文转换为你要求的英文缩写作为文件名，找不到就用原中文
                    country_code = COUNTRY_MAP.get(country_name, country_name)
                    
                    if country_code not in country_ips:
                        country_ips[country_code] = []
                    country_ips[country_code].append(ip)

        # 写入文件
        if not country_ips:
            print("⚠️ 未在此数据中筛选出任何 443 端口的有效 IP。")
            return

        for country, ips in country_ips.items():
            # 去重并排序
            unique_ips = sorted(list(set(ips)))
            file_path = os.path.join(OUTPUT_DIR, f"{country}.txt")
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(unique_ips) + "\n")
            print(f"✅ 成功创建并写入: {file_path} (共 {len(unique_ips)} 个 443 IP)")

    except Exception as e:
        print(f"❌ 运行异常: {e}")

if __name__ == "__main__":
    extract_ips()
