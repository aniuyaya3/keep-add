import requests
import re

# Raw JSON 文件地址
URL = "https://raw.githubusercontent.com/vipmc838/cf_best_ip/refs/heads/main/cloudflare_bestip.json"

def parse_bandwidth(bw_str: str) -> float:
    """
    将带宽字符串转换成数字（仅 Mbps）
    示例："504.16mb" -> 504.16
    """
    # 可能存在大写/小写，以及末尾 mb/mB
    match = re.search(r"([\d.]+)", bw_str)
    return float(match.group(1)) if match else 0.0

def get_top5(entries: list) -> list:
    """
    entries: 列表元素为 {"IP": "...", "带宽": "...", ...}
    返回按照带宽排序后的前 5
    """
    # 过滤掉没有带宽的项
    sorted_entries = sorted(entries, key=lambda x: parse_bandwidth(x.get("带宽", "0")), reverse=True)
    return sorted_entries[:5]

def main():
    # 请求 JSON 数据
    response = requests.get(URL)
    response.raise_for_status()
    data = response.json()

    # 获取完整数据
    full = data.get("完整数据", {})

    # 获取联通 和 移动
    unicom = full.get("联通", [])
    mobile = full.get("移动", [])

    # 排序并取 top 5
    top5_unicom = get_top5(unicom)
    top5_mobile = get_top5(mobile)

    # 写入联通 txt
    with open("outputs/unicom_top5.txt", "w", encoding="utf-8") as f:
        for item in top5_unicom:
            f.write(f"{item['IP']} {item['带宽']}\n")

    # 写入移动 txt
    with open("outputs/mobile_top5.txt", "w", encoding="utf-8") as f:
        for item in top5_mobile:
            f.write(f"{item['IP']} {item['带宽']}\n")

    print("已生成 outputs/unicom_top5.txt 和 outputs/mobile_top5.txt")

if __name__ == "__main__":
    main()
