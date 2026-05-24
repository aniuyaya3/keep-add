#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.request
import re

def filter_hk_pure_ips():
    url = "https://raw.githubusercontent.com/HandsomeMJZ/cfip/refs/heads/main/best_ips.txt"
    output_file = "ip.txt"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    print("正在下载并解析纯 HK IP...")
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8')
            
        lines = content.splitlines()
        hk_ips = []
        
        # 同时匹配 IPv4 和 IPv6 的正则表达式
        # 匹配原则：提取每行开头直到冒号(端口前)或空格前的纯 IP 部分
        ip_pattern = re.compile(r'^([0-9a-fA-F\.:]+)')

        for line in lines:
            line = line.strip()
            # 仅处理包含 hk 的行
            if 'hk' in line.lower():
                # 移除可能存在的端口号和标签（例如 1.1.1.1:443#HK -> 1.1.1.1）
                # 或者是 [2606:4700::1]:443#HK -> 2606:4700::1
                match = ip_pattern.match(line)
                if match:
                    pure_ip = match.group(1)
                    # 清洗掉 IPv6 两端的方括号 [ ] 和末尾可能残留的冒号
                    pure_ip = pure_ip.replace('[', '').replace(']', '').rstrip(':')
                    hk_ips.append(pure_ip)
        
        # 自动去重并保持排序
        hk_ips = sorted(list(set(hk_ips)))
                
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(hk_ips))
            
        print(f" 成功！已提取出 {len(hk_ips)} 个纯 HK IP（已去重、去端口），保存至 {output_file}")
        
    except Exception as e:
        print(f" 发生错误: {e}")

if __name__ == "__main__":
    filter_hk_pure_ips()
