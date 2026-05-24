#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.request
import re

def filter_hk_ips():
    url = "https://raw.githubusercontent.com/HandsomeMJZ/cfip/refs/heads/main/best_ips.txt"
    output_file = "ip.txt"
    
    # 设置 User-Agent 伪装浏览器，防止被 GitHub 拦截
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    print( "正在从 GitHub 下载原始 IP 列表..." )
    
    try:
        # 发起网络请求
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            # 读取内容并按行解码
            content = response.read().decode('utf-8')
            
        lines = content.splitlines()
        hk_ips = []
        
        # 遍历每一行，筛选包含 hk 或 HK 的行
        for line in lines:
            if 'hk' in line.lower():
                hk_ips.append(line.strip())
                
        # 将筛选后的结果写入 ip.txt
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(hk_ips))
            
        print(f" 成功！已筛选出 {len(hk_ips)} 个 HK 节点，并保存到 {output_file}")
        
    except urllib.error.URLError as e:
        print(f" 网络错误：无法连接到 GitHub。请检查代理或网络环境。原因: {e.reason}")
    except Exception as e:
        print(f" 发生未知错误: {e}")

if __name__ == "__main__":
    filter_hk_ips()
