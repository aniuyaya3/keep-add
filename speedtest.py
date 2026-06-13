#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.request

def filter_hk_pure_ips():
    url = "https://raw.githubusercontent.com/HandsomeMJZ/cfip/refs/heads/main/best_ips.txt,https://edt-aio-nav.pages.dev/vps789/top10.txt"
    output_file = "ip.txt"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    print("正在提取纯净 HK IP（强制剔除端口）...")
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8')
            
        lines = content.splitlines()
        hk_ips = set() # 使用集合自动去重
        
        for line in lines:
            line = line.strip()
            if not line or 'hk' not in line.lower():
                continue
                
            # 1. 移除 #HK 等后缀标签
            if '#' in line:
                line = line.split('#')[0].strip()
                
            # 2. 处理端口号
            if ']:' in line:
                # 针对 IPv6 格式，如 [2001:db8::1]:443 -> 提取方括号内部
                pure_ip = line.split(']:')[0].replace('[', '').strip()
            elif line.count(':') == 1:
                # 针对标准 IPv4 格式，如 1.1.1.1:443 -> 按冒号切分取前半部分
                pure_ip = line.split(':')[0].strip()
            elif ':' in line and not line.endswith(']'):
                # 针对没有带方括号却带了端口的特殊 IPv6 格式
                # 从右边倒序切分一次
                parts = line.rsplit(':', 1)
                # 如果最后一部分全是数字（说明是端口），就取前面部分
                if parts[1].isdigit():
                    pure_ip = parts[0].strip()
                else:
                    pure_ip = line
            else:
                pure_ip = line
                
            if pure_ip:
                hk_ips.add(pure_ip)
        
        # 排序并写入文件
        sorted_ips = sorted(list(hk_ips))
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_ips))
            
        print(f" 更新成功！已过滤所有端口，共导出 {len(sorted_ips)} 个纯净 IP 到 {output_file}")
        
    except Exception as e:
        print(f" 发生错误: {e}")

if __name__ == "__main__":
    filter_hk_pure_ips()
