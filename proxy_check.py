#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Residential Proxy Scanner
=========================
功能：
1. 从 watchttvv/free-proxy-list 获取代理
2. 只筛选 [家宽]
3. 支持 socks5/http/https/turn/sstp
4. 支持用户名密码
5. 支持 IPv6
6. X 自动展开 0~255
7. X 组发现第一个可用代理后立即停止
8. 普通代理直接检测
9. 自动读取出口国家
10. 自动判断住宅 / 机房
11. 输出 px.txt
12. Telegram 通知
13. Telegram 发送 px.txt
"""
import os
import re
import json
import time
import random
import argparse
import threading
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
import requests
# ============================================================
# 基础配置
# ============================================================
SOURCE_URL = (
    "https://raw.githubusercontent.com/watchttvv/"
    "free-proxy-list/refs/heads/main/proxy.txt"
)
CHECK_API = "https://cs.uuu.dpdns.org/check"
DEFAULT_OUTPUT = "px.txt"
# X 每组最多尝试 256 个
MAX_X_VALUES = 256
# 不同代理组并发数量
MAX_WORKERS = 16
# API 请求超时
REQUEST_TIMEOUT = 20
# 单个 X 组最多检测数量
MAX_X_ATTEMPTS = 256
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "Chrome/131.0.0.0 Safari/537.36"
)
# ============================================================
# Telegram
# ============================================================
TG_BOT_TOKEN = os.environ.get(
    "TG_BOT_TOKEN",
    ""
).strip()
TG_CHAT_ID = os.environ.get(
    "TG_CHAT_ID",
    ""
).strip()
# ============================================================
# Session
# ============================================================
session = requests.Session()
session.headers.update({
    "User-Agent": USER_AGENT,
    "Accept": "application/json,text/plain,*/*",
})
print_lock = threading.Lock()
def log(message):
    with print_lock:
        print(message, flush=True)
# ============================================================
# Telegram API
# ============================================================
def telegram_api(method, **kwargs):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    url = (
        "https://api.telegram.org/"
        f"bot{TG_BOT_TOKEN}/{method}"
    )
    try:
        response = requests.post(
            url,
            data=kwargs,
            timeout=30,
        )
        if response.status_code != 200:
            log(
                "[TG] API错误 "
                f"{response.status_code}: "
                f"{response.text[:500]}"
            )
            return False
        data = response.json()
        if not data.get("ok"):
            log(
                "[TG] Telegram返回错误："
                f"{data}"
            )
            return False
        return True
    except Exception as e:
        log(
            f"[TG] Telegram请求异常：{e}"
        )
        return False
def telegram_send_message(text):
    return telegram_api(
        "sendMessage",
        chat_id=TG_CHAT_ID,
        text=text,
        parse_mode="HTML",
        disable_web_page_preview="true",
    )
def telegram_send_file(
    filepath,
    caption=""
):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    url = (
        "https://api.telegram.org/"
        f"bot{TG_BOT_TOKEN}/sendDocument"
    )
    try:
        with open(
            filepath,
            "rb"
        ) as file:
            response = requests.post(
                url,
                data={
                    "chat_id": TG_CHAT_ID,
                    "caption": caption,
                    "parse_mode": "HTML",
                },
                files={
                    "document": (
                        os.path.basename(filepath),
                        file,
                        "text/plain",
                    )
                },
                timeout=60,
            )
        if response.status_code != 200:
            log(
                "[TG] 文件发送失败 "
                f"{response.status_code}: "
                f"{response.text[:500]}"
            )
            return False
        data = response.json()
        if not data.get("ok"):
            log(
                f"[TG] 文件发送失败：{data}"
            )
            return False
        return True
    except Exception as e:
        log(
            f"[TG] 文件发送异常：{e}"
        )
        return False
# ============================================================
# 获取代理源
# ============================================================
def fetch_source():
    log(
        f"[+] 获取代理列表：{SOURCE_URL}"
    )
    response = session.get(
        SOURCE_URL,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    text = response.text
    log(
        "[+] 获取完成："
        f"{len(text.splitlines())} 行"
    )
    return text
# ============================================================
# 代理 URL 提取
# ============================================================
PROXY_RE = re.compile(
    r"""
    (?P<url>
        (?:socks5|http|https|turn|sstp)://
        [^\s]+
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
def extract_proxy_lines(text):
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        # ====================================================
        # 核心：
        # 只处理 [家宽]
        # ====================================================
        if "[家宽]" not in line:
            continue
        match = PROXY_RE.search(line)
        if not match:
            continue
        proxy = match.group(
            "url"
        ).strip()
        results.append({
            "proxy": proxy,
            "source_line": line,
        })
    return results
# ============================================================
# 判断是否包含 X
# ============================================================
def contains_x(proxy):
    return "X" in proxy.upper()
# ============================================================
# 展开 X
# ============================================================
def expand_proxy(proxy):
    if not contains_x(proxy):
        return [proxy]
    # ========================================================
    # 解析 scheme
    # ========================================================
    match = re.match(
        r"^(?P<scheme>[a-zA-Z0-9]+://)"
        r"(?P<authority>[^/]+)"
        r"(?P<suffix>/.*)?$",
        proxy,
    )
    if not match:
        log(
            f"[!] 无法解析代理：{proxy}"
        )
        return []
    scheme = match.group(
        "scheme"
    )
    authority = match.group(
        "authority"
    )
    suffix = (
        match.group("suffix")
        or ""
    )
    # ========================================================
    # 用户名密码
    # ========================================================
    if "@" in authority:
        auth, hostport = (
            authority.rsplit("@", 1)
        )
        auth_prefix = auth + "@"
    else:
        auth_prefix = ""
        hostport = authority
    # ========================================================
    # IPv4:port
    # ========================================================
    match = re.match(
        r"^(?P<host>"
        r"(?:\d+|X)"
        r"(?:\.(?:\d+|X)){3}"
        r")"
        r"(?P<port>:\d+)?$",
        hostport,
        re.IGNORECASE,
    )
    if not match:
        log(
            f"[!] X不是标准IPv4格式："
            f"{proxy}"
        )
        return []
    host = match.group(
        "host"
    )
    port = (
        match.group("port")
        or ""
    )
    parts = host.split(".")
    if len(parts) != 4:
        return []
    x_positions = [
        i
        for i, part in enumerate(parts)
        if part.upper() == "X"
    ]
    if not x_positions:
        return [proxy]
    # ========================================================
    # 理论数量
    # ========================================================
    total = (
        MAX_X_VALUES
        ** len(x_positions)
    )
    if total > MAX_X_ATTEMPTS:
        log(
            f"[!] 跳过 {proxy}："
            f"需要 {total} 个候选"
        )
        return []
    # ========================================================
    # 递归展开
    # ========================================================
    results = []
    def recursive(
        index,
        current,
    ):
        if index == 4:
            ip = ".".join(current)
            results.append(
                scheme
                + auth_prefix
                + ip
                + port
                + suffix
            )
            return
        if parts[index].upper() == "X":
            for value in range(
                MAX_X_VALUES
            ):
                recursive(
                    index + 1,
                    current + [
                        str(value)
                    ],
                )
        else:
            recursive(
                index + 1,
                current + [
                    parts[index]
                ],
            )
    recursive(0, [])
    # ========================================================
    # 随机顺序
    #
    # 避免每次都从 .0 开始
    # ========================================================
    random.shuffle(results)
    return results
# ============================================================
# 国家识别
# ============================================================
def get_country(data):
    exit_info = (
        data.get("exit")
        or {}
    )
    location = (
        exit_info.get("location")
        or {}
    )
    candidates = [
        # location
        location.get("country"),
        location.get("country_name"),
        location.get("countryName"),
        # exit
        exit_info.get("country"),
        exit_info.get("country_name"),
        exit_info.get("countryName"),
        # 顶层
        data.get("country"),
        data.get("country_name"),
        data.get("countryName"),
    ]
    for value in candidates:
        if value:
            value = str(
                value
            ).strip()
            if value:
                return value
    return "未知"
# ============================================================
# 国家代码
# ============================================================
def get_country_code(data):
    exit_info = (
        data.get("exit")
        or {}
    )
    location = (
        exit_info.get("location")
        or {}
    )
    candidates = [
        location.get("country_code"),
        location.get("countryCode"),
        exit_info.get("country_code"),
        exit_info.get("countryCode"),
        data.get("country_code"),
        data.get("countryCode"),
    ]
    for value in candidates:
        if value:
            return str(
                value
            ).strip()
    return ""
# ============================================================
# 城市
# ============================================================
def get_city(data):
    exit_info = (
        data.get("exit")
        or {}
    )
    location = (
        exit_info.get("location")
        or {}
    )
    candidates = [
        location.get("city"),
        location.get("city_name"),
        location.get("cityName"),
        exit_info.get("city"),
        exit_info.get("city_name"),
        data.get("city"),
    ]
    for value in candidates:
        if value:
            return str(
                value
            ).strip()
    return ""
# ============================================================
# 判断是否住宅
# ============================================================
def is_residential(data):
    exit_info = (
        data.get("exit")
        or {}
    )
    # ========================================================
    # API 最可靠字段
    # ========================================================
    if "is_datacenter" in exit_info:
        return not bool(
            exit_info.get(
                "is_datacenter"
            )
        )
    # ========================================================
    # 其它可能字段
    # ========================================================
    if "is_datacenter" in data:
        return not bool(
            data.get(
                "is_datacenter"
            )
        )
    # ========================================================
    # 如果 API 返回文字类型
    # ========================================================
    values = [
        exit_info.get("type"),
        exit_info.get("network_type"),
        exit_info.get("category"),
        data.get("type"),
        data.get("network_type"),
        data.get("category"),
    ]
    for value in values:
        if not value:
            continue
        value = str(
            value
        ).lower()
        if (
            "datacenter" in value
            or "机房" in value
        ):
            return False
        if (
            "residential" in value
            or "住宅" in value
        ):
            return True
    # ========================================================
    # API 没有提供判断
    #
    # 因为源已经明确 [家宽]
    # 所以允许保留
    # ========================================================
    return True
# ============================================================
# 检测代理
# ============================================================
def check_proxy(proxy):
    try:
        response = session.get(
            CHECK_API,
            params={
                "proxy": proxy
            },
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            return {
                "proxy": proxy,
                "success": False,
                "error": (
                    f"HTTP "
                    f"{response.status_code}"
                ),
            }
        try:
            data = response.json()
        except Exception:
            return {
                "proxy": proxy,
                "success": False,
                "error": "JSON解析失败",
            }
        # ====================================================
        # API success
        # ====================================================
        if not data.get(
            "success"
        ):
            return {
                "proxy": proxy,
                "success": False,
                "error": data.get(
                    "error",
                    "检测失败",
                ),
            }
        # ====================================================
        # 国家
        # ====================================================
        country = get_country(
            data
        )
        country_code = (
            get_country_code(
                data
            )
        )
        city = get_city(
            data
        )
        # ====================================================
        # 住宅判断
        # ====================================================
        residential = (
            is_residential(
                data
            )
        )
        # ====================================================
        # 延迟
        # ====================================================
        response_time = data.get(
            "responseTime",
            0,
        )
        try:
            response_time = int(
                response_time
            )
        except Exception:
            response_time = 0
        # ====================================================
        # 调试：
        # 如果国家仍然未知，输出原始 JSON
        # ====================================================
        if country == "未知":
            log(
                "[DEBUG] 国家未知，"
                "API原始返回："
            )
            log(
                json.dumps(
                    data,
                    ensure_ascii=False,
                )[:5000]
            )
        # ====================================================
        # 返回
        # ====================================================
        return {
            "proxy": proxy,
            "success": True,
            "country": country,
            "country_code": country_code,
            "city": city,
            "residential": residential,
            "response_time": response_time,
            "exit": (
                data.get("exit")
                or {}
            ),
            "raw": data,
        }
    except requests.exceptions.Timeout:
        return {
            "proxy": proxy,
            "success": False,
            "error": "超时",
        }
    except requests.exceptions.RequestException as e:
        return {
            "proxy": proxy,
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "proxy": proxy,
            "success": False,
            "error": str(e),
        }
# ============================================================
# 普通代理
# ============================================================
def process_normal(proxy):
    result = check_proxy(
        proxy
    )
    if not result.get(
        "success"
    ):
        return []
    # ========================================================
    # 如果 API 明确判断为机房
    # 就不要写入
    # ========================================================
    if not result.get(
        "residential",
        True
    ):
        log(
            f"[×] 机房过滤："
            f"{proxy}"
        )
        return []
    log(
        f"[✓] "
        f"{proxy} "
        f"-> "
        f"{result['country']} "
        f"{result['response_time']}ms"
    )
    return [result]
# ============================================================
# X 代理组
#
# 关键：
#
# 发现第一个可用代理
# 立即停止这个 X 组
# ============================================================
def process_x_group(source_proxy):
    expanded = expand_proxy(
        source_proxy
    )
    if not expanded:
        return []
    log(
        f"[X] 开始："
        f"{source_proxy} "
        f"候选 {len(expanded)}"
    )
    checked = 0
    for candidate in expanded:
        checked += 1
        result = check_proxy(
            candidate
        )
        # ----------------------------------------------------
        # 成功
        # ----------------------------------------------------
        if result.get(
            "success"
        ):
            # ------------------------------------------------
            # API 明确判断机房
            # ------------------------------------------------
            if not result.get(
                "residential",
                True
            ):
                log(
                    f"[X] 命中但为机房："
                    f"{candidate}"
                )
                continue
            # ------------------------------------------------
            # 找到住宅代理
            # ------------------------------------------------
            log(
                f"[✓] X命中："
                f"{candidate} "
                f"-> "
                f"{result['country']} "
                f"{result['response_time']}ms "
                f""
                f"({checked}/"
                f"{len(expanded)})"
            )
            # =================================================
            # 核心：
            #
            # 立即停止
            # =================================================
            return [result]
        # ----------------------------------------------------
        # 每 50 个打印一次
        # ----------------------------------------------------
        if checked % 50 == 0:
            log(
                f"[X] "
                f"{source_proxy} "
                f"已检测 "
                f"{checked}/"
                f"{len(expanded)}"
            )
    log(
        f"[×] X组无可用："
        f"{source_proxy}"
    )
    return []
# ============================================================
# 处理一个源代理
# ============================================================
def process_source_proxy(
    source_proxy
):
    if contains_x(
        source_proxy
    ):
        return process_x_group(
            source_proxy
        )
    return process_normal(
        source_proxy
    )
# ============================================================
# Telegram 汇总
# ============================================================
def build_telegram_message(
    source_count,
    candidate_count,
    valid,
    elapsed,
):
    valid_count = len(
        valid
    )
    lines = []
    lines.append(
        "🏠 <b>住宅代理检测完成</b>"
    )
    lines.append("")
    lines.append(
        f"📥 源中家宽："
        f"<b>{source_count}</b>"
    )
    lines.append(
        f"🔎 X理论候选："
        f"<b>{candidate_count}</b>"
    )
    lines.append(
        f"✅ 有效住宅："
        f"<b>{valid_count}</b>"
    )
    lines.append(
        f"⏱ 耗时："
        f"<b>{elapsed:.1f}s</b>"
    )
    if candidate_count:
        rate = (
            valid_count
            / candidate_count
            * 100
        )
        lines.append(
            f"📊 有效率："
            f"<b>{rate:.2f}%</b>"
        )
    lines.append("")
    # ========================================================
    # TOP 10
    # ========================================================
    if valid:
        lines.append(
            "🏆 <b>TOP 10</b>"
        )
        for index, item in enumerate(
            valid[:10],
            1
        ):
            proxy = item[
                "proxy"
            ]
            country = item.get(
                "country",
                "未知"
            )
            city = item.get(
                "city",
                ""
            )
            latency = item.get(
                "response_time",
                0
            )
            location = country
            if city:
                location += (
                    f" · {city}"
                )
            lines.append(
                f"{index}. "
                f"<code>{proxy}</code>\n"
                f"   🌍 {location} "
                f"⚡ {latency}ms"
            )
    else:
        lines.append(
            "❌ "
            "没有找到有效住宅代理"
        )
    lines.append("")
    lines.append(
        "📄 <b>px.txt</b> "
        "将作为文件发送"
    )
    return "\n".join(
        lines
    )
# ============================================================
# 主程序
# ============================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workers",
        type=int,
        default=MAX_WORKERS,
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
    )
    args = parser.parse_args()
    start_time = time.time()
    # ========================================================
    # Telegram 状态
    # ========================================================
    if (
        TG_BOT_TOKEN
        and TG_CHAT_ID
    ):
        log(
            "[TG] Telegram通知：已启用"
        )
    else:
        log(
            "[TG] Telegram通知：未配置"
        )
    # ========================================================
    # 获取源
    # ========================================================
    text = fetch_source()
    # ========================================================
    # 提取 [家宽]
    # ========================================================
    residential_sources = (
        extract_proxy_lines(
            text
        )
    )
    source_count = len(
        residential_sources
    )
    log("")
    log(
        f"[+] [家宽]代理："
        f"{source_count}"
    )
    if not residential_sources:
        open(
            args.output,
            "w",
            encoding="utf-8"
        ).close()
        return
    # ========================================================
    # 统计 X 理论候选
    # ========================================================
    theoretical_candidates = 0
    for item in residential_sources:
        proxy = item[
            "proxy"
        ]
        if contains_x(proxy):
            theoretical_candidates += (
                MAX_X_VALUES
            )
        else:
            theoretical_candidates += 1
    log(
        "[+] 理论最大候选："
        f"{theoretical_candidates}"
    )
    # ========================================================
    # 开始检测
    #
    # 注意：
    #
    # 每个源代理是一个任务。
    #
    # X 内部顺序检测。
    #
    # 不同 X 组之间并发。
    # ========================================================
    valid = []
    completed_groups = 0
    total_groups = len(
        residential_sources
    )
    log("")
    log(
        "[+] 开始检测："
        f"{total_groups} 个源代理 "
        f"/ 并发 {args.workers}"
    )
    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:
        future_map = {}
        for item in residential_sources:
            source_proxy = item[
                "proxy"
            ]
            future = executor.submit(
                process_source_proxy,
                source_proxy,
            )
            future_map[
                future
            ] = source_proxy
        for future in as_completed(
            future_map
        ):
            source_proxy = (
                future_map[future]
            )
            completed_groups += 1
            try:
                results = (
                    future.result()
                )
                valid.extend(
                    results
                )
            except Exception as e:
                log(
                    f"[!] 任务异常："
                    f"{source_proxy} "
                    f"{e}"
                )
            if (
                completed_groups % 10 == 0
                or
                completed_groups
                == total_groups
            ):
                log(
                    f"[*] 进度："
                    f"{completed_groups}/"
                    f"{total_groups} "
                    f"有效："
                    f"{len(valid)}"
                )
    # ========================================================
    # 去重
    # ========================================================
    unique = {}
    for item in valid:
        proxy = item[
            "proxy"
        ]
        if proxy not in unique:
            unique[
                proxy
            ] = item
    valid = list(
        unique.values()
    )
    # ========================================================
    # 延迟排序
    # ========================================================
    valid.sort(
        key=lambda item:
        item.get(
            "response_time",
            999999
        )
    )
    # ========================================================
    # 写 px.txt
    # ========================================================
    output_lines = []
    for item in valid:
        proxy = item[
            "proxy"
        ]
        country = item.get(
            "country",
            "未知"
        )
        city = item.get(
                "city",
                ""
        )
        output_lines.append(
            f"{proxy}#家宽_{country}_{city}"
        )
    output_lines = list(
        dict.fromkeys(
            output_lines
        )
    )
    with open(
        args.output,
        "w",
        encoding="utf-8"
    ) as file:
        if output_lines:
            file.write(
                "\n".join(
                    output_lines
                )
                + "\n"
            )
    # ========================================================
    # 完成统计
    # ========================================================
    elapsed = (
        time.time()
        - start_time
    )
    valid_count = len(
        output_lines
    )
    log("")
    log("=" * 60)
    log("检测完成")
    log("=" * 60)
    log(
        f"[家宽]源："
        f"{source_count}"
    )
    log(
        f"理论候选："
        f"{theoretical_candidates}"
    )
    log(
        f"有效住宅："
        f"{valid_count}"
    )
    log(
        f"耗时："
        f"{elapsed:.1f}s"
    )
    log(
        f"输出："
        f"{args.output}"
    )
    log("=" * 60)
    # ========================================================
    # 输出 TOP 20
    # ========================================================
    if output_lines:
        log("")
        log(
            "TOP 20："
        )
        for line in output_lines[:20]:
            log(line)
    # ========================================================
    # Telegram
    # ========================================================
    if (
        TG_BOT_TOKEN
        and TG_CHAT_ID
    ):
        message = (
            build_telegram_message(
                source_count=source_count,
                candidate_count=theoretical_candidates,
                valid=valid,
                elapsed=elapsed,
            )
        )
        # ----------------------------------------------------
        # 发送统计
        # ----------------------------------------------------
        log(
            "[TG] 发送检测统计..."
        )
        telegram_send_message(
            message
        )
        # ----------------------------------------------------
        # 发送 px.txt
        # ----------------------------------------------------
        log(
            "[TG] 发送 px.txt..."
        )
        caption = (
            "📄 <b>住宅代理列表</b>\n"
            f"有效数量：<b>{valid_count}</b>"
        )
        telegram_send_file(
            args.output,
            caption
        )
# ============================================================
# Entry
# ============================================================
if __name__ == "__main__":
    main()
