#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
# ============================================================
# 配置
# ============================================================
SOURCE_URL = (
    "https://raw.githubusercontent.com/watchttvv/"
    "free-proxy-list/refs/heads/main/proxy.txt"
)
CHECK_API = "https://cs.uuu.dpdns.org/check"
OUTPUT_FILE = "px.txt"
MAX_WORKERS = 16
REQUEST_TIMEOUT = 20
MAX_CANDIDATES = 200000
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/131 Safari/537.36"
)
# Telegram
# 从环境变量读取，不要把 Token 写进代码
TG_BOT_TOKEN = None
TG_CHAT_ID = None
session = requests.Session()
session.headers.update({
    "User-Agent": USER_AGENT,
    "Accept": "application/json,text/plain,*/*",
})
print_lock = threading.Lock()
# ============================================================
# 日志
# ============================================================
def log(msg):
    with print_lock:
        print(msg, flush=True)
# ============================================================
# Telegram
# ============================================================
def telegram_api(method, **kwargs):
    """
    调用 Telegram Bot API
    """
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    url = (
        f"https://api.telegram.org/"
        f"bot{TG_BOT_TOKEN}/{method}"
    )
    try:
        r = requests.post(
            url,
            data=kwargs,
            timeout=20
        )
        if r.status_code != 200:
            log(
                f"[TG] API失败："
                f"{r.status_code} {r.text[:300]}"
            )
            return False
        data = r.json()
        if not data.get("ok"):
            log(
                f"[TG] Telegram返回失败："
                f"{data}"
            )
            return False
        return True
    except Exception as e:
        log(f"[TG] 请求异常：{e}")
        return False
def telegram_send_message(text):
    """
    发送 Telegram 文本消息
    """
    return telegram_api(
        "sendMessage",
        chat_id=TG_CHAT_ID,
        text=text,
        parse_mode="HTML",
        disable_web_page_preview="true"
    )
def telegram_send_file(filepath, caption):
    """
    将 px.txt 发送到 Telegram
    """
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    url = (
        f"https://api.telegram.org/"
        f"bot{TG_BOT_TOKEN}/sendDocument"
    )
    try:
        with open(filepath, "rb") as f:
            r = requests.post(
                url,
                data={
                    "chat_id": TG_CHAT_ID,
                    "caption": caption,
                    "parse_mode": "HTML",
                },
                files={
                    "document": (
                        filepath,
                        f,
                        "text/plain"
                    )
                },
                timeout=60
            )
        if r.status_code != 200:
            log(
                f"[TG] 文件发送失败："
                f"{r.status_code} {r.text[:300]}"
            )
            return False
        data = r.json()
        if not data.get("ok"):
            log(f"[TG] 文件发送失败：{data}")
            return False
        return True
    except Exception as e:
        log(f"[TG] 文件发送异常：{e}")
        return False
# ============================================================
# 获取代理源
# ============================================================
def fetch_source():
    log(f"[+] 获取代理列表：{SOURCE_URL}")
    r = session.get(
        SOURCE_URL,
        timeout=REQUEST_TIMEOUT
    )
    r.raise_for_status()
    text = r.text
    log(
        f"[+] 获取完成："
        f"{len(text.splitlines())} 行"
    )
    return text
# ============================================================
# 提取代理
# ============================================================
PROXY_RE = re.compile(
    r"""
    (?P<url>
        (?:socks5|http|https|turn|sstp)://
        [^\s]+
    )
    """,
    re.IGNORECASE | re.VERBOSE
)
def extract_proxy_lines(text):
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        # 只处理 [家宽]
        if "[家宽]" not in line:
            continue
        m = PROXY_RE.search(line)
        if not m:
            continue
        proxy = m.group("url").strip()
        results.append({
            "proxy": proxy,
            "source_line": line,
        })
    return results
# ============================================================
# X 展开
# ============================================================
def expand_proxy(proxy):
    if "X" not in proxy.upper():
        return [proxy]
    m = re.match(
        r"^(?P<prefix>[a-zA-Z0-9]+://)"
        r"(?P<authority>[^/]+)"
        r"(?P<suffix>/.*)?$",
        proxy
    )
    if not m:
        return []
    prefix = m.group("prefix")
    authority = m.group("authority")
    suffix = m.group("suffix") or ""
    # 用户名密码
    if "@" in authority:
        auth, hostport = authority.rsplit("@", 1)
        auth_prefix = auth + "@"
    else:
        auth_prefix = ""
        hostport = authority
    # IPv4
    host_match = re.match(
        r"^(?P<host>\d+(?:\.\d+|\.X){3})"
        r"(?P<port>:\d+)?$",
        hostport,
        re.IGNORECASE
    )
    if not host_match:
        log(f"[!] 无法展开：{proxy}")
        return []
    host = host_match.group("host")
    port = host_match.group("port") or ""
    parts = host.split(".")
    if len(parts) != 4:
        return []
    x_count = sum(
        1
        for p in parts
        if p.upper() == "X"
    )
    if x_count == 0:
        return [proxy]
    total = 256 ** x_count
    if total > MAX_CANDIDATES:
        log(
            f"[!] 跳过 {proxy}："
            f"{total} 个候选超过限制 "
            f"{MAX_CANDIDATES}"
        )
        return []
    results = []
    def recursive(index, current):
        if index == 4:
            ip = ".".join(current)
            results.append(
                prefix +
                auth_prefix +
                ip +
                port +
                suffix
            )
            return
        if parts[index].upper() == "X":
            for n in range(256):
                recursive(
                    index + 1,
                    current + [str(n)]
                )
        else:
            recursive(
                index + 1,
                current + [parts[index]]
            )
    recursive(0, [])
    return results
# ============================================================
# 检测
# ============================================================
def check_proxy(proxy):

    try:

        r = session.get(
            CHECK_API,
            params={
                "proxy": proxy
            },
            timeout=REQUEST_TIMEOUT
        )

        if r.status_code != 200:

            return {
                "proxy": proxy,
                "success": False,
                "error": f"HTTP {r.status_code}",
            }

        try:
            data = r.json()

        except Exception:

            return {
                "proxy": proxy,
                "success": False,
                "error": "JSON解析失败",
            }

        if not data.get("success"):

            return {
                "proxy": proxy,
                "success": False,
                "error": data.get(
                    "error",
                    "检测失败"
                ),
            }

        # ====================================================
        # 出口信息
        # ====================================================

        exit_info = data.get("exit") or {}

        # location 可能存在，也可能不存在
        location = exit_info.get("location") or {}

        # ====================================================
        # 国家信息兼容读取
        # ====================================================

        country = (
            location.get("country")
            or location.get("country_name")
            or location.get("countryName")
            or exit_info.get("country")
            or exit_info.get("country_name")
            or exit_info.get("countryName")
            or data.get("country")
            or data.get("country_name")
            or data.get("countryName")
        )

        # ====================================================
        # 城市
        # ====================================================

        city = (
            location.get("city")
            or location.get("city_name")
            or location.get("cityName")
            or exit_info.get("city")
            or exit_info.get("city_name")
            or data.get("city")
        )

        # ====================================================
        # 国家代码
        # ====================================================

        country_code = (
            location.get("country_code")
            or location.get("countryCode")
            or exit_info.get("country_code")
            or exit_info.get("countryCode")
            or data.get("country_code")
            or data.get("countryCode")
        )

        # ====================================================
        # 最后兜底
        # ====================================================

        if not country:

            # 如果有国家代码，也不要直接写未知
            if country_code:
                country = country_code

            else:
                country = "未知"

        response_time = data.get(
            "responseTime",
            0
        )

        return {
            "proxy": proxy,
            "success": True,

            "country": country,

            "country_code": country_code,

            "city": city,

            "exit": exit_info,

            "response_time": response_time,

            # 保存完整 JSON，方便以后调试
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
# Telegram 汇总
# ============================================================
def build_telegram_message(
    residential_count,
    candidate_count,
    valid_count,
    elapsed,
    valid
):
    lines = []
    lines.append("🏠 <b>住宅代理检测完成</b>")
    lines.append("")
    lines.append(
        f"📥 住宅源代理："
        f"<b>{residential_count}</b>"
    )
    lines.append(
        f"🔎 展开后候选："
        f"<b>{candidate_count}</b>"
    )
    lines.append(
        f"✅ 有效代理："
        f"<b>{valid_count}</b>"
    )
    lines.append(
        f"⏱ 检测耗时："
        f"<b>{elapsed:.1f} 秒</b>"
    )
    if candidate_count > 0:
        rate = (
            valid_count /
            candidate_count *
            100
        )
        lines.append(
            f"📊 有效率："
            f"<b>{rate:.2f}%</b>"
        )
    lines.append("")
    # TOP 10
    if valid:
        lines.append(
            "🏆 <b>TOP 10</b>"
        )
        for i, item in enumerate(
            valid[:10],
            1
        ):
            proxy = item["proxy"]
            country = item.get(
                "country",
                "未知"
            )
            latency = item.get(
                "response_time",
                0
            )
            lines.append(
                f"{i}. "
                f"<code>{proxy}</code>\n"
                f"   🌍 {country} "
                f"⚡ {latency}ms"
            )
    else:
        lines.append(
            "❌ 本次没有检测到有效住宅代理"
        )
    lines.append("")
    lines.append(
        "📄 px.txt 将作为文件发送"
    )
    return "\n".join(lines)
# ============================================================
# 主程序
# ============================================================
def main():
    global TG_BOT_TOKEN
    global TG_CHAT_ID
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workers",
        type=int,
        default=MAX_WORKERS
    )
    parser.add_argument(
        "--output",
        default=OUTPUT_FILE
    )
    args = parser.parse_args()
    # --------------------------------------------------------
    # Telegram 环境变量
    # --------------------------------------------------------
    import os
    TG_BOT_TOKEN = os.environ.get(
        "TG_BOT_TOKEN"
    )
    TG_CHAT_ID = os.environ.get(
        "TG_CHAT_ID"
    )
    if TG_BOT_TOKEN and TG_CHAT_ID:
        log("[TG] Telegram通知已启用")
    else:
        log(
            "[TG] 未配置 Telegram，"
            "跳过通知"
        )
    start_time = time.time()
    # --------------------------------------------------------
    # 获取源
    # --------------------------------------------------------
    text = fetch_source()
    # --------------------------------------------------------
    # 找家宽
    # --------------------------------------------------------
    residential = extract_proxy_lines(text)
    log("")
    log(
        f"[+] 找到住宅代理："
        f"{len(residential)} 条"
    )
    if not residential:
        open(
            args.output,
            "w",
            encoding="utf-8"
        ).close()
        return
    # --------------------------------------------------------
    # 展开 X
    # --------------------------------------------------------
    candidates = []
    for item in residential:
        proxy = item["proxy"]
        expanded = expand_proxy(proxy)
        log(
            f"[+] {proxy} -> "
            f"{len(expanded)} 个候选"
        )
        candidates.extend(expanded)
    # 去重
    candidates = list(
        dict.fromkeys(candidates)
    )
    log("")
    log(
        f"[+] X展开后："
        f"{len(candidates)} 个候选"
    )
    # --------------------------------------------------------
    # 检测
    # --------------------------------------------------------
    valid = []
    completed = 0
    total = len(candidates)
    log("")
    log(
        f"[+] 开始检测："
        f"{total} 个"
        f" / 并发 {args.workers}"
    )
    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:
        future_map = {
            executor.submit(
                check_proxy,
                proxy
            ): proxy
            for proxy in candidates
        }
        for future in as_completed(
            future_map
        ):
            proxy = future_map[future]
            completed += 1
            try:
                result = future.result()
            except Exception as e:
                result = {
                    "proxy": proxy,
                    "success": False,
                    "error": str(e),
                }
            if result.get("success"):
                country = result.get(
                    "country",
                    "未知"
                )
                latency = result.get(
                    "response_time",
                    0
                )
                valid.append(result)
                log(
                    f"[✓] {proxy} "
                    f"-> {country} "
                    f"{latency}ms "
                    f"({completed}/{total})"
                )
            elif completed % 100 == 0:
                log(
                    f"[*] 已完成 "
                    f"{completed}/{total} "
                    f"有效 {len(valid)}"
                )
    # --------------------------------------------------------
    # 按延迟排序
    # --------------------------------------------------------
    valid.sort(
        key=lambda x:
        x.get("response_time") or 999999
    )
    # --------------------------------------------------------
    # 生成 px.txt
    # --------------------------------------------------------
    output_lines = []
    for item in valid:
        proxy = item["proxy"]
        country = item.get(
            "country",
            "未知"
        )
        output_lines.append(
            f"{proxy}#住宅-{country}"
        )
    output_lines = list(
        dict.fromkeys(output_lines)
    )
    with open(
        args.output,
        "w",
        encoding="utf-8"
    ) as f:
        if output_lines:
            f.write(
                "\n".join(output_lines)
                + "\n"
            )
    # --------------------------------------------------------
    # 汇总
    # --------------------------------------------------------
    elapsed = (
        time.time() -
        start_time
    )
    log("")
    log("=" * 60)
    log("检测完成")
    log("=" * 60)
    log(
        f"住宅源：{len(residential)}"
    )
    log(
        f"候选：{len(candidates)}"
    )
    log(
        f"有效：{len(valid)}"
    )
    log(
        f"耗时：{elapsed:.1f}s"
    )
    log("=" * 60)
    # --------------------------------------------------------
    # Telegram
    # --------------------------------------------------------
    if TG_BOT_TOKEN and TG_CHAT_ID:
        message = build_telegram_message(
            residential_count=len(residential),
            candidate_count=len(candidates),
            valid_count=len(valid),
            elapsed=elapsed,
            valid=valid
        )
        # 先发文字
        telegram_send_message(message)
        # 再发 px.txt
        caption = (
            f"📄 <b>px.txt</b>\n"
            f"住宅有效代理：{len(valid)}"
        )
        telegram_send_file(
            args.output,
            caption
        )
if __name__ == "__main__":
    main()
