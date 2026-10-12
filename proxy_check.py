#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import html
import json
import time
import random
import argparse
import threading
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
    wait,
    FIRST_COMPLETED,
)

import requests

# ============================================================
# 基础配置
# ============================================================
SOURCE_URL = (
    "https://raw.githubusercontent.com/watchttvv/"
    "free-proxy-list/refs/heads/main/proxy.txt"
)

CHECK_APIS = [
    "https://cs.uuu.dpdns.org/check",
    "https://cs2.uuu.dpdns.org/check",
    "https://cs3.uuu.dpdns.org/check",
    "https://cs4.uuu.dpdns.org/check",
]
DEFAULT_OUTPUT = "px.txt"

MAX_X_VALUES = 256        # 每个 X 取值 0~255
MAX_WORKERS = 16          # 不同代理组并发数量
REQUEST_TIMEOUT = 20      # API 请求超时（秒）
MAX_X_ATTEMPTS = 256      # 单个 X 组最多实际检测的候选数
API_RETRIES = 2           # 瞬时 HTTP 错误的额外重试次数
RETRYABLE_STATUS = {403, 429, 500, 502, 503, 504}
RACE_WINDOW = 8           # X 组内抢跑窗口（每组最多在飞检测数）
MAX_INFLIGHT = 64         # 全局在飞检测上限（双 Worker 合计）

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "Chrome/131.0.0.0 Safari/537.36"
)

# ============================================================
# Telegram
# ============================================================
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "").strip()

# ============================================================
# Session（thread-local，修复原版跨线程共享）
# ============================================================
_tls = threading.local()


def get_session():
    session = getattr(_tls, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "application/json,text/plain,*/*",
        })
        _tls.session = session
    return session


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
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/{method}"
    try:
        response = requests.post(url, data=kwargs, timeout=30)
        if response.status_code != 200:
            log(f"[TG] API错误 {response.status_code}: {response.text[:500]}")
            return False
        data = response.json()
        if not data.get("ok"):
            log(f"[TG] Telegram返回错误：{data}")
            return False
        return True
    except Exception as e:
        log(f"[TG] Telegram请求异常：{e}")
        return False


def telegram_send_message(text):
    return telegram_api(
        "sendMessage",
        chat_id=TG_CHAT_ID,
        text=text,
        parse_mode="HTML",
        disable_web_page_preview="true",
    )


def telegram_send_file(filepath, caption=""):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendDocument"
    try:
        with open(filepath, "rb") as file:
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
            log(f"[TG] 文件发送失败 {response.status_code}: {response.text[:500]}")
            return False
        data = response.json()
        if not data.get("ok"):
            log(f"[TG] 文件发送失败：{data}")
            return False
        return True
    except Exception as e:
        log(f"[TG] 文件发送异常：{e}")
        return False


# ============================================================
# 获取代理源（带重试）
# ============================================================
def fetch_source():
    log(f"[+] 获取代理列表：{SOURCE_URL}")
    last_exc = None
    for attempt in range(3):
        try:
            response = get_session().get(SOURCE_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            text = response.text
            log(f"[+] 获取完成：{len(text.splitlines())} 行")
            return text
        except Exception as e:
            last_exc = e
            if attempt < 2:
                wait = 2 ** attempt
                log(f"[!] 获取源失败（{e}），{wait}s 后重试")
                time.sleep(wait)
    raise last_exc


# ============================================================
# 代理 URL 提取
# ============================================================
PROXY_RE = re.compile(
    r"(?P<url>(?:socks5|http|https|turn|sstp)://[^\s]+)",
    re.IGNORECASE,
)


def extract_proxy_lines(text):
    results = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 只处理 [家宽]
        if "[家宽]" not in line:
            continue
        match = PROXY_RE.search(line)
        if not match:
            continue
        proxy = match.group("url").strip()
        if proxy in seen:  # 源去重，避免重复全量扫描
            continue
        seen.add(proxy)
        results.append({"proxy": proxy, "source_line": line})
    return results


# ============================================================
# X 识别与展开（修复：只认 IPv4 主机段中整段为 X 的 octet）
# ============================================================
_PROXY_PARTS_RE = re.compile(
    r"^(?P<scheme>[a-zA-Z0-9]+://)"
    r"(?P<authority>[^/]+)"
    r"(?P<suffix>/.*)?$"
)
_IPV4_HOSTPORT_RE = re.compile(
    r"^(?P<host>(?:\d+|X)(?:\.(?:\d+|X)){3})(?P<port>:\d+)?$",
    re.IGNORECASE,
)


def parse_proxy(proxy):
    """拆出 scheme / auth_prefix / host / port / suffix；失败返回 None。"""
    match = _PROXY_PARTS_RE.match(proxy)
    if not match:
        return None
    authority = match.group("authority")
    if "@" in authority:
        auth, hostport = authority.rsplit("@", 1)
        auth_prefix = auth + "@"
    else:
        auth_prefix = ""
        hostport = authority
    return {
        "scheme": match.group("scheme"),
        "auth_prefix": auth_prefix,
        "hostport": hostport,
        "suffix": match.group("suffix") or "",
    }


def x_octet_positions(proxy):
    """返回 IPv4 主机段中整段为 X 的 octet 下标列表；无 X 返回 []。

    密码、域名、路径里出现的字母 x 不算 X 占位——这是原版最大的误判源。
    """
    parts = parse_proxy(proxy)
    if not parts:
        return []
    match = _IPV4_HOSTPORT_RE.match(parts["hostport"])
    if not match:
        return []
    octets = match.group("host").split(".")
    return [i for i, o in enumerate(octets) if o.upper() == "X"]


def contains_x(proxy):
    return bool(x_octet_positions(proxy))


def theoretical_candidates(proxy):
    positions = x_octet_positions(proxy)
    if not positions:
        return 1
    return min(MAX_X_VALUES ** len(positions), MAX_X_ATTEMPTS)


def expand_proxy(proxy):
    positions = x_octet_positions(proxy)
    if not positions:
        # 含 X 占位但主机不是 IPv4 形式（如 IPv6 X）：明确日志，不静默丢
        if _has_ipv6_x(proxy):
            log(f"[!] 跳过（IPv6 X 占位不支持展开）：{proxy}")
            return []
        return [proxy]
    parts = parse_proxy(proxy)
    match = _IPV4_HOSTPORT_RE.match(parts["hostport"])
    host = match.group("host")
    port = match.group("port") or ""
    octets = host.split(".")

    def build(values):
        current = list(octets)
        for pos, value in zip(positions, values):
            current[pos] = str(value)
        return (
            parts["scheme"] + parts["auth_prefix"]
            + ".".join(current) + port + parts["suffix"]
        )

    total = MAX_X_VALUES ** len(positions)
    if total <= MAX_X_ATTEMPTS:
        results = []

        def recursive(index, current):
            if index == len(positions):
                results.append(build(current))
                return
            for value in range(MAX_X_VALUES):
                recursive(index + 1, current + [value])

        recursive(0, [])
        random.shuffle(results)
        return results

    # 多 X：随机采样 MAX_X_ATTEMPTS 个不重复候选（原版直接放弃整组）
    log(
        f"[!] {proxy}：理论候选 {total} 个，"
        f"随机采样 {MAX_X_ATTEMPTS} 个检测"
    )
    sampled = set()
    while len(sampled) < MAX_X_ATTEMPTS:
        sampled.add(tuple(random.randrange(MAX_X_VALUES) for _ in positions))
    results = [build(values) for values in sampled]
    random.shuffle(results)
    return results


def _has_ipv6_x(proxy):
    """仅方括号 IPv6 字面量里的 X 才算 IPv6 X 占位；
    域名/主机名里的字母 x（如 example.com）绝不能误判。"""
    parts = parse_proxy(proxy)
    if not parts:
        return False
    hostport = parts["hostport"]
    return hostport.startswith("[") and "X" in hostport.upper()


# ============================================================
# 国家 / 城市 / 住宅判断
# （已按 2026-10-12 实测的 API 返回结构核对：exit.country /
#  exit.country_code / exit.city / exit.is_datacenter 均真实存在）
# ============================================================
def _dig(data, *paths):
    for path in paths:
        current = data
        ok = True
        for key in path:
            if not isinstance(current, dict) or not current.get(key):
                ok = False
                break
            current = current[key]
        if ok:
            return str(current).strip()
    return ""


def get_country(data):
    value = _dig(
        data,
        ("exit", "location", "country"),
        ("exit", "location", "country_name"),
        ("exit", "country"),
        ("exit", "country_name"),
        ("country",),
        ("country_name",),
        # 兜底：只有代码没有名称时用代码，避免整列变“未知”
        ("exit", "location", "country_code"),
        ("exit", "country_code"),
        ("country_code",),
    )
    return value or "未知"


def get_country_code(data):
    return _dig(
        data,
        ("exit", "location", "country_code"),
        ("exit", "location", "countryCode"),
        ("exit", "country_code"),
        ("exit", "countryCode"),
        ("country_code",),
        ("countryCode",),
    )


def get_city(data):
    return _dig(
        data,
        ("exit", "location", "city"),
        ("exit", "city"),
        ("exit", "city_name"),
        ("city",),
    )


def is_residential(data):
    exit_info = data.get("exit") or {}
    if "is_datacenter" in exit_info:
        return not bool(exit_info.get("is_datacenter"))
    if "is_datacenter" in data:
        return not bool(data.get("is_datacenter"))
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
        value = str(value).lower()
        if "datacenter" in value or "机房" in value:
            return False
        if "residential" in value or "住宅" in value:
            return True
    # API 没有提供判断；源已明确 [家宽]，允许保留（与原版一致）
    return True


# ============================================================
# endpoint 轮换 + 全局在飞上限
#
# 轮换：每次检测（含重试）取下一个 endpoint，负载在 cs / cs2 两个
# Worker 间均分；某 endpoint 返回可重试错误时，下一次重试天然落到
# 另一个 Worker，等于自带故障转移。
# 全局信号量：不管组间并发和组内抢跑开多大，真正同时打到 API 的
# 请求数封顶 MAX_INFLIGHT，避免把两个 Worker 一起打到 403。
# ============================================================
_api_counter_lock = threading.Lock()
_api_counter = 0
_inflight_sem = threading.Semaphore(MAX_INFLIGHT)
_active_apis = None
_active_lock = threading.Lock()


def probe_check_apis():
    """一次性探活：拿到任意 HTTP 响应（含 403）就算 endpoint 存在；
    只有连接层异常（DNS 不存在、连不上）才剔除。"""
    alive = []
    for url in CHECK_APIS:
        try:
            requests.get(
                url,
                params={"proxy": "http://127.0.0.1:9"},
                timeout=10,
                headers={"User-Agent": USER_AGENT},
            )
            alive.append(url)
        except Exception:
            log(f"[!] endpoint 不可用，本轮剔除：{url}")
    if not alive:
        log("[!] 全部 endpoint 探活失败，回退为完整列表")
        return list(CHECK_APIS)
    return alive


def active_check_apis():
    global _active_apis
    if _active_apis is None:
        with _active_lock:
            if _active_apis is None:
                _active_apis = probe_check_apis()
                log(
                    f"[+] 可用 endpoint {len(_active_apis)}/"
                    f"{len(CHECK_APIS)}："
                    + "、".join(
                        u.split("/")[2] for u in _active_apis
                    )
                )
    return _active_apis


def next_check_api():
    global _api_counter
    apis = active_check_apis()
    with _api_counter_lock:
        url = apis[_api_counter % len(apis)]
        _api_counter += 1
    return url


def check_proxy(proxy):
    with _inflight_sem:
        return _check_proxy_inner(proxy)


# ============================================================
# 检测代理（瞬时 HTTP 错误重试；success=false 不重试）
# ============================================================
def _check_proxy_inner(proxy):
    last_error = "检测失败"
    for attempt in range(API_RETRIES + 1):
        try:
            response = get_session().get(
                next_check_api(),
                params={"proxy": proxy},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.Timeout:
            return {"proxy": proxy, "success": False, "error": "超时"}
        except requests.exceptions.RequestException as e:
            # 连接层异常（DNS/连接被拒等）多半是单个 endpoint 的问题：
            # 切到下一个 endpoint 重试，而不是直接判这个候选死亡
            last_error = str(e)
            if attempt < API_RETRIES:
                time.sleep((2 ** attempt) + random.uniform(0, 0.5))
                continue
            return {"proxy": proxy, "success": False, "error": last_error}
        except Exception as e:
            return {"proxy": proxy, "success": False, "error": str(e)}

        if response.status_code != 200:
            last_error = f"HTTP {response.status_code}"
            if response.status_code in RETRYABLE_STATUS and attempt < API_RETRIES:
                time.sleep((2 ** attempt) + random.uniform(0, 0.5))
                continue
            return {"proxy": proxy, "success": False, "error": last_error}

        try:
            data = response.json()
        except Exception:
            # CF 拦截页等非 JSON 响应同样按瞬时错误处理
            last_error = "JSON解析失败"
            if attempt < API_RETRIES:
                time.sleep((2 ** attempt) + random.uniform(0, 0.5))
                continue
            return {"proxy": proxy, "success": False, "error": last_error}

        if not data.get("success"):
            return {
                "proxy": proxy,
                "success": False,
                "error": data.get("error", "检测失败"),
            }

        country = get_country(data)
        if country == "未知":
            log("[DEBUG] 国家未知，API原始返回：")
            log(json.dumps(data, ensure_ascii=False)[:5000])

        try:
            response_time = int(data.get("responseTime", 0))
        except Exception:
            response_time = 0

        return {
            "proxy": proxy,
            "success": True,
            "country": country,
            "country_code": get_country_code(data),
            "city": get_city(data),
            "residential": is_residential(data),
            "response_time": response_time,
            "exit": data.get("exit") or {},
            "raw": data,
        }
    return {"proxy": proxy, "success": False, "error": last_error}


# ============================================================
# 普通代理
# ============================================================
def process_normal(proxy):
    result = check_proxy(proxy)
    if not result.get("success"):
        return []
    if not result.get("residential", True):
        log(f"[×] 机房过滤：{proxy}")
        return []
    log(
        f"[✓] {proxy} -> {result['country']} "
        f"{result['response_time']}ms"
    )
    return [result]


# ============================================================
# X 代理组：抢跑（滑动窗口）+ 命中即停
#
# 原理：组内同时保持 RACE_WINDOW 个检测在飞，完成一个补一个，
# 死代理的服务端超时互相重叠而不是串行累加。第一个返回的
# “成功且住宅”即为命中：停发新候选、取消未启动的在飞任务；
# 已发出的请求停不掉，结果直接丢弃（其线程仍占全局信号量
# 直到自然结束，总量有界）。命中但机房不算命中，继续抢跑。
# RACE_WINDOW=1 时退化为原版顺序扫。
# ============================================================
def process_x_group(source_proxy):
    expanded = expand_proxy(source_proxy)
    if not expanded:
        return []
    window = max(1, RACE_WINDOW)
    log(f"[X] 开始：{source_proxy} 候选 {len(expanded)} 抢跑窗口 {window}")
    checked = 0
    hit = None

    if window == 1:
        for candidate in expanded:
            checked += 1
            result = check_proxy(candidate)
            if result.get("success"):
                if not result.get("residential", True):
                    log(f"[X] 命中但为机房：{candidate}")
                    continue
                hit = result
                break
            if checked % 50 == 0:
                log(f"[X] {source_proxy} 已检测 {checked}/{len(expanded)}")
    else:
        candidates = iter(expanded)
        executor = ThreadPoolExecutor(max_workers=window)
        in_flight = {}

        def fill():
            while len(in_flight) < window:
                try:
                    candidate = next(candidates)
                except StopIteration:
                    return
                in_flight[executor.submit(check_proxy, candidate)] = candidate

        try:
            fill()
            while in_flight and hit is None:
                done, _ = wait(
                    list(in_flight), return_when=FIRST_COMPLETED
                )
                for future in done:
                    candidate = in_flight.pop(future)
                    checked += 1
                    try:
                        result = future.result()
                    except Exception as e:
                        result = {
                            "proxy": candidate,
                            "success": False,
                            "error": str(e),
                        }
                    if result.get("success"):
                        if not result.get("residential", True):
                            log(f"[X] 命中但为机房：{candidate}")
                            continue
                        hit = result
                        break
                    if checked % 50 == 0:
                        log(
                            f"[X] {source_proxy} "
                            f"已检测 {checked}/{len(expanded)}"
                        )
                if hit is None:
                    fill()
        finally:
            # 不等待在飞的落败者：取消未启动的，已启动的丢弃结果
            executor.shutdown(wait=False, cancel_futures=True)

    if hit is not None:
        log(
            f"[✓] X命中：{hit['proxy']} -> {hit['country']} "
            f"{hit['response_time']}ms ({checked}/{len(expanded)})"
        )
        return [hit]
    log(f"[×] X组无可用：{source_proxy}")
    return []


def process_source_proxy(source_proxy):
    if contains_x(source_proxy):
        return process_x_group(source_proxy)
    return process_normal(source_proxy)


# ============================================================
# Telegram 汇总（动态内容全部 HTML 转义）
# ============================================================
def build_telegram_message(source_count, candidate_count, valid, elapsed):
    valid_count = len(valid)
    lines = ["🏠 <b>住宅代理检测完成</b>", ""]
    lines.append(f"📥 源中家宽：<b>{source_count}</b>")
    lines.append(f"🔎 X理论候选：<b>{candidate_count}</b>")
    lines.append(f"✅ 有效住宅：<b>{valid_count}</b>")
    lines.append(f"⏱ 耗时：<b>{elapsed:.1f}s</b>")
    if candidate_count:
        rate = valid_count / candidate_count * 100
        lines.append(f"📊 有效率：<b>{rate:.2f}%</b>")
    lines.append("")
    if valid:
        lines.append("🏆 <b>TOP 10</b>")
        for index, item in enumerate(valid[:10], 1):
            proxy = html.escape(item["proxy"])
            country = html.escape(item.get("country", "未知"))
            city = html.escape(item.get("city", ""))
            latency = item.get("response_time", 0)
            location = country + (f" · {city}" if city else "")
            lines.append(
                f"{index}. <code>{proxy}</code>\n"
                f"   🌍 {location} ⚡ {latency}ms"
            )
        lines.append("")
        lines.append("📄 <b>px.txt</b> 将作为文件发送")
    else:
        lines.append("❌ 没有找到有效住宅代理")
    return "\n".join(lines)


def _suffix_part(value):
    """px.txt 后缀清洗：空白→_，去掉会截断注释的 #。"""
    return re.sub(r"\s+", "_", str(value or "").strip()).replace("#", "")


# ============================================================
# 主程序
# ============================================================
def main():
    global RACE_WINDOW, _inflight_sem
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=MAX_WORKERS)
    parser.add_argument("--race", type=int, default=RACE_WINDOW,
                        help="X 组内抢跑窗口，1=顺序扫")
    parser.add_argument("--max-inflight", type=int, default=MAX_INFLIGHT,
                        help="全局在飞检测上限（双 Worker 合计）")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    RACE_WINDOW = max(1, args.race)
    _inflight_sem = threading.Semaphore(max(1, args.max_inflight))
    active = active_check_apis()
    log(
        f"[+] 检测 endpoint：{len(active)} 个轮换 "
        f"抢跑窗口：{RACE_WINDOW} 全局在飞上限：{args.max_inflight}"
    )

    start_time = time.time()
    log("[TG] Telegram通知：已启用" if (TG_BOT_TOKEN and TG_CHAT_ID)
        else "[TG] Telegram通知：未配置")

    text = fetch_source()
    residential_sources = extract_proxy_lines(text)
    source_count = len(residential_sources)
    log("")
    log(f"[+] [家宽]代理：{source_count}")

    if not residential_sources:
        open(args.output, "w", encoding="utf-8").close()
        return

    theoretical = sum(
        theoretical_candidates(item["proxy"]) for item in residential_sources
    )
    log(f"[+] 理论最大候选：{theoretical}")

    valid = []
    completed_groups = 0
    total_groups = len(residential_sources)
    log("")
    log(f"[+] 开始检测：{total_groups} 个源代理 / 并发 {args.workers}")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(process_source_proxy, item["proxy"]): item["proxy"]
            for item in residential_sources
        }
        for future in as_completed(future_map):
            source_proxy = future_map[future]
            completed_groups += 1
            try:
                valid.extend(future.result())
            except Exception as e:
                log(f"[!] 任务异常：{source_proxy} {e}")
            if completed_groups % 10 == 0 or completed_groups == total_groups:
                log(
                    f"[*] 进度：{completed_groups}/{total_groups} "
                    f"有效：{len(valid)}"
                )

    # 去重 + 按延迟排序
    unique = {}
    for item in valid:
        unique.setdefault(item["proxy"], item)
    valid = sorted(
        unique.values(),
        key=lambda item: item.get("response_time", 999999),
    )

    output_lines = list(dict.fromkeys(
        f"{item['proxy']}#家宽_{_suffix_part(item.get('country', '未知'))}"
        f"_{_suffix_part(item.get('city', ''))}"
        for item in valid
    ))
    with open(args.output, "w", encoding="utf-8") as file:
        if output_lines:
            file.write("\n".join(output_lines) + "\n")

    elapsed = time.time() - start_time
    valid_count = len(output_lines)
    log("")
    log("=" * 60)
    log("检测完成")
    log("=" * 60)
    log(f"[家宽]源：{source_count}")
    log(f"理论候选：{theoretical}")
    log(f"有效住宅：{valid_count}")
    log(f"耗时：{elapsed:.1f}s")
    log(f"输出：{args.output}")
    log("=" * 60)

    if output_lines:
        log("")
        log("TOP 20：")
        for line in output_lines[:20]:
            log(line)

    if TG_BOT_TOKEN and TG_CHAT_ID:
        message = build_telegram_message(
            source_count=source_count,
            candidate_count=theoretical,
            valid=valid,
            elapsed=elapsed,
        )
        log("[TG] 发送检测统计...")
        telegram_send_message(message)
        if valid_count:
            log("[TG] 发送 px.txt...")
            caption = (
                "📄 <b>住宅代理列表</b>\n"
                f"有效数量：<b>{valid_count}</b>"
            )
            telegram_send_file(args.output, caption)
        else:
            log("[TG] 有效数为 0，跳过空文件发送")


if __name__ == "__main__":
    main()
