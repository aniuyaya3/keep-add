#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, sys, time, json, requests, urllib
from seleniumbase import SB

# 环境变量配置(可以直接私库在双引号里填写)
EMAIL         = os.environ.get("EMAIL") or ""           # 邮箱,只用于通知使用，可随意填写
DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN") or ""   # Discord Token 备用登录方式, 失败时才使用,必须填写
TG_CHAT_ID    = os.environ.get("TG_CHAT_ID") or ""      # TG chat id,不填写不通知，需和bot token一起填写生效
TG_BOT_TOKEN  = os.environ.get("TG_BOT_TOKEN") or ""    # TG bot token 

BASE_URL = "https://dash.pingless.org"

# 解析 DISCORD_TOKEN
DC_TOKEN = ""
if DISCORD_TOKEN:
    _parts = DISCORD_TOKEN.split(",", 1)
    DC_TOKEN = _parts[-1].strip()
else:
    print("❌ 未配置 DISCORD_TOKEN,脚本退出")
    sys.exit(1)

# 发送tg通知
def send_telegram_message(message: str):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("⚠️ Telegram 未配置，跳过通知")
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TG_CHAT_ID, "text": message}, timeout=10)
        print("✅ Telegram 通知已发送")
    except Exception as e:
        print(f"❌ Telegram 发送失败: {e}")

# 通知格式
def format_notification(status: str, extra: str = "", error: str = "", expiry_date: str = "") -> str:
    local_time = time.gmtime(time.time() + 8 * 3600)
    now = time.strftime("%Y-%m-%d %H:%M:%S", local_time)
    if '@' in EMAIL:
        name, domain = EMAIL.split('@', 1)
        if len(name) > 4:
            masked_email = f"{name[:2]}****{name[-2:]}@{domain}"
        else:
            masked_email = f"{name}@{domain}"
    else:
        masked_email = EMAIL[:2] + '****'

    lines = [
        "🚀 Pingless 续期通知",
        "",
        f"{status}",
    ]
    if expiry_date:
        lines.append(f"📅 到期时间: {expiry_date}")
    if extra:
        lines.append("")
        lines.append(extra)
    if error:
        lines.append(f"⚠️ 错误信息: {error}")
    lines.append("")
    lines.append(f"👤 登录账户: {masked_email}")
    lines.append(f"⏱️ 登录时间: {now}")
    return "\n".join(lines)
    
# 去掉倒计时末尾的 remaining（仅用于通知展示）
def strip_remaining(t: str) -> str:
    return re.sub(r"\s*remaining\s*$", "", t or "", flags=re.I).strip()

# 获取当前出口ip
def get_current_ip(proxy_server: str = "") -> str:
    proxies = None
    if proxy_server:
        proxies = {"http": proxy_server, "https": proxy_server}
    response = requests.get("https://api.ip.sb/ip", proxies=proxies, timeout=15)
    response.raise_for_status()
    return response.text.strip()

#   Discord OAuth 登录（Pingless 站点）
DISCORD_CLIENT_ID   = "1461061267069600018"
OAUTH_REDIRECT_URI  = f"{BASE_URL}/api/auth/discord/callback"  # 备用值，优先从授权 URL 动态提取
OAUTH_SCOPE         = "identify email"
DISCORD_API         = "https://discord.com/api/v9/oauth2/authorize"
DISCORD_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
)
STATE_RE = re.compile(r"[?&]state=([^&]+)")

def extract_discord_authorize_url(current_url: str) -> str:
    """从 Discord 登录中转页中提取真正的授权 URL"""
    # 方法1: redirect_to 被正确 URL 编码时 parse_qs 可正常解析
    parsed = urllib.parse.urlparse(current_url)
    params = urllib.parse.parse_qs(parsed.query)
    redirect_to = params.get("redirect_to", [""])[0].strip()
    if redirect_to and "oauth2/authorize" in redirect_to:
        if redirect_to.startswith("/"):
            return f"https://discord.com{redirect_to}"
        return redirect_to

    # 方法2: redirect_to 未被完全编码（含裸 &），用正则取完整值
    m = re.search(r'[?&]redirect_to=(.+)', current_url)
    if m:
        redirect_to = urllib.parse.unquote(m.group(1).strip())
        if redirect_to.startswith("/"):
            return f"https://discord.com{redirect_to}"
        if redirect_to.startswith("http"):
            return redirect_to

    return ""


def fetch_authorize_url_from_site() -> str:
    """通过 HTTP 请求获取站点生成的 Discord 授权 URL（含正确 redirect_uri）"""
    try:
        resp = requests.get(
            f"{BASE_URL}/api/discord/login",
            allow_redirects=False,
            timeout=15,
            headers={"User-Agent": DISCORD_UA},
        )
        location = resp.headers.get("Location", "")
        if location and "discord.com" in location:
            print("🔗 从站点重定向获取到授权 URL")
            return location
        # 有些站点在响应体中包含重定向 URL
        if resp.text and "discord.com/oauth2/authorize" in resp.text:
            m = re.search(r'(https://discord\.com/oauth2/authorize\?[^\s"\'<>]+)', resp.text)
            if m:
                return m.group(1)
    except Exception as e:
        print(f"⚠️ HTTP 获取授权 URL 失败: {e}")
    return ""


def capture_discord_state(sb) -> str:
    """为 Zenode 的 Discord OAuth 路由生成一个稳定的 state 值"""
    print("🔎 获取 Discord OAuth state...")
    state = f"pingless-{int(time.time() * 1000)}"
    url = sb.get_current_url()
    print(f"✅ 已生成本地 state（当前落地页：{urllib.parse.urlparse(url).path}）")
    return state


def discord_authorize(state: str, authorize_url: str = "") -> str:
    """用 DC_TOKEN 直接完成 Discord 侧授权，返回跳转回站点的 location"""
    if not authorize_url:
        query = urllib.parse.urlencode({
            "client_id":     DISCORD_CLIENT_ID,
            "response_type": "code",
            "redirect_uri":  OAUTH_REDIRECT_URI,
            "scope":         OAUTH_SCOPE,
            "state":         state,
        })
        authorize_url = f"{DISCORD_API}?{query}"

    # 浏览器提取的可能是 Web 页面 URL，需转换为 API 端点
    if "/oauth2/authorize" in authorize_url and "/api/" not in authorize_url:
        authorize_url = authorize_url.replace("/oauth2/authorize", "/api/v9/oauth2/authorize", 1)

    # 从授权 URL 提取实际参数（确保 redirect_uri 与 Discord 应用注册的一致）
    _parsed = urllib.parse.urlparse(authorize_url)
    _params = urllib.parse.parse_qs(_parsed.query)
    _redirect_uri = _params.get("redirect_uri", [OAUTH_REDIRECT_URI])[0]
    _client_id = _params.get("client_id", [DISCORD_CLIENT_ID])[0]
    _scope = _params.get("scope", [OAUTH_SCOPE])[0]

    # 确保必要参数在授权 URL 中
    _query = _parsed.query or ""
    _missing = []
    if "response_type=" not in _query:
        _missing.append("response_type=code")
    if "scope=" not in _query:
        _missing.append(f"scope={urllib.parse.quote(_scope)}")
    if _missing:
        sep = "&" if _query else "?"
        authorize_url += f"{sep}{'&'.join(_missing)}"

    print(f"🔗 scope={_scope} | redirect_uri={_redirect_uri}")

    referer = (
        "https://discord.com/oauth2/authorize?" +
        urllib.parse.urlencode({
            "client_id":     _client_id,
            "redirect_uri":  _redirect_uri,
            "response_type": "code",
            "scope":         _scope,
            "state":         state,
        })
    )

    headers = {
        "accept":           "*/*",
        "authorization":    DC_TOKEN,
        "content-type":     "application/json",
        "origin":           "https://discord.com",
        "referer":          referer,
        "user-agent":       DISCORD_UA,
        "x-discord-locale": "en-US",
    }

    body = json.dumps({
        "permissions": "0",
        "authorize": True,
        "scope": _scope,
        "integration_type": 0,
        "location_context": {
            "guild_id": "10000",
            "channel_id": "10000",
            "channel_type": 10000,
        },
    })

    proxies = None
    _is_proxy = os.environ.get("IS_PROXY", "false").lower() == "true"
    _proxy_server = os.environ.get("PROXY_SERVER", "").strip() or "http://127.0.0.1:1081"
    if _is_proxy:
        proxies = {"http": _proxy_server, "https": _proxy_server}

    try:
        resp = requests.post(authorize_url, headers=headers, data=body, proxies=proxies, timeout=20)
        if resp.status_code != 200:
            print(f"❌ Discord OAuth2 授权失败: HTTP {resp.status_code} - {resp.text[:300]}")
            if resp.status_code == 401:
                send_telegram_message(format_notification(
                    "❌ Discord Token 已失效",
                    error="401 Unauthorized — 请更新 DISCORD_TOKEN",
                ))
            return ""
        resp_data = {}
        try:
            resp_data = resp.json()
            location = resp_data.get("location", "")
        except Exception:
            body_text = resp.text.strip()
            print(f"⚠️ Discord 返回非 JSON 响应（前200字符）：{body_text[:200]}")
            location_match = re.search(r'"location"\s*:\s*"([^"]+)"', body_text)
            if location_match:
                location = location_match.group(1)
            else:
                location = ""
    except Exception as e:
        print(f"❌ Discord OAuth2 授权异常: {e}")
        return ""

    if not location:
        print(f"❌ 授权响应中未找到 location 字段: {resp_data or resp.text[:200]}")
        return ""

    masked = re.sub(r"code=[^&]+", "code=***", location)
    print(f"✅ 拿到回调 URL: {masked}")
    return location


def click_activity_confirm(sb, in_modal: bool = False) -> tuple[bool, str]:
    if in_modal:
        for _ in range(10):
            js_code = """
            const modal = document.querySelector('#host-activity-confirmation-modal');
            if (!modal) return false;
            const candidates = Array.from(modal.querySelectorAll('button'));
            const targets = [
                'je confirme utiliser ce serveur',
                'i confirm i am using this server',
            ];
            for (const btn of candidates) {
                const text = (btn.textContent || '').replace(/\\s+/g, ' ').trim().toLowerCase();
                if (targets.some(item => text.includes(item))) {
                    btn.scrollIntoView({ block: 'center' });
                    btn.click();
                    return true;
                }
            }
            return false;
            """
            try:
                clicked = sb.execute_script(js_code)
                if clicked:
                    return True, 'modal::text-match'
            except Exception:
                pass
            sb.sleep(0.5)
        return False, ""

    target_selectors = ['button[data-activity-confirm]', 'button:contains("Je confirme utiliser ce serveur")', 'button:contains("I confirm I am using this server")']
    for selector in target_selectors:
        try:
            if sb.is_element_present(selector):
                sb.click(selector)
                return True, selector
        except Exception:
            pass

    js_code = """
    const targetButtons = Array.from(document.querySelectorAll('button[data-activity-confirm]'));
    for (const btn of targetButtons) {
        if (btn && (btn.offsetParent !== null || btn.getClientRects().length > 0)) {
            btn.scrollIntoView({ block: 'center' });
            btn.click();
            return true;
        }
    }
    return false;
    """
    try:
        clicked = sb.execute_script(js_code)
        if clicked:
            return True, 'button[data-activity-confirm]'
    except Exception:
        pass

    return False, ""


def do_discord_login(sb) -> bool:
    """通过 Discord OAuth 完成 Pingless 登录"""

    login_selectors = [
        'a[href*="/api/discord/login"]',
        'a:contains("Continue with Discord")',
        'a[href*="discord"]',
    ]
    clicked = False
    for selector in login_selectors:
        try:
            if sb.is_element_visible(selector):
                sb.click(selector)
                clicked = True
                print(f"✅ 已点击 Discord 登录按钮: {selector}")
                break
        except Exception:
            pass

    sb.sleep(5)
    current_url = sb.get_current_url()

    # 如果未到 Discord，尝试直接访问登录端点触发重定向
    if "discord.com" not in current_url:
        print("🔄 未跳转到 Discord，尝试直接访问 /api/discord/login...")
        sb.open(f"{BASE_URL}/api/discord/login")
        sb.wait_for_ready_state_complete()
        sb.sleep(5)
        current_url = sb.get_current_url()

    # 继续等待 Discord 重定向
    if "discord.com" not in current_url:
        for _ in range(10):
            sb.sleep(1)
            current_url = sb.get_current_url()
            if "discord.com" in current_url:
                break

    if "discord.com" not in current_url:
        print(f"❌ 未能跳转到 Discord，当前 URL: {current_url}")
        sb.save_screenshot("login_no_discord.png")
        return False

    print(f"📍 已到达 Discord: {urllib.parse.urlparse(current_url).path}")

    # 优先通过 HTTP 获取授权 URL（避免浏览器 URL 编码问题）
    authorize_url = fetch_authorize_url_from_site()

    # 备用：从浏览器 Discord 页面提取
    if not authorize_url:
        authorize_url = extract_discord_authorize_url(current_url)
        if not authorize_url and "oauth2/authorize" in current_url:
            authorize_url = current_url

    if not authorize_url:
        print(f"❌ 无法从 Discord 页面提取授权 URL: {current_url}")
        sb.save_screenshot("login_no_auth_url.png")
        return False

    # 从授权 URL 提取 state
    state_match = STATE_RE.search(authorize_url)
    state = state_match.group(1) if state_match else f"pingless-{int(time.time() * 1000)}"
    print(f"🔎 OAuth state: {state[:30]}...")

    location = discord_authorize(state, authorize_url=authorize_url)
    if not location:
        return False

    print("↩️ 携带授权码打开回调链接...")
    sb.uc_open_with_reconnect(location, reconnect_time=4)
    time.sleep(3)

    url = sb.get_current_url()
    if "/error/banned" in url:
        print("🚫 账号已被封禁")
        sb.save_screenshot("login_banned.png")
        return False

    if BASE_URL not in url:
        print(f"❌ 回调后未跳转至 Pingless，当前 URL：{url}")
        sb.save_screenshot("login_no_redirect.png")
        return False

    try:
        body_text = sb.get_text("body")
    except Exception:
        body_text = ""
    if "fraud" in body_text.lower():
        print("🚫 触发风控（fraud attempt），可能是 IP 被拦截")
        sb.save_screenshot("login_fraud.png")
        return False

    for _ in range(30):
        url = sb.get_current_url()
        path = urllib.parse.urlparse(url).path
        if BASE_URL in url and path not in ["/login", "/login/discord"]:
            print(f"✅ Discord 登录成功！当前页面：{url}")
            return True
        time.sleep(0.5)

    print(f"❌ 登录超时或未跳转成功，最终停留在：{url}")
    try:
        body_text = sb.get_text("body")
        print(f"📄 页面正文片段：{body_text[:200].strip()!r}")
    except Exception:
        pass
    sb.save_screenshot("login_timeout.png")
    return False


# 处理单台服务器：从 servers 页面点击第 idx 行进入详情页并执行续期，返回结果摘要
def process_server(sb, idx: int, total: int, server_name: str, server_status: str) -> str:
    is_offline = server_status.lower() == "offline"
    server_info = f"🖥️ 服务器[{idx + 1}/{total}]: {server_name or '未知'} ({server_status or '未知状态'})"

    # 点击第 idx 个服务器行进入详情页
    print(f"🖱️ 点击服务器 [{idx + 1}/{total}]，进入服务器详情页...")
    try:
        clicked = sb.execute_script(f"""
            const rows = document.querySelectorAll('.server-row');
            if (rows.length > {idx}) {{ rows[{idx}].click(); return true; }}
            return false;
        """)
    except Exception:
        clicked = False
    if not clicked:
        print(f"❌ 未找到第 {idx + 1} 个服务器行")
        return f"{server_info}\n📋 续期结果: ❌ 未找到对应服务器行"
    sb.wait_for_ready_state_complete()
    sb.sleep(4)

    # 校验是否到达服务器详情页（url 中包含 manage?id=）
    current_url = sb.get_current_url()
    if "manage?id=" not in current_url:
        print(f"❌ 未到达服务器详情页，当前URL: {current_url}")
        return f"{server_info}\n📋 续期结果: ❌ 未到达服务器详情页"
    print(f"✅ 已到达服务器详情页: {current_url}")

    # 获取 Next Renewal 倒计时（#renewal-time）
    def get_renewal_time() -> str:
        try:
            if sb.is_element_present("#renewal-time"):
                return sb.get_text("#renewal-time").strip()
        except Exception:
            pass
        return ""

    renewal_time_before = get_renewal_time()
    print(f"⏳ Next Renewal: {renewal_time_before or '未获取到'}")

    # 判断 Renewal 按钮是否可用（不可用时按钮带 hidden/disabled，页面显示 renewal-time 倒计时）
    renew_available = False
    if sb.is_element_present("#renew-server"):
        btn_class = sb.get_attribute("#renew-server", "class") or ""
        try:
            sb.get_attribute("#renew-server", "disabled")
            btn_disabled = True
        except Exception:
            btn_disabled = False
        renew_available = ("hidden" not in btn_class) and (not btn_disabled)

    if not renew_available:
        print(f"ℹ️ 未到续期时间 (Next Renewal: {renewal_time_before or '未知'})")
        return f"{server_info}\n📋 续期结果: ⏳ 未到续期时间\n📅 到期时间: {strip_remaining(renewal_time_before) or '未获取到'}"

    # 点击 Renew Now 按钮执行续期
    print("🔁 点击 Renew Now 按钮执行续期...")
    sb.click("#renew-server")
    sb.sleep(3)

    # 等待 success 提示模态框（alert success）—— 模态框可能几秒就消失
    success_text = ""
    for _ in range(5):
        try:
            success_text = sb.execute_script("""
                const els = document.querySelectorAll('[class*="alert"], [role="alert"], [class*="toast"], [class*="modal"]');
                for (const el of els) {
                    const cls = (el.className || '').toString().toLowerCase();
                    const txt = (el.textContent || '').replace(/\\s+/g, ' ').trim();
                    if (!txt) continue;
                    if (cls.includes('success') || /success|renewed|续期成功/i.test(txt)) {
                        return txt.slice(0, 200);
                    }
                }
                return '';
            """) or ""
        except Exception:
            success_text = ""
        if success_text:
            break
        sb.sleep(1)

    # 续期后再次检查 renewal-time
    renewal_time_after = get_renewal_time()
    print(f"⏳ 续期后 Next Renewal: {renewal_time_after or '未获取到'}")

    # 判断续期是否成功：模态框检测到 或 renewal-time 发生明显变化
    renewal_changed = (
        renewal_time_after
        and renewal_time_after != renewal_time_before
        and "remaining" in renewal_time_after.lower()
    )
    renew_success = bool(success_text) or renewal_changed

    if renew_success:
        if success_text:
            print(f"✅ 续期成功: {success_text}")
        else:
            print(f"✅ 续期成功（renewal-time 变化: {renewal_time_before} → {renewal_time_after}）")
        # 如果服务器是 Offline 状态，续期后需要启动
        if is_offline:
            print("🔌 服务器为 Offline，尝试启动...")
            started = False
            for sel in ['button:contains("Start")', '#start-server', 'button:contains("启动")']:
                try:
                    if sb.is_element_visible(sel):
                        sb.click(sel)
                        started = True
                        print(f"✅ 已点击启动按钮: {sel}")
                        break
                except Exception:
                    pass
            if started:
                sb.sleep(3)
                server_info += "\n🔌 已执行启动操作"
            else:
                print("⚠️ 未找到启动按钮，请手动启动")
                server_info += "\n⚠️ 未找到启动按钮，请手动启动"
        return (
            f"{server_info}\n📋 续期结果: ✅ 续期成功"
            f"\n📅 到期时间: {strip_remaining(renewal_time_after or renewal_time_before) or '未获取到'}"
        )

    print("⚠️ 未检测到续期成功提示，请人工检查")
    return (
        f"{server_info}\n📋 续期结果: ⚠️ 续期可能未成功，请登录后台检查"
        f"\n📅 到期时间: {strip_remaining(renewal_time_after or renewal_time_before) or '未获取到'}"
    )


# 主流程
def main():
    print("#" * 25)
    print("   Pingless 自动续期")
    print("#" * 25)

    IS_PROXY = os.environ.get("IS_PROXY", "false").lower() == "true"
    PROXY_SERVER = os.environ.get("PROXY_SERVER", "").strip() or "http://127.0.0.1:1081"
    HEADLESS = os.environ.get("HEADLESS", "false").lower() == "true" 

    sb_kwargs = {"uc": True, "headless": HEADLESS}

    if IS_PROXY:
        print(f"🔗 挂载代理: {PROXY_SERVER}")
        sb_kwargs["proxy"] = PROXY_SERVER
    else:
        print("🍭 未使用代理，直连访问")

    with SB(**sb_kwargs) as sb:
        try:
            ip = get_current_ip(PROXY_SERVER if IS_PROXY else "")
            print(f"📍 当前出口IP: {ip}")
        except Exception as e:
            print(f"⚠️ 获取出口 IP 失败: {e}")

        login_ok = False

        print("🚀 启动浏览器...")
        sb.open(f"{BASE_URL}/auth")
        sb.wait_for_ready_state_complete()
        sb.sleep(5)

        print("🔑 通过 Discord token登录...")
        if do_discord_login(sb):
            current_url = sb.get_current_url()
            current_title = sb.get_title()
            print(f"📝 当前URL: {current_url}, Title: {current_title}")

            if "dashboard" in current_url and "auth" not in current_url:
                login_ok = True
            else:
                print(f"❌ Discord 登录后未到达 Dashboard 页面，当前URL: {current_url}, 标题: {current_title}")

        if not login_ok:
            error_msg = "Discord 登录失败或页面异常"
            send_telegram_message(format_notification("❌ 登录失败", error=error_msg))
            return

        print(f"🌐 导航到 servers 页面: {BASE_URL}/servers")
        sb.open(f"{BASE_URL}/servers")
        sb.wait_for_ready_state_complete()
        sb.sleep(3)

        # 等待服务器列表加载
        try:
            sb.wait_for_element_present(".server-row", timeout=15)
        except Exception:
            pass

        if not sb.is_element_present(".server-row"):
            print("❌ servers 页面未找到任何服务器")
            send_telegram_message(format_notification("❌ 续期失败", error="servers 页面未找到服务器"))
            return

        # 等待 5 秒让状态加载完成
        sb.sleep(5)

        # 获取所有服务器的名称和状态（可能有多台服务器）
        try:
            servers = sb.execute_script("""
                return Array.from(document.querySelectorAll('.server-row')).map(row => {
                    const nameEl = row.querySelector('.font-medium.text-white');
                    const statusEl = row.querySelector('.status-text');
                    return {
                        name: nameEl ? nameEl.textContent.trim() : '',
                        status: statusEl ? statusEl.textContent.trim() : '',
                    };
                });
            """) or []
        except Exception:
            servers = []
        if not servers:
            servers = [{"name": "", "status": ""}]
        total = len(servers)
        print(f"📋 共发现 {total} 台服务器")

        # 循环处理每台服务器
        results = []
        for idx, info in enumerate(servers):
            server_name = (info.get("name") or "").strip()
            server_status = (info.get("status") or "").strip()
            print(f"🖥️ 服务器[{idx + 1}/{total}]: {server_name or '未知'} | 状态: {server_status or '未知'}")

            # 第二台起需先返回 servers 列表页
            if idx > 0:
                print(f"🌐 返回 servers 页面处理下一台服务器...")
                sb.open(f"{BASE_URL}/servers")
                sb.wait_for_ready_state_complete()
                sb.sleep(3)
                try:
                    sb.wait_for_element_present(".server-row", timeout=15)
                except Exception:
                    pass
                sb.sleep(3)

            try:
                result = process_server(sb, idx, total, server_name, server_status)
            except Exception as e:
                print(f"❌ 处理服务器[{idx + 1}/{total}]异常: {e}")
                result = f"🖥️ 服务器[{idx + 1}/{total}]: {server_name or '未知'}\n📋 续期结果: ❌ 处理异常: {e}"
            results.append(result)

        # 汇总发送通知
        send_telegram_message(format_notification(
            f"📋 共处理 {total} 台服务器",
            extra="\n\n".join(results),
        ))

        print("🏁 脚本执行完毕")

if __name__ == "__main__":
    main()
