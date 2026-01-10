#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KataBump 自动续订/提醒脚本
cron: 0 9,21 * * *
new Env('KataBump续订');
"""

import os
import sys
import re
import requests
from datetime import datetime, timezone, timedelta

# ================== 配置 ==================
DASHBOARD_URL = 'https://dashboard.katabump.com'
SERVER_ID = os.environ.get('KATA_SERVER_ID', '')
KATA_EMAIL = os.environ.get('KATA_EMAIL', '')
KATA_PASSWORD = os.environ.get('KATA_PASSWORD', '')

TG_BOT_TOKEN = os.environ.get('TG_BOT_TOKEN', '')
TG_CHAT_ID = os.environ.get('TG_CHAT_ID', '')

# 执行器
EXECUTOR_NAME = os.environ.get('EXECUTOR_NAME', 'GitHub Actions')

# SOCKS5 代理（新增）
# 示例：
# socks5h://127.0.0.1:1080
# socks5://user:pass@ip:port
SOCKS5_PROXY = os.environ.get('SOCKS5_PROXY', '')

# Renew 操作指南
RENEW_GUIDE_HTML = """
📝 <b>Renew 操作指南:</b>
1. 登录 <a href="https://dashboard.katabump.com/">Dashboard</a>
2. 点击菜单栏 <b>Your Servers</b>
3. 找到服务器点击 <b>See</b>
4. 进入 <b>General</b> 页面
5. 点击蓝色的 <b>Renew</b> 按钮

🔗 <a href="https://dashboard.katabump.com/">点击此处直接跳转登录</a>
"""

# ================== 工具函数 ==================
def log(msg):
    tz = timezone(timedelta(hours=8))
    t = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{t}] {msg}')


def send_telegram(message):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    try:
        requests.post(
            f'https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage',
            json={
                'chat_id': TG_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            },
            timeout=30
        )
        log('✅ Telegram 通知已发送')
        return True
    except Exception as e:
        log(f'❌ Telegram 错误: {e}')
    return False


def get_expiry(html):
    match = re.search(r'Expiry[\s\S]*?(\d{4}-\d{2}-\d{2})', html, re.IGNORECASE)
    return match.group(1) if match else None


def get_csrf(html):
    patterns = [
        r'<input[^>]*name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']csrf["\']',
    ]
    for p in patterns:
        m = re.search(p, html, re.IGNORECASE)
        if m and len(m.group(1)) > 10:
            return m.group(1)
    return None


def days_until(date_str):
    try:
        exp = datetime.strptime(date_str, '%Y-%m-%d')
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return (exp - today).days
    except:
        return None


def parse_renew_error(url):
    if 'renew-error' not in url:
        return None, None

    error_match = re.search(r'renew-error=([^&]+)', url)
    if not error_match:
        return '未知错误', None

    error = requests.utils.unquote(error_match.group(1).replace('+', ' '))

    date_match = re.search(r'as of (\d+) (\w+)', error)
    if date_match:
        day = date_match.group(1)
        month = date_match.group(2)
        return error, f'{month} {day}'

    return error, None

# ================== 主逻辑 ==================
def run():
    log('🚀 KataBump 自动续订/提醒')
    log(f'🖥 服务器 ID: {SERVER_ID}')

    session = requests.Session()

    # ---------- SOCKS5 代理 ----------
    if SOCKS5_PROXY:
        session.proxies.update({
            'http': SOCKS5_PROXY,
            'https': SOCKS5_PROXY
        })
        log(f'🌐 使用 SOCKS5 代理: {SOCKS5_PROXY}')

    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    })

    try:
        # ========== 登录 ==========
        log('🔐 登录中...')
        session.get(f'{DASHBOARD_URL}/auth/login', timeout=30)

        login_resp = session.post(
            f'{DASHBOARD_URL}/auth/login',
            data={
                'email': KATA_EMAIL,
                'password': KATA_PASSWORD,
                'remember': 'true'
            },
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': DASHBOARD_URL,
                'Referer': f'{DASHBOARD_URL}/auth/login',
            },
            timeout=30,
            allow_redirects=True
        )

        log(f'📍 登录后URL: {login_resp.url}')

        if '/auth/login' in login_resp.url:
            raise Exception('登录失败，请检查账号密码')

        log('✅ 登录成功')

        # ========== 获取服务器信息 ==========
        server_page = session.get(f'{DASHBOARD_URL}/servers/edit?id={SERVER_ID}', timeout=30)
        url = server_page.url

        expiry = get_expiry(server_page.text) or '未知'
        days = days_until(expiry)
        csrf = get_csrf(server_page.text)

        log(f'📅 到期: {expiry} (剩余 {days} 天)')

        # ========== 续订限制 ==========
        error, _ = parse_renew_error(url)
        if error:
            log(f'⏳ {error}')
            if days is not None and days <= 2:
                send_telegram(
                    f'ℹ️ <b>KataBump 续订提醒</b>\n\n'
                    f'🖥 服务器: <code>{SERVER_ID}</code>\n'
                    f'📅 到期: {expiry}\n'
                    f'⏰ 剩余: {days} 天\n'
                    f'📝 状态: {error}\n'
                    f'💻 执行器: {EXECUTOR_NAME}\n\n'
                    f'{RENEW_GUIDE_HTML}'
                )
            return

        # ========== 尝试续订 ==========
        log('🔄 尝试续订...')
        api_resp = session.post(
            f'{DASHBOARD_URL}/api-client/renew?id={SERVER_ID}',
            data={'csrf': csrf} if csrf else {},
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': DASHBOARD_URL,
                'Referer': f'{DASHBOARD_URL}/servers/edit?id={SERVER_ID}'
            },
            timeout=30,
            allow_redirects=False
        )

        log(f'📥 状态码: {api_resp.status_code}')

        if api_resp.status_code == 302:
            location = api_resp.headers.get('Location', '')
            log(f'📍 重定向到: {location}')

            if 'renew=success' in location:
                check = session.get(f'{DASHBOARD_URL}/servers/edit?id={SERVER_ID}', timeout=30)
                new_expiry = get_expiry(check.text) or '未知'
                send_telegram(
                    f'✅ <b>KataBump 续订成功</b>\n\n'
                    f'🖥 服务器: <code>{SERVER_ID}</code>\n'
                    f'📅 原到期: {expiry}\n'
                    f'📅 新到期: {new_expiry}\n'
                    f'💻 执行器: {EXECUTOR_NAME}'
                )
                return

            if 'error=captcha' in location:
                raise Exception('检测到验证码，需要手动续订')

        # 最终校验
        check = session.get(f'{DASHBOARD_URL}/servers/edit?id={SERVER_ID}', timeout=30)
        new_expiry = get_expiry(check.text) or '未知'

        if new_expiry > expiry:
            send_telegram(
                f'✅ <b>KataBump 续订成功</b>\n\n'
                f'🖥 服务器: <code>{SERVER_ID}</code>\n'
                f'📅 原到期: {expiry}\n'
                f'📅 新到期: {new_expiry}\n'
                f'💻 执行器: {EXECUTOR_NAME}'
            )
        else:
            if days is not None and days <= 2:
                send_telegram(
                    f'⚠️ <b>KataBump 请检查续订状态</b>\n\n'
                    f'🖥 服务器: <code>{SERVER_ID}</code>\n'
                    f'📅 到期: {new_expiry}\n'
                    f'💻 执行器: {EXECUTOR_NAME}\n\n'
                    f'{RENEW_GUIDE_HTML}'
                )

    except Exception as e:
        log(f'❌ 错误: {e}')
        send_telegram(
            f'❌ <b>KataBump 运行出错</b>\n\n'
            f'🖥 服务器: <code>{SERVER_ID}</code>\n'
            f'❗ 错误信息: {e}\n'
            f'💻 执行器: {EXECUTOR_NAME}\n\n'
            f'{RENEW_GUIDE_HTML}'
        )
        raise


def main():
    log('=' * 50)
    log('   KataBump 自动续订/提醒脚本')
    log('=' * 50)

    if not KATA_EMAIL or not KATA_PASSWORD:
        log('❌ 请设置 KATA_EMAIL 和 KATA_PASSWORD')
        sys.exit(1)

    run()
    log('🏁 完成')


if __name__ == '__main__':
    main()
