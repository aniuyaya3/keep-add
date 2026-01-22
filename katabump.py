#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KataBump 自动续订脚本 (代理版)
流程: 登录 → CF预热 → 服务器页面 → 点击Renew → 提交
"""

import os
import sys
import re
import asyncio
import requests
from datetime import datetime, timezone, timedelta
from playwright.async_api import async_playwright

# 配置
DASHBOARD_URL = 'https://dashboard.katabump.com'
SERVER_ID = os.environ.get('KATA_SERVER_ID') or ''
KATA_EMAIL = os.environ.get('KATA_EMAIL') or ''
KATA_PASSWORD = os.environ.get('KATA_PASSWORD') or ''
TG_BOT_TOKEN = os.environ.get('TG_BOT_TOKEN') or ''
TG_CHAT_ID = os.environ.get('TG_CHAT_ID') or os.environ.get('TG_USER_ID') or ''
SCREENSHOT_DIR = os.environ.get('SCREENSHOT_DIR') or '/tmp'
PROXY_SERVER = os.environ.get('PROXY_SERVER') or ''

CF_CHALLENGE_URL = 'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/cmg/1'


def log(msg):
    tz = timezone(timedelta(hours=8))
    t = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{t}] {msg}')


def get_requests_proxies():
    if not PROXY_SERVER:
        return None
    proxy = PROXY_SERVER.replace('socks5://', 'socks5h://')
    return {'http': proxy, 'https': proxy}


def tg_notify(message):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    try:
        requests.post(
            f'https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage',
            json={'chat_id': TG_CHAT_ID, 'text': message, 'parse_mode': 'HTML'},
            timeout=30, proxies=get_requests_proxies()
        )
        return True
    except:
        return False


def tg_notify_photo(photo_path, caption=''):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False
    try:
        with open(photo_path, 'rb') as f:
            requests.post(
                f'https://api.telegram.org/bot{TG_BOT_TOKEN}/sendPhoto',
                data={'chat_id': TG_CHAT_ID, 'caption': caption, 'parse_mode': 'HTML'},
                files={'photo': f}, timeout=60, proxies=get_requests_proxies()
            )
        return True
    except:
        return False


def get_expiry_from_text(text):
    match = re.search(r'Expiry[\s\S]*?(\d{4}-\d{2}-\d{2})', text, re.IGNORECASE)
    return match.group(1) if match else None


def days_until(date_str):
    try:
        exp = datetime.strptime(date_str, '%Y-%m-%d')
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return (exp - today).days
    except:
        return None


async def cf_warmup(page, context):
    """CF Cookie 预热"""
    log('🔥 CF 预热...')
    
    try:
        # 访问 CF challenge 端点
        await page.goto(CF_CHALLENGE_URL, timeout=30000)
        await page.wait_for_timeout(2000)
        
        # 检查 cookies
        cookies = await context.cookies()
        cf_cookies = [c for c in cookies if 'cf' in c['name'].lower()]
        log(f'📋 CF Cookies: {[c["name"] for c in cf_cookies]}')
        
        log('✅ CF 预热完成')
        return True
    except Exception as e:
        log(f'⚠️ CF 预热: {e}')
        return False


async def run():
    log('🚀 KataBump 自动续订')
    log(f'🖥 服务器: {SERVER_ID}')
    
    if not SERVER_ID:
        raise Exception('未设置 KATA_SERVER_ID')
    
    server_url = f'{DASHBOARD_URL}/servers/edit?id={SERVER_ID}'
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
            ]
        )
        
        context_options = {
            'viewport': {'width': 1280, 'height': 900},
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'locale': 'en-US',
            'timezone_id': 'America/New_York',
        }
        
        if PROXY_SERVER:
            context_options['proxy'] = {'server': PROXY_SERVER}
            log(f'🌐 代理: {PROXY_SERVER}')
        
        context = await browser.new_context(**context_options)
        page = await context.new_page()
        
        await page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        """)
        
        try:
            # ========== 1. 登录 ==========
            log('🔐 登录...')
            await page.goto(f'{DASHBOARD_URL}/auth/login', timeout=60000)
            await page.wait_for_timeout(2000)
            
            await page.locator('input[name="email"], input[type="email"]').fill(KATA_EMAIL)
            await page.locator('input[name="password"], input[type="password"]').fill(KATA_PASSWORD)
            await page.locator('button[type="submit"]').first.click()
            
            await page.wait_for_timeout(4000)
            
            try:
                await page.wait_for_url('**/dashboard**', timeout=15000)
            except:
                pass
            
            if '/auth/login' in page.url:
                screenshot_path = os.path.join(SCREENSHOT_DIR, 'login_failed.png')
                await page.screenshot(path=screenshot_path, full_page=True)
                tg_notify_photo(screenshot_path, '❌ 登录失败')
                raise Exception('登录失败')
            
            log('✅ 登录成功')
            
            # ========== 2. CF 预热 ==========
            await cf_warmup(page, context)
            
            # ========== 3. 服务器页面 ==========
            log('📄 打开服务器页面...')
            await page.goto(server_url, timeout=60000, wait_until='domcontentloaded')
            
            try:
                await page.locator('button[data-bs-target="#renew-modal"]').wait_for(timeout=20000)
            except:
                await page.wait_for_timeout(5000)
            
            page_content = await page.content()
            old_expiry = get_expiry_from_text(page_content) or '未知'
            days = days_until(old_expiry)
            log(f'📅 到期: {old_expiry} (剩余 {days} 天)')
            
            # ========== 4. 点击 Renew ==========
            renew_btn = page.locator('button[data-bs-target="#renew-modal"]')
            if await renew_btn.count() == 0:
                renew_btn = page.locator('button:has-text("Renew")')
            
            if await renew_btn.count() == 0:
                screenshot_path = os.path.join(SCREENSHOT_DIR, 'no_renew.png')
                await page.screenshot(path=screenshot_path, full_page=True)
                raise Exception('未找到 Renew 按钮')
            
            log('🖱 点击 Renew...')
            await renew_btn.first.click()
            await page.wait_for_timeout(2000)
            
            modal = page.locator('#renew-modal')
            try:
                await modal.wait_for(state='visible', timeout=5000)
                log('✅ 模态框打开')
            except:
                raise Exception('模态框未打开')
            
            # 等待 Turnstile 自动完成
            log('⏳ 等待 Turnstile...')
            await page.wait_for_timeout(3000)
            
            response_input = page.locator('#renew-modal input[name="cf-turnstile-response"]')
            for i in range(30):
                if await response_input.count() > 0:
                    value = await response_input.get_attribute('value') or ''
                    if len(value) > 20:
                        log(f'✅ Turnstile 通过 ({i+1}秒)')
                        break
                await page.wait_for_timeout(1000)
                if i % 5 == 4:
                    log(f'⏳ 等待中... ({i+1}秒)')
            else:
                screenshot_path = os.path.join(SCREENSHOT_DIR, 'turnstile_timeout.png')
                await page.screenshot(path=screenshot_path, full_page=True)
                if days and days <= 3:
                    tg_notify_photo(screenshot_path, f'⚠️ 需手动续订\n到期: {old_expiry}\n👉 {server_url}')
                log('❌ Turnstile 超时')
                return
            
            # ========== 5. 提交 ==========
            log('🖱 确认续订...')
            submit = page.locator('#renew-modal button[type="submit"]')
            if await submit.count() == 0:
                submit = page.locator('#renew-modal .modal-footer button.btn-primary')
            await submit.first.click()
            
            await page.wait_for_timeout(5000)
            
            # ========== 结果 ==========
            current_url = page.url
            screenshot_path = os.path.join(SCREENSHOT_DIR, 'result.png')
            await page.screenshot(path=screenshot_path, full_page=True)
            
            if 'renew=success' in current_url:
                page_content = await page.content()
                new_expiry = get_expiry_from_text(page_content) or '未知'
                log(f'🎉 成功！新到期: {new_expiry}')
                tg_notify_photo(screenshot_path, f'✅ 续订成功\n{old_expiry} → {new_expiry}')
            elif 'renew-error' in current_url:
                log('⚠️ 续订受限')
            else:
                await page.goto(server_url, timeout=60000)
                await page.wait_for_timeout(3000)
                page_content = await page.content()
                new_expiry = get_expiry_from_text(page_content) or '未知'
                
                if new_expiry > old_expiry:
                    log(f'🎉 成功！新到期: {new_expiry}')
                    tg_notify_photo(screenshot_path, f'✅ 续订成功\n{old_expiry} → {new_expiry}')
                else:
                    log(f'ℹ️ 到期: {new_expiry}')
        
        except Exception as e:
            log(f'❌ 错误: {e}')
            try:
                screenshot_path = os.path.join(SCREENSHOT_DIR, 'error.png')
                await page.screenshot(path=screenshot_path, full_page=True)
                tg_notify_photo(screenshot_path, f'❌ {e}')
            except:
                pass
            raise
        
        finally:
            await browser.close()


def main():
    log('=' * 50)
    log('   KataBump 自动续订')
    log('=' * 50)
    
    if not KATA_EMAIL or not KATA_PASSWORD or not SERVER_ID:
        log('❌ 请设置环境变量')
        sys.exit(1)
    
    log(f'📧 邮箱: {KATA_EMAIL[:3]}***')
    log(f'🖥 服务器: {SERVER_ID}')
    log(f'🌐 代理: {PROXY_SERVER or "无"}')
    
    asyncio.run(run())
    log('🏁 完成')


if __name__ == '__main__':
    main()
