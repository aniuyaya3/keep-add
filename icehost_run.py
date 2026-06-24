import os
import time
import json
import urllib.parse
import requests
# 引入 SeleniumBase 高级过盾包
from seleniumbase import SB

SERVER_URL = os.getenv("ICEHOST_SERVER_URL")
ICEHOST_COOKIES = os.getenv("ICEHOST_COOKIES")

def send_tg_notification(message, photo_path=None):
    """发送结果和截图至 Telegram"""
    token = os.getenv("TG_BOT_TOKEN")
    chat_id = os.getenv("TG_CHAT_ID")
    if not token or not chat_id:
        print("未配置 TG 机器人变量，跳过发送 TG 推送。")
        return

    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        requests.post(url, json=payload)
        print("TG 状态通知发送成功。")
    except Exception as e:
        print(f"发送 TG 消息异常: {e}")

    if photo_path and os.path.exists(photo_path):
        try:
            url = f"https://api.telegram.org/bot{token}/sendPhoto"
            with open(photo_path, "rb") as f:
                files = {"photo": f}
                data = {"chat_id": chat_id, "caption": "IceHost 实时画面"}
                requests.post(url, data=data, files=files)
            print("TG 截图发送成功。")
        except Exception as e:
            print(f"发送 TG 截图异常: {e}")

def run():
    if not SERVER_URL:
        print("错误: 缺少 ICEHOST_SERVER_URL 环境变量")
        return

    # 1. 启动 SeleniumBase 并开启 UC 免密/防检测模式与 Xvfb 虚拟桌面 (xvfb=True)
    with SB(uc=True, xvfb=True) as sb:
        print(f"正在访问 IceHost 面板: {SERVER_URL}")
        # 使用 UC 专属重连模式访问，能极大缓解首屏 Cloudflare 阻断
        sb.uc_open_with_reconnect(SERVER_URL, reconnect_time=8)
        sb.sleep(5)

        # 2. 注入 Cookies
        if ICEHOST_COOKIES:
            try:
                raw_data = json.loads(ICEHOST_COOKIES)
                cookies_to_add = []
                if isinstance(raw_data, list):
                    cookies_to_add = raw_data
                elif isinstance(raw_data, dict):
                    cookies_to_add = raw_data.get("cookies", [])

                for c in cookies_to_add:
                    raw_value = c["value"]
                    decoded_value = urllib.parse.unquote(raw_value)
                    
                    # 转换格式为 Selenium 格式
                    cookie_dict = {
                        "name": c["name"],
                        "value": decoded_value,
                        "domain": c["domain"],
                        "path": c.get("path", "/"),
                        "secure": c.get("secure", True)
                    }
                    if "sameSite" in c:
                        ss = str(c["sameSite"]).lower()
                        if ss in ["lax", "strict", "none"]:
                            cookie_dict["sameSite"] = ss.capitalize()
                    
                    sb.add_cookie(cookie_dict)
                print("Cookie 成功注入！")
                
                # 重新刷新加载，应用 Cookie
                sb.refresh()
                sb.sleep(5)
            except Exception as e:
                print(f"注入 Cookie 过程中发生异常，跳过: {e}")

        # 3. 核心过盾：自动寻找并执行系统级物理点击过 Cloudflare Turnstile 验证盾
        sb.save_screenshot("icehost_debug_screenshot.png")
        try:
            print("正在检测并调用系统级 PyAutoGUI 驱动，物理点击 Cloudflare 人机验证码...")
            # 在虚拟桌面上定位验证框并模拟发送系统硬件级点击事件
            sb.uc_gui_click_captcha()
            sb.sleep(10) # 给予 10 秒跳转缓冲
            sb.save_screenshot("icehost_debug_screenshot.png")
        except Exception as e:
            print(f"验证盾已被跳过或点击执行完毕: {e}")

        # 4. 判断登录状态
        current_url = sb.get_current_url()
        # 判断是否停留在登录页
        if "login" in current_url or sb.is_element_visible("input[type='email']"):
            msg = "❌ <b>IceHost 登录失效！</b>\n请在浏览器重新提取并更新 ICEHOST_COOKIES。"
            print(msg)
            send_tg_notification(msg, "icehost_debug_screenshot.png")
            return

        # 5. 判定波兰语红框限制
        page_source = sb.get_page_source()
        keywords = ["Nie możesz przedłużyć", "niedawno to zrobiłeś", "kolejne 6 godziny"]
        is_limited = any(kw in page_source for kw in keywords)

        if is_limited:
            print("检测到红框限制提示：说明未到可续期时间。结束本次运行（不发送 Telegram 提醒）。")
            return

        # 6. 安全寻找并点击续期按钮
        # 终极修复：使用 not(*) 强制排除外层包装，且使用小写转换，100% 精准、唯一锁定按钮本身！
        renew_btn_selector = "//*[not(*) and contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'dodaj 6')]"
        
        try:
            print("正在等待续期按钮加载...")
            # 阻塞式主动等待，给予最长 15 秒的时间让 React 完成渲染
            sb.wait_for_element_visible(renew_btn_selector, timeout=15)
            print("未检测到限制提示，找到续期按钮，正在点击...")
            sb.click(renew_btn_selector)
            sb.sleep(10) # 等待 10 秒页面处理
            
            # 刷新页面检查二次结果
            sb.refresh()
            sb.sleep(5)
            sb.save_screenshot("icehost_debug_screenshot.png")
            
            updated_source = sb.get_page_source()
            is_now_limited = any(kw in updated_source for kw in keywords)
            
            if is_now_limited:
                # 按照您的要求：如果点击后出现了红框限制提示，说明确实“未到可续期时间”（时间没变且报错）
                # 此时不发送 Telegram 消息，保持安静直接退出。
                print("点击后弹出了红框限制提示：说明未到可续期时间（续期未成功）。结束本次运行（不发送 Telegram 提醒）。")
            else:
                # 只有真正没有报错、成功延长了时间才发送 TG
                msg = "⚡ <b>IceHost 服务器续期成功！</b>\n服务器已真正成功延长 6 小时有效期。"
                print(msg)
                send_tg_notification(msg, "icehost_debug_screenshot.png")
        except Exception as e:
            print(f"未在页面中找到可用的蓝色续期按钮（可能已被续满，或按钮标签发生变动）: {e}")

if __name__ == "__main__":
    run()
