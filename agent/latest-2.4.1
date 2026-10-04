// ====== 免费住宅IP智能调度系统 (Alpine/Debian自适应 + 多服务器独立国家/端口 + 分发接口鉴权) ======
// 变更说明（v2）：
//  1. /agent 安装脚本自动辨别系统：Alpine 用 apk + OpenRC，Debian/Ubuntu 用 apt + systemd。
//  2. 多服务器独立策略：每台 VPS 按公网 IP 独立配置国家、端口、模式、手动节点、YouTube检测；未单独配置的走默认策略。
//  3. 安全修复：/scripts/* 与 /agent 纳入 Basic Auth，未登录无法下载含凭证的引擎代码；面板下发命令自动携带凭证。
// 部署：设置环境变量 WEB_USER / WEB_PASS / PROXY_USER / PROXY_PASS / PROXY_PORT，绑定 D1 为 DB。
// 注意：Worker 升级后，已部署的旧版 agent 需重新运行 /agent 安装脚本（旧 agent 读不到新配置结构）。

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;

    // --- shell 单引号转义（用于把凭证安全嵌入 bash 脚本） ---
    const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

    // --- 提取并处理云端安全隔离变量 ---
    const WEB_USER = env.WEB_USER || "admin";
    const WEB_PASS = env.WEB_PASS || "admin888";
    const PROXY_USER = env.PROXY_USER || "proxyuser";
    const PROXY_PASS = env.PROXY_PASS || "888888";
    const configuredProxyPort = env.PROXY_PORT ? parseInt(env.PROXY_PORT, 10) : 10001;
    const PROXY_PORT = Number.isInteger(configuredProxyPort) && configuredProxyPort >= 1 && configuredProxyPort <= 65535 ? configuredProxyPort : 10001;

    // ====================================================
    // [基础防御] 浏览器与安全节点 Basic Auth 鉴权函数
    // ====================================================
    const authenticate = (request) => {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(" ");
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const idx = decoded.indexOf(":");
        if (idx === -1) return false;
        const username = decoded.slice(0, idx);
        const password = decoded.slice(idx + 1);
        return username === WEB_USER && password === WEB_PASS;
      } catch (e) {
        return false;
      }
    };

    const unauthorizedResponse = () => {
      return new Response("Unauthorized Access. Scanner Blocked.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Residential Proxy Security Control"',
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    };

    // ====================================================
    // [1] 数据库建表 (D1)
    // ====================================================
    await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS servers (
          ip TEXT PRIMARY KEY,
          details TEXT,
          log TEXT DEFAULT '',
          candidates TEXT DEFAULT '[]',
          last_seen INTEGER
        )
      `).run();
    try { await env.DB.prepare(`ALTER TABLE servers ADD COLUMN log TEXT DEFAULT ''`).run(); } catch (e) {}
    try { await env.DB.prepare(`ALTER TABLE servers ADD COLUMN candidates TEXT DEFAULT '[]'`).run(); } catch (e) {}
    try { await env.DB.prepare(`ALTER TABLE servers ADD COLUMN version TEXT DEFAULT ''`).run(); } catch (e) {}
    try { await env.DB.prepare(`ALTER TABLE servers ADD COLUMN applied TEXT DEFAULT ''`).run(); } catch (e) {}

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS global_config (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `).run();

    // ====================================================
    // [2] 安全敏感接口拦截区（分发接口同样需要鉴权，防止凭证泄露）
    // ====================================================
    const PROTECTED_PATHS = ["/", "/api/config", "/api/nodes", "/api/proxies", "/api/report", "/api/switch",
      "/scripts/proxy_server.py", "/scripts/lite_manager.py", "/agent", "/uninstall"];
    if (PROTECTED_PATHS.includes(url.pathname)) {
      if (!authenticate(request)) return unauthorizedResponse();
    }

    // ====================================================
    // [3] 动态分发：Proxy Server 引擎源码
    // ====================================================
    if (url.pathname === "/scripts/proxy_server.py") {
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64
from typing import Any

PROXY_USER = b"${PROXY_USER}"
PROXY_PASS = b"${PROXY_PASS}"

def parse_int(value: Any) -> int:
    try: return int(value)
    except: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def create_connection(address: tuple[str, int], bind_interface: str, timeout: float = 20) -> socket.socket:
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored: return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data: return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)

        if b"\\x02" not in methods:
            client.sendall(b"\\x05\\xFF")
            return
        client.sendall(b"\\x05\\x02")

        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)

        if uname != PROXY_USER or upass != PROXY_PASS:
            client.sendall(b"\\x01\\x01")
            return
        client.sendall(b"\\x01\\x00")

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")

        upstream = create_connection((host, port), bind_interface, timeout=20)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\\r\\n\\r\\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\\r\\n")

        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if line.split(":", 1)[1].strip() == expected_auth:
                    auth_passed = True
                    break

        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\nProxy-Authenticate: Basic realm=\\"Proxy\\"\\r\\n\\r\\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), bind_interface, timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\\r\\n" + "\\r\\n".join(headers) + "\\r\\nConnection: close\\r\\n\\r\\n"
        upstream = create_connection((parsed.hostname, port), bind_interface, timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int], bind_interface: str) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first, bind_interface)
        else: http_client(client, first, bind_interface)
    except:
        try: client.close()
        except: pass

def start_proxy_server(host: str, port: int, bind_interface: str = "tun0") -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
    except Exception as e: return
    while True:
        try:
            client, address = server.accept()
            threading.Thread(target=proxy_client, args=(client, address, bind_interface), daemon=True).start()
        except: time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

// ====================================================
// [4] 动态分发：Lite Manager 调度引擎源码 (多服务器独立策略版)
// 每台 VPS 按自身公网 IP 匹配 servers 配置，找不到则走 defaults
// ====================================================
if (url.pathname === "/scripts/lite_manager.py") {
const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, subprocess, threading, time, urllib.request, json, sys
from pathlib import Path

MAX_CONCURRENT_NODES = 1
API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = "${domain}"
AGENT_VERSION = "2.4.1"

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"
_PORT_FILE = WORKSPACE / ".port"


def _load_saved_port(default):
    """启动时读取上次持久化的监听端口，避免配置变更触发 os._exit 重启后归零导致无限重启。"""
    try:
        p = int(_PORT_FILE.read_text().strip())
        if 1 <= p <= 65535:
            return p
    except Exception:
        pass
    return default


BASE_PROXY_PORT = _load_saved_port(${PROXY_PORT})
LOG_MAX_BYTES = 256 * 1024
REPORT_LOG_BYTES = 12 * 1024
MANAGER_LOG_FILE = WORKSPACE / "manager.log"

GOLDEN_NODES_FILE = WORKSPACE / "golden_nodes.json"
golden_nodes = {}
golden_lock = threading.Lock()

WEB_USER = "${WEB_USER}"
WEB_PASS = "${WEB_PASS}"

dynamic_slot_map = {0: "JP"}
control_mode = "auto"
manual_node_ip = ""
manual_status = ""
youtube_check_enabled = False
config_fetch_interval = 15
heartbeat_interval = 30
pool = {0: {"process": None, "ip": "", "country": "", "connected_at": 0, "connecting": False}}
pool_lock = threading.Lock()
public_ip = ""
_first_config_applied = False
_port_lock = threading.Lock()

# ---------- 模式隔离：连接代际与手动退避 ----------
_connect_epoch = 0            # 连接代际：任何使旧连接/在途拨号失效的策略变更都会递增
_epoch_lock = threading.Lock()
_manual_fail_count = 0        # 手动模式连续失败计数（退避计时用，不进自动黑名单）
_manual_next_retry_at = 0.0   # 手动模式下次允许重拨的时间戳
_manual_last_printed = ""     # 手动状态日志去重


def _bump_epoch():
    """递增连接代际。模式切换、手动节点变更、掐线等使旧连接失效的策略变更必须调用；
    旧代际的拨号线程检测到后静默退出，不触碰 pool/黑名单/状态（模式隔离的核心机制）。"""
    global _connect_epoch
    with _epoch_lock:
        _connect_epoch += 1
        return _connect_epoch


def _current_epoch():
    with _epoch_lock:
        return _connect_epoch


def _set_manual_status(s):
    """更新手动状态；日志只在状态变迁时打印（retry 倒计时每轮都变，只在进入时打印一次）。"""
    global manual_status, _manual_last_printed
    manual_status = s
    if s == _manual_last_printed:
        return
    if s.startswith("retrying:") and _manual_last_printed.startswith("retrying:"):
        return
    _manual_last_printed = s
    if "connecting" not in s and "connected" not in s:
        print(f"[-] 手动模式: {s} ({manual_node_ip or '(未选择)'})", flush=True)


def append_bounded_log(log_file, stream):
    try:
        with open(log_file, "a", buffering=1) as output:
            for line in iter(stream.readline, b""):
                output.write(line.decode("utf-8", errors="replace"))
                output.flush()
                if log_file.stat().st_size > LOG_MAX_BYTES:
                    content = log_file.read_bytes()[-LOG_MAX_BYTES // 2:]
                    log_file.write_bytes(b"[log truncated]\\n" + content)
    except:
        pass


def read_recent_log(log_file):
    try:
        return log_file.read_text(errors="replace")[-REPORT_LOG_BYTES:]
    except:
        return ""


def read_recent_logs():
    try:
        result = subprocess.run(
            ["journalctl", "-u", "proxy-lite.service", "-n", "120", "--no-pager", "-o", "short-iso"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        journal = result.stdout.decode("utf-8", errors="replace").strip()
        if journal:
            return journal[-REPORT_LOG_BYTES:]
    except:
        pass
    manager = read_recent_log(MANAGER_LOG_FILE)
    openvpn = read_recent_log(WORKSPACE / "ovpn_err_0.log")
    return (manager + "\\n" + openvpn)[-REPORT_LOG_BYTES:]


class BoundedTee:
    def __init__(self, console, log_file):
        self.console = console
        self.log_file = log_file

    def write(self, value):
        try:
            self.console.write(value)
        except UnicodeEncodeError:
            try:
                if hasattr(self.console, "buffer"):
                    self.console.buffer.write(value.encode("utf-8", errors="replace"))
                else:
                    self.console.write(value.encode("ascii", errors="replace").decode("ascii"))
            except:
                pass
        try:
            self.console.flush()
        except:
            pass
        try:
            with open(self.log_file, "a", buffering=1) as output:
                output.write(value)
            if self.log_file.stat().st_size > LOG_MAX_BYTES:
                content = self.log_file.read_bytes()[-LOG_MAX_BYTES // 2:]
                self.log_file.write_bytes(b"[log truncated]\\n" + content)
        except:
            pass

    def flush(self):
        self.console.flush()


dead_ips = {}

last_switch_timestamps = {0: 0}
global_node_reservoir = {}
reservoir_lock = threading.Lock()

_cached_snapshot = []
_last_harvest_time = 0


def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except:
        public_ip = "Unknown_IP"


def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": f"Basic {auth_ptr}"
    }


def is_ip_blacklisted(ip):
    if ip in dead_ips:
        if time.time() < dead_ips[ip]["expire_at"]:
            return True
        else:
            del dead_ips[ip]
    return False


def add_to_blacklist(ip, country, reason="fault", duration=60):
    dead_ips[ip] = {
        "country": country,
        "expire_at": time.time() + duration,
        "reason": reason
    }


def load_golden_nodes():
    global golden_nodes
    try:
        if GOLDEN_NODES_FILE.exists():
            with open(GOLDEN_NODES_FILE, 'r') as f:
                golden_nodes = json.load(f)
            print(f"[*] 成功加载，当前储备历史高质节点数: {len(golden_nodes)}", flush=True)
    except:
        pass


def save_golden_nodes():
    try:
        with open(GOLDEN_NODES_FILE, 'w') as f:
            json.dump(golden_nodes, f)
    except:
        pass


def add_golden_node(node):
    with golden_lock:
        golden_nodes[node["ip"]] = {
            "ip": node["ip"], "country": node["country"], "config": node["config"],
            "ping": node.get("ping", 9999), "added_at": time.time()
        }
    save_golden_nodes()


def remove_golden_node(ip):
    with golden_lock:
        if ip in golden_nodes:
            del golden_nodes[ip]
    save_golden_nodes()


def fetch_config():
    req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))


def apply_config(data):
    """多服务器独立策略：按本机公网 IP 匹配 servers 配置，命中则用之，否则用 defaults。"""
    global dynamic_slot_map, last_switch_timestamps, BASE_PROXY_PORT, control_mode, manual_node_ip, youtube_check_enabled, config_fetch_interval, heartbeat_interval, _first_config_applied, manual_status, _manual_fail_count, _manual_next_retry_at, _manual_last_printed
    servers_cfg = data.get("servers") or {}
    defaults_cfg = data.get("defaults") or {}
    my_cfg = servers_cfg.get(public_ip) or {}
    def pick(key, default):
        v = my_cfg.get(key, None)
        if v is None or v == "":
            v = defaults_cfg.get(key, default)
        return v
    new_port = pick("port", 10001)
    try:
        new_port = int(new_port)
    except:
        new_port = BASE_PROXY_PORT
    if not (1 <= new_port <= 65535):
        new_port = BASE_PROXY_PORT
    with _port_lock:
        port_changed = (new_port != BASE_PROXY_PORT)
        first_sync = not _first_config_applied
        if port_changed:
            if first_sync:
                print(f"[*] 启动时同步监听端口: {BASE_PROXY_PORT} -> {new_port}（首次同步，直接采用不重启）", flush=True)
            else:
                print(f"[*] 本机({public_ip})监听端口变更: {BASE_PROXY_PORT} -> {new_port}，准备重启服务...", flush=True)
            try:
                _PORT_FILE.write_text(str(new_port))
            except Exception as e:
                print(f"[!] 端口持久化失败: {e}", flush=True)
            BASE_PROXY_PORT = new_port
        _first_config_applied = True
    if port_changed and not first_sync:
        os._exit(0)
    new_mode = "manual" if pick("mode", "auto") == "manual" else "auto"
    new_manual_node_ip = str(pick("manual_node_ip", "") or "").strip()
    mode_changed = new_mode != control_mode or (new_mode == "manual" and new_manual_node_ip != manual_node_ip)
    if mode_changed:
        # 模式/手动节点变更：旧连接与其在途拨号线程即刻过期，手动退避计数清零
        _manual_fail_count = 0
        _manual_next_retry_at = 0.0
        if new_mode == "auto":
            manual_status = ""
            _manual_last_printed = ""
        else:
            _set_manual_status("waiting: 切换中…")
    control_mode = new_mode
    manual_node_ip = new_manual_node_ip
    youtube_check_enabled = pick("youtube_check", False) is True
    config_fetch_interval = max(5, min(3600, int(data.get("config_fetch_interval", 15))))
    heartbeat_interval = max(10, min(3600, int(data.get("heartbeat_interval", 30))))
    new_country = str(pick("country", "JP") or "JP").upper()
    fs_map = data.get("force_switch") or {}
    my_fs = fs_map.get(public_ip, {}) if isinstance(fs_map, dict) else {}
    force_switch = {}
    try:
        force_switch = {int(k): int(v) for k, v in my_fs.items()}
    except:
        pass
    with pool_lock:
        killed_any = False
        for slot in range(MAX_CONCURRENT_NODES):
            desired_country = new_country
            dynamic_slot_map[slot] = desired_country
            info = pool[slot]
            cmd_ts = force_switch.get(slot, 0)
            should_switch = False
            if cmd_ts > last_switch_timestamps.get(slot, 0):
                last_switch_timestamps[slot] = cmd_ts
                should_switch = True
                print("[*] ⚡ 接收到母机手动干预指令: 强制刷新单端口网络层IP！", flush=True)
            if info["process"] and info["process"].poll() is None:
                current_country = info.get("country", "")
                # 手动模式下国家策略不适用：只响应模式/手动节点变更与强制切换，避免自动逻辑掐手动的线
                country_mismatch = (control_mode == "auto" and current_country and current_country != desired_country)
                if country_mismatch or should_switch or mode_changed:
                    if not should_switch and not mode_changed:
                        print(f"[*] 策略变更触发: 需要从 {current_country} 切换到 {desired_country}，正在掐断旧连接...", flush=True)
                    # 模式切换的掐线不是故障；手动钉选的节点也不是故障：都不进自动冷却黑名单
                    pinned_manual = (control_mode == "manual" and info["ip"] and info["ip"] == manual_node_ip)
                    if info["ip"] and not pinned_manual and not mode_changed:
                        add_to_blacklist(info["ip"], info["country"], reason="manual", duration=60)
                    try:
                        info["process"].terminate()
                        info["process"].wait(timeout=2)
                    except:
                        try:
                            info["process"].kill()
                        except:
                            pass
                    info["process"] = None
                    info["ip"] = ""
                    info["country"] = ""
                    killed_any = True
        if mode_changed or killed_any:
            # 代际递增后，旧代际的在途拨号线程必定静默退出（finally 被代际保护），
            # 它们置起的 connecting 标记必须在这里回收，否则槽位永久卡死不再拨号。
            for slot in range(MAX_CONCURRENT_NODES):
                pool[slot]["connecting"] = False
            _bump_epoch()


def update_config_loop():
    while True:
        try:
            apply_config(fetch_config())
        except:
            pass
        time.sleep(config_fetch_interval)


def build_applied_info():
    """当前实际生效的配置（供面板对比“下发 vs 实际”）。"""
    return {
        "country": dynamic_slot_map.get(0, "UN"),
        "port": BASE_PROXY_PORT,
        "mode": control_mode,
        "manual_node_ip": manual_node_ip,
        "manual_status": manual_status,
    }


def c2_heartbeat_loop():
    if not public_ip or public_ip == "Unknown_IP":
        get_public_ip()
    try:
        payload = json.dumps({"ip": public_ip, "version": AGENT_VERSION, "applied": build_applied_info(), "details": [], "log": read_recent_logs()}).encode('utf-8')
        req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
        urllib.request.urlopen(req, timeout=10)
    except:
        pass
    while True:
        time.sleep(heartbeat_interval)
        if not public_ip or public_ip == "Unknown_IP":
            get_public_ip()
        details = []
        with pool_lock:
            for slot, info in pool.items():
                if info["process"] and info["process"].poll() is None:
                    uptime = time.time() - info["connected_at"]
                    if uptime > 10:
                        actual_country = info.get("country", dynamic_slot_map.get(slot, "UN"))
                        details.append({"slot": slot, "country": actual_country, "port": BASE_PROXY_PORT, "connected_time": int(uptime), "node_ip": info["ip"]})
        with reservoir_lock:
            candidates = [{"ip": n["ip"], "country": n["country"], "ping": n.get("ping", 9999)} for n in global_node_reservoir.values() if n.get("ip") and not is_ip_blacklisted(n["ip"])]
        candidates.sort(key=lambda n: n["ping"])
        payload = json.dumps({"ip": public_ip, "version": AGENT_VERSION, "applied": build_applied_info(), "details": details, "log": read_recent_logs(), "candidates": candidates[:500]}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
            print(f"[*] 成功向心跳控制塔汇报。连通率: {len(details)} / 1", flush=True)
        except:
            pass

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    sys.stdout = BoundedTee(sys.__stdout__, MANAGER_LOG_FILE)
    sys.stderr = BoundedTee(sys.__stderr__, MANAGER_LOG_FILE)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n")
        AUTH_FILE.chmod(0o600)
    load_golden_nodes()


def harvest_snapshot_nodes() -> list:
    global _cached_snapshot, _last_harvest_time
    if time.time() - _last_harvest_time < 300 and _cached_snapshot:
        return _cached_snapshot
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res:
            text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"):
            lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"):
                continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip, "ping": int(raw_ping) if raw_ping.isdigit() else 9999,
                "country": row.get("CountryShort", "").upper(),
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        if nodes:
            _cached_snapshot = nodes
            _last_harvest_time = time.time()
        return _cached_snapshot
    except:
        return _cached_snapshot


def setup_routing(slot: int):
    dev, table = f"tun{slot}", str(100 + slot)
    subprocess.run(["ip", "rule", "del", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", dev, "table", table], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", dev, "table", table], capture_output=True)


def connect_slot(slot: int, node: dict, epoch: int, is_manual: bool):
    """拨号线程。epoch=出生代际：若与当前代际不符，说明模式/策略已变更，
    必须静默退出，不得触碰 pool、黑名单与 manual_status（模式隔离的核心）。
    is_manual=True 时跳过自动模式的质量门禁（住宅鉴定/YouTube/故障冷却），
    用户钉选即最高优先级；重拨节奏由手动退避计时器控制。"""
    global manual_status, _manual_fail_count, _manual_next_retry_at
    def _stale():
        return epoch != _current_epoch()
    def _kill_proc(p):
        try:
            p.terminate()
            p.wait(timeout=2)
        except:
            try:
                p.kill()
            except:
                pass
    if _stale():
        return
    try:
        dev, cfg_path, log_file = f"tun{slot}", CONFIG_DIR / f"tun{slot}.ovpn", WORKSPACE / f"ovpn_err_{slot}.log"
        cfg_path.write_text(node["config"])
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", dev, "--dev-type", "tun", "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", "--route-nopull", "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", "--connect-timeout", "10", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
        log_file.write_text("")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        threading.Thread(target=append_bounded_log, args=(log_file, process.stdout), daemon=True).start()
        success = False
        for _ in range(25):
            time.sleep(1)
            if process.poll() is not None:
                break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True
                    break
            except:
                pass
        if _stale():
            _kill_proc(process)
            return
        if success and process.poll() is None:
            if is_manual:
                print(f"[*] 手动模式: 隧道已打通，直接采用钉选节点 {node['ip']}（跳过自动质量门禁）", flush=True)
            else:
                is_residential = True
                try:
                    print(f"[*] 单端口 ({node['country']}) 隧道初步打通，鉴定是否为纯正住宅IP...", flush=True)
                    req_url = f"https://ip.net.coffee/ip/{node['ip']}"
                    check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(check_req, timeout=10) as check_res:
                        api_resp = check_res.read().decode("utf-8").lower()
                        if "residential" in api_resp or "isp" in api_resp or "住宅" in api_resp:
                            is_residential = True
                        else:
                            clean_resp = api_resp.replace(" ", "").replace("\\n", "").replace("\\r", "")
                            if "hosting" in api_resp or "datacenter" in api_resp or "机房" in api_resp or "data center" in api_resp:
                                if '"hosting":false' not in clean_resp and '"datacenter":false' not in clean_resp:
                                    is_residential = False
                except:
                    pass
                if not is_residential:
                    is_history_golden = False
                    with golden_lock:
                        if node["ip"] in golden_nodes:
                            is_history_golden = True
                    if is_history_golden:
                        print(f"[*] 单端口 ({node['country']}) 虽为机房IP，但具备免死特权，强制放行: {node['ip']}", flush=True)
                    else:
                        print(f"[-] 单端口 ({node['country']}) 检测为机房IP，暂时隔离冷却(2小时): {node['ip']}", flush=True)
                        if _stale():
                            _kill_proc(process)
                            return
                        _kill_proc(process)
                        add_to_blacklist(node["ip"], node["country"], reason="datacenter", duration=7200)
                        return
            setup_routing(slot)
            if not is_manual and youtube_check_enabled:
                print(f"[*] 单端口 ({node['country']}) 核验通过，执行 YouTube 业务连通性测试...", flush=True)
                services_passed = True
                test_urls = ["https://www.youtube.com"]
                for test_url in test_urls:
                    res = subprocess.run(["curl", "-s", "-I", "-m", "15", "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "--interface", f"tun{slot}", test_url], capture_output=True)
                    if res.returncode != 0:
                        print(f"[-] 单端口 ({node['country']}) 访问 {test_url} 阻断/超时，临时冷却: {node['ip']}", flush=True)
                        services_passed = False
                        break
                if not services_passed:
                    if _stale():
                        _kill_proc(process)
                        return
                    _kill_proc(process)
                    add_to_blacklist(node["ip"], node["country"], reason="fault", duration=60)
                    return
            if not is_manual:
                add_golden_node(node)
            if _stale():
                _kill_proc(process)
                return
            with pool_lock:
                pool[slot]["process"] = process
                pool[slot]["ip"] = node["ip"]
                pool[slot]["country"] = node["country"]
                pool[slot]["connected_at"] = time.time()
            print(f"[+] 单端口 ({node['country']}) 优质IP完全就绪入池: {node['ip']}", flush=True)
            if is_manual:
                manual_status = f"connected: {node['ip']}"
                _manual_fail_count = 0
        else:
            _kill_proc(process)
            if is_manual:
                # 手动节点不进自动黑名单：由退避计时器控制重拨节奏，避免“cooling”卡死
                if not _stale():
                    _manual_fail_count += 1
                    wait_s = min(300, 10 * (2 ** (_manual_fail_count - 1)))
                    _manual_next_retry_at = time.time() + wait_s
                    manual_status = f"retrying: {node['ip']} 连接失败，{wait_s}s后重拨 (连续失败{_manual_fail_count}次)"
                    print(f"[-] 手动模式: {manual_status}", flush=True)
            elif not _stale():
                add_to_blacklist(node["ip"], node["country"], reason="fault", duration=60)
    finally:
        # 过期线程不得清除新代际的 connecting 标记（否则会导致重复拨号）
        with pool_lock:
            if epoch == _current_epoch():
                pool[slot]["connecting"] = False


def health_check_loop():
    global _manual_fail_count, _manual_next_retry_at, manual_status
    test_targets = [
        "http://www.gstatic.com/generate_204",
        "http://captive.apple.com/hotspot-detect.html",
        "https://www.cloudflare.com/cdn-cgi/trace",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]
    while True:
        time.sleep(60)
        slots_to_check = []
        with pool_lock:
            for slot, info in pool.items():
                if info["process"] and info["process"].poll() is None and (time.time() - info["connected_at"] > 60):
                    slots_to_check.append((slot, info["process"], info["ip"], dynamic_slot_map.get(slot, "UN")))
        for slot, process, ip, country in slots_to_check:
            failed = True
            for attempt in range(2):
                alive = False
                for target in test_targets:
                    res = subprocess.run(["curl", "-s", "-I", "-m", "10", "--interface", f"tun{slot}", target], capture_output=True)
                    if res.returncode == 0:
                        alive = True
                        break
                if alive:
                    failed = False
                    break
                time.sleep(3)
            if failed:
                print(f"[!] 单端口网络 连续多次均失败！判定掉线重拨: {ip}", flush=True)
                if control_mode == "manual" and ip and ip == manual_node_ip:
                    # 手动钉选节点：不进自动故障冷却，由退避计时器安排重拨同一节点
                    _manual_fail_count += 1
                    wait_s = min(300, 10 * (2 ** (_manual_fail_count - 1)))
                    _manual_next_retry_at = time.time() + wait_s
                    manual_status = f"retrying: {ip} 掉线，{wait_s}s后重拨 (连续失败{_manual_fail_count}次)"
                else:
                    add_to_blacklist(ip, country, reason="fault", duration=60)
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    try:
                        process.kill()
                    except:
                        pass


def maintain_pool():
    global dead_ips, global_node_reservoir, golden_nodes, manual_status
    while True:
        snapshot = harvest_snapshot_nodes()
        with reservoir_lock:
            for n in snapshot:
                global_node_reservoir[n["ip"]] = n
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips:
                global_node_reservoir.pop(ip, None)
            print(f"[*] ⚡ 蓄水池循环，当前大池常驻: {len(global_node_reservoir)} 个 (极品保留库: {len(golden_nodes)} 个)", flush=True)
        empty_slots = []
        with pool_lock:
            for slot, info in pool.items():
                if not info["connecting"] and (info["process"] is None or info["process"].poll() is not None):
                    empty_slots.append(slot)
                    info["process"] = None
                    info["ip"] = ""
                    info["country"] = ""
        if empty_slots:
            with reservoir_lock:
                all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x.get("ping", 9999))
            with golden_lock:
                all_golden_nodes = sorted(list(golden_nodes.values()), key=lambda x: x.get("ping", 9999))
            used_ips = [info["ip"] for info in pool.values() if info["ip"]]
            for slot in empty_slots:
                if control_mode == "manual":
                    # 手动模式：钉选节点不受自动黑名单（故障冷却/机房隔离）约束，
                    # 重拨节奏只由手动退避计时器控制——这就是手动与自动的隔离线。
                    if not manual_node_ip:
                        _set_manual_status("waiting: 未选择节点")
                    elif time.time() < _manual_next_retry_at:
                        remain = int(_manual_next_retry_at - time.time()) + 1
                        _set_manual_status(f"retrying: {remain}s后重拨")
                    else:
                        node = next((n for n in all_pool_nodes if n["ip"] == manual_node_ip), None)
                        if not node:
                            node = next((n for n in all_golden_nodes if n["ip"] == manual_node_ip), None)
                        if node is None:
                            _set_manual_status("waiting: 候选中无此节点")
                        elif node["ip"] in used_ips:
                            _set_manual_status("waiting: 节点已被占用")
                        else:
                            _set_manual_status(f"connecting: {node['ip']}")
                            used_ips.append(node["ip"])
                            spawn_ok = False
                            slot_epoch = _current_epoch()
                            with pool_lock:
                                if not pool[slot]["connecting"] and pool[slot]["process"] is None:
                                    pool[slot]["connecting"] = True
                                    slot_epoch = _current_epoch()
                                    spawn_ok = True
                            if spawn_ok:
                                threading.Thread(target=connect_slot, args=(slot, node, slot_epoch, True), daemon=True).start()
                            else:
                                used_ips.remove(node["ip"])
                    continue
                target_country = dynamic_slot_map.get(slot, "JP")
                candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                if not candidates:
                    golden_candidates = [n for n in all_golden_nodes if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                    if golden_candidates:
                        print(f"[*] 🏆 主池枯竭，触发！正在提取历史高质 [{target_country}] 节点...", flush=True)
                        candidates = golden_candidates
                if not candidates:
                    now_ts = time.time()
                    country_blacklisted = [ip for ip, meta in list(dead_ips.items()) if meta["country"] == target_country and now_ts < meta["expire_at"] and meta["reason"]!= "datacenter"]
                    if country_blacklisted:
                        for bip in country_blacklisted:
                            dead_ips.pop(bip, None)
                        print(f"[!] ⚡ 区域紧急熔断：[{target_country}] 储备资源彻底归零！已精准释放该区域共 {len(country_blacklisted)} 个冷却中节点提前救场！", flush=True)
                        candidates = [n for n in (all_pool_nodes + all_golden_nodes) if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                if candidates:
                    node = candidates.pop(0)
                    used_ips.append(node["ip"])
                    with pool_lock:
                        pool[slot]["connecting"] = True
                        slot_epoch = _current_epoch()
                    threading.Thread(target=connect_slot, args=(slot, node, slot_epoch, False), daemon=True).start()
                    time.sleep(0.5)
                else:
                    print("[-] 单端口: 本地中该国家可用配额彻底打空，挂起抓取...", flush=True)
        time.sleep(5)


def main():
    if os.geteuid()!= 0:
        return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", "openvpn.*tun[0-9]"], capture_output=True)
    print("========================================", flush=True)
    print(" 免费住宅IP智能调度系统 [多服务器独立策略版] 启动！", flush=True)
    print(f" 本机公网 IP: {public_ip}", flush=True)
    print("========================================", flush=True)
    threading.Thread(target=update_config_loop, daemon=True).start()
    try:
        apply_config(fetch_config())
    except:
        pass
    import proxy_server
    for i in range(MAX_CONCURRENT_NODES):
        threading.Thread(target=proxy_server.start_proxy_server, args=("0.0.0.0", BASE_PROXY_PORT, f"tun{i}"), daemon=True).start()
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()


if __name__ == "__main__":
    main()
`;
return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8"}});
}

    // ====================================================
    // [5] 动态分发：VPS 一键安装脚本（自动辨别 Alpine / Debian+OpenRC/systemd）
    // ====================================================
    if (url.pathname === "/agent") {
      const agentScript = `#!/usr/bin/env bash
set -e
echo "=========================================================="
echo "    免费住宅IP智能调度系统 直连部署 (多服务器独立策略版)"
echo "=========================================================="

# ---------- 系统自动辨别 ----------
OS="unknown"
if [ -f /etc/alpine-release ]; then
  OS="alpine"
elif [ -f /etc/debian_version ]; then
  OS="debian"
elif [ -f /etc/os-release ]; then
  . /etc/os-release
  case "$ID" in
    alpine) OS="alpine" ;;
    debian|ubuntu|raspbian|linuxmint|pop) OS="debian" ;;
    *) case "$ID_LIKE" in *debian*|*ubuntu*) OS="debian" ;; esac ;;
  esac
fi
if [ "$OS" = "unknown" ]; then
  echo "[-] 无法识别的系统，仅支持 Debian/Ubuntu 与 Alpine。"
  exit 1
fi
echo "[*] 识别到系统类型: $OS"

# ---------- 安装依赖 ----------
if [ "$OS" = "alpine" ]; then
  apk update
  apk add --no-cache openvpn python3 curl iproute2 iptables
else
  apt-get update -q
  apt-get install -y openvpn python3 curl iproute2 iptables
fi

# ---------- 拉取引擎 ----------
mkdir -p /opt/proxy_lite/configs
cd /opt/proxy_lite

C2_USER=${shq(WEB_USER)}
C2_PASS=${shq(WEB_PASS)}
echo "[1/3] 从调度中心拉取智能隔离引擎..."
for _name in lite_manager proxy_server; do
  if ! curl -sSL --user "\${C2_USER}:\${C2_PASS}" -o "\${_name}.py.new" ${domain}/scripts/\${_name}.py; then
    echo "[-] \${_name}.py 下载失败（网络或鉴权），已保留旧文件，终止部署。"
    rm -f "\${_name}.py.new"
    exit 1
  fi
  if ! head -c 32 "\${_name}.py.new" | grep -q "python3"; then
    echo "[-] \${_name}.py 内容异常（可能是鉴权失败返回的错误页面），已保留旧文件，终止部署。"
    rm -f "\${_name}.py.new"
    exit 1
  fi
  if ! grep -q "_first_config_applied" "\${_name}.py.new" && [ "\${_name}" = "lite_manager" ]; then
    echo "[-] lite_manager.py 版本过旧（缺少防重启循环修复），已保留旧文件，终止部署。"
    rm -f "\${_name}.py.new"
    exit 1
  fi
  mv -f "\${_name}.py.new" "\${_name}.py"
  echo "[*] \${_name}.py 更新成功。"
done

# ---------- 配置系统守护 ----------
echo "[2/3] 配置系统群组守护..."
if [ "$OS" = "alpine" ]; then
  rm -f /lib/systemd/system/proxy-lite.service
  cat > /etc/init.d/proxy-lite << 'EOF'
#!/sbin/openrc-run
supervisor=supervise-daemon
name="proxy-lite"
description="Residential Proxy Core Engine"
command="/usr/bin/python3"
command_args="-u /opt/proxy_lite/lite_manager.py"
directory="/opt/proxy_lite"
pidfile="/run/proxy-lite.pid"
respawn_delay=5
respawn_max=0
depend() {
  need net
}
EOF
  chmod +x /etc/init.d/proxy-lite
  rc-update add proxy-lite default >/dev/null
  rc-service proxy-lite restart
else
  rm -f /etc/init.d/proxy-lite
  cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=Residential Proxy Core Engine
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable proxy-lite.service
  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/proxy-lite.conf << 'EOF'
[Journal]
SystemMaxUse=50M
SystemMaxFileSize=10M
RuntimeMaxUse=20M
MaxRetentionSec=7day
EOF
  systemctl restart systemd-journald
  journalctl --vacuum-size=50M --vacuum-time=7d >/dev/null 2>&1 || true
  systemctl restart proxy-lite.service
fi

echo "[+] 部署成功！多服务器独立策略版已生效（$OS)。"
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [5b] 动态分发：VPS 一键卸载脚本（Alpine / Debian 自适应）
    // 清理内容：服务（systemd/OpenRC）→ 残留进程 → 策略路由/tun 接口 → crontab 残留 → /opt/proxy_lite
    // C2 面板上的机器条目会在心跳超时（2 分钟）后自动消失，无需额外注销。
    // ====================================================
    if (url.pathname === "/uninstall") {
      const uninstallScript = `#!/usr/bin/env bash
set -e
echo "=========================================================="
echo "    免费住宅IP智能调度系统 卸载程序"
echo "=========================================================="

# ---------- 系统自动辨别 ----------
OS="unknown"
if [ -f /etc/alpine-release ]; then
  OS="alpine"
elif [ -f /etc/debian_version ]; then
  OS="debian"
elif [ -f /etc/os-release ]; then
  . /etc/os-release
  case "$ID" in
    alpine) OS="alpine" ;;
    debian|ubuntu|raspbian|linuxmint|pop) OS="debian" ;;
    *) case "$ID_LIKE" in *debian*|*ubuntu*) OS="debian" ;; esac ;;
  esac
fi
echo "[*] 识别到系统类型: $OS"

# ---------- 停止并移除服务 ----------
echo "[1/5] 停止代理服务..."
if [ "$OS" = "alpine" ]; then
  rc-service proxy-lite stop 2>/dev/null || true
  rc-update del proxy-lite default 2>/dev/null || true
else
  systemctl stop proxy-lite.service 2>/dev/null || true
  systemctl disable proxy-lite.service 2>/dev/null || true
fi
# 兼容另一系统的残留文件
rm -f /etc/init.d/proxy-lite /lib/systemd/system/proxy-lite.service
rm -f /etc/systemd/journald.conf.d/proxy-lite.conf
if [ "$OS" = "debian" ]; then
  systemctl daemon-reload 2>/dev/null || true
fi

# ---------- 杀残留进程 ----------
echo "[2/5] 清理残留进程..."
pkill -f "openvpn.*tun[0-9]" 2>/dev/null || true
pkill -f "lite_manager.py" 2>/dev/null || true
sleep 2
pkill -9 -f "openvpn.*tun[0-9]" 2>/dev/null || true
pkill -9 -f "lite_manager.py" 2>/dev/null || true

# ---------- 清理策略路由与 tun 接口 ----------
echo "[3/5] 清理策略路由..."
for slot in 0 1 2 3; do
  table=$((100 + slot))
  ip rule del table $table 2>/dev/null || true
  ip route flush table $table 2>/dev/null || true
  ip link del tun$slot 2>/dev/null || true
done

# ---------- 清理定时任务残留 ----------
echo "[4/5] 清理定时任务残留..."
if crontab -l 2>/dev/null | grep -q "/opt/proxy_lite/"; then
  crontab -l 2>/dev/null | grep -v "/opt/proxy_lite/" | crontab - 2>/dev/null || true
  echo "[*] 已移除相关 crontab 条目"
fi

# ---------- 删除程序文件 ----------
echo "[5/5] 删除程序文件..."
rm -rf /opt/proxy_lite

echo ""
echo "[+] 卸载完成。"
echo "    - 面板上的该机器条目将在 2 分钟心跳超时后自动消失"
echo "    - 依赖包 (openvpn/python3/curl/iproute2/iptables) 已保留，如需删除请手动执行"
echo "=========================================================="
`;
      return new Response(uninstallScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [6] 开放API接口（国家列表保持公开）
    // ====================================================
    if (url.pathname === "/api/countries") {
        try {
            const requestedCountries = [
                "AE","AR","AT","AU","BE","BD","BG","BH","BR","CA","CH","CL","CN","CO",
                "CR","CY","CZ","DE","DK","EE","EG","ES","FI","FR","GB","GR","HK","HR",
                "HU","ID","IE","IL","IN","IQ","IR","IS","IT","JM","JO","JP","KE","KH",
                "KR","KW","KZ","LA","LB","LK","LT","LU","LV","MA","MD","MM","MN","MO",
                "MX","MY","NG","NL","NO","NP","NZ","OM","PA","PE","PH","PK","PL","PT",
                "QA","RO","RS","RU","SA","SE","SG","SI","SK","TH","TR","TW","UA","US",
                "UY","UZ","VE","VN","ZA"
            ];
            const response = await fetch("https://www.vpngate.net/api/iphone/");
            const text = await response.text();
            const lines = text.split('\n');
            const countries = new Set(requestedCountries);
            for (let i = 2; i < lines.length; i++) {
                const parts = lines[i].split(',');
                if (parts.length > 6) {
                    const country = parts[6];
                    if (country && country.length === 2 && country !== "xx" && country !== "--") countries.add(country);
                }
            }
            return new Response(JSON.stringify(Array.from(countries)), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        } catch(err) {
            return new Response(JSON.stringify(["JP", "KR", "US", "GB", "TW"]), { headers: { "Content-Type": "application/json" } });
        }
    }

    // ====================================================
    // [7] 配置接口：多服务器独立策略 + 旧版数据自动迁移
    //   servers: { "<vps公网IP>": {country, port, mode, manual_node_ip, youtube_check} }
    //   defaults: 未单独配置服务器的默认策略
    //   force_switch: { "<vps公网IP>": { "0": timestamp } }
    // ====================================================
    const readKV = async () => {
      const kv = {};
      try {
        const { results } = await env.DB.prepare(`SELECT key, value FROM global_config`).all();
        if (results) for (const row of results) kv[row.key] = row.value;
      } catch (e) {}
      return kv;
    };
    const writeKV = async (key, value) => {
      await env.DB.prepare(`
        INSERT INTO global_config (key, value) VALUES (?1, ?2)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `).bind(key, value).run();
    };
    const cleanEntry = (e) => {
      const entry = (e && typeof e === "object") ? e : {};
      const port = Number.parseInt(entry.port, 10);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("port");
      const country = String(entry.country || "JP").toUpperCase().trim();
      if (!/^[A-Z]{2}$/.test(country)) throw new Error("country");
      return {
        country,
        port,
        mode: entry.mode === "manual" ? "manual" : "auto",
        manual_node_ip: typeof entry.manual_node_ip === "string" ? entry.manual_node_ip.trim() : "",
        youtube_check: entry.youtube_check === true
      };
    };

    if (url.pathname === "/api/config" && request.method === "GET") {
        const kv = await readKV();
        let servers = {};
        let defaults = null;
        let force_switch = {};
        try { if (kv.servers_config) servers = JSON.parse(kv.servers_config) || {}; } catch (e) {}
        try { if (kv.default_config) defaults = JSON.parse(kv.default_config); } catch (e) {}
        try { if (kv.force_switch) { const fs = JSON.parse(kv.force_switch); if (fs && typeof fs === "object") force_switch = fs; } } catch (e) {}

        // 旧版单机配置自动迁移为默认策略
        if (!defaults) {
          defaults = { country: "JP", port: PROXY_PORT, mode: "auto", manual_node_ip: "", youtube_check: false };
          try {
            if (kv.slot_map) {
              const m = JSON.parse(kv.slot_map);
              const c = m[0] || m["0"];
              if (c && /^[A-Za-z]{2}$/.test(String(c))) defaults.country = String(c).toUpperCase();
            }
          } catch (e) {}
          if (kv.proxy_port) {
            const p = parseInt(kv.proxy_port, 10);
            if (Number.isInteger(p) && p >= 1 && p <= 65535) defaults.port = p;
          }
          if (kv.mode === "manual") defaults.mode = "manual";
          if (kv.manual_node_ip) defaults.manual_node_ip = kv.manual_node_ip;
          if (kv.youtube_check === "true") defaults.youtube_check = true;
        }

        const num = (v, lo, hi, dft) => {
          const n = parseInt(v, 10);
          return Number.isInteger(n) ? Math.max(lo, Math.min(hi, n)) : dft;
        };
        return new Response(JSON.stringify({
          servers, defaults, force_switch,
          config_fetch_interval: num(kv.config_fetch_interval, 5, 3600, 15),
          heartbeat_interval: num(kv.heartbeat_interval, 10, 3600, 30),
          frontend_poll_interval: num(kv.frontend_poll_interval, 5, 300, 5)
        }), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
        let data;
        try { data = await request.json(); } catch (e) { return new Response("Invalid JSON", { status: 400 }); }
        try {
          const rawServers = (data.servers && typeof data.servers === "object") ? data.servers : {};
          const servers = {};
          for (const [ip, entry] of Object.entries(rawServers)) {
            const cleanIp = String(ip).trim();
            if (!cleanIp) continue;
            servers[cleanIp] = cleanEntry(entry);
          }
          const defaults = cleanEntry(data.defaults || {});
          await writeKV("servers_config", JSON.stringify(servers));
          await writeKV("default_config", JSON.stringify(defaults));
          const num = (v, lo, hi, dft) => {
            const n = Number.parseInt(v, 10);
            return Number.isInteger(n) ? Math.max(lo, Math.min(hi, n)) : dft;
          };
          await writeKV("config_fetch_interval", String(num(data.config_fetch_interval, 5, 3600, 15)));
          await writeKV("heartbeat_interval", String(num(data.heartbeat_interval, 10, 3600, 30)));
          await writeKV("frontend_poll_interval", String(num(data.frontend_poll_interval, 5, 300, 5)));
          return new Response("OK");
        } catch (err) {
          return new Response("Invalid server entry: port must be 1-65535, country must be a 2-letter code.", { status: 400 });
        }
    }

    if (url.pathname === "/api/switch" && request.method === "POST") {
        let data;
        try { data = await request.json(); } catch (e) { return new Response("Invalid JSON", { status: 400 }); }
        const serverIp = String(data.server_ip || "").trim();
        const targetSlot = String(data.slot ?? 0);
        if (!serverIp) return new Response("missing server_ip", { status: 400 });
        const kv = await readKV();
        let force_switch = {};
        try { if (kv.force_switch) { const fs = JSON.parse(kv.force_switch); if (fs && typeof fs === "object") force_switch = fs; } } catch (e) {}
        if (!force_switch[serverIp] || typeof force_switch[serverIp] !== "object") force_switch[serverIp] = {};
        force_switch[serverIp][targetSlot] = Date.now();
        await writeKV("force_switch", JSON.stringify(force_switch));
        return new Response("OK");
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        await env.DB.prepare(`
          INSERT INTO servers (ip, details, log, candidates, version, applied, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
          ON CONFLICT(ip) DO UPDATE SET details = excluded.details, log = excluded.log, candidates = excluded.candidates, version = excluded.version, applied = excluded.applied, last_seen = excluded.last_seen
        `).bind(data.ip, JSON.stringify(data.details || []), String(data.log || '').slice(-12000), JSON.stringify(data.candidates || []).slice(0, 100000), String(data.version || ''), JSON.stringify(data.applied || {}).slice(0, 2000), Date.now()).run();
        return new Response("OK", { status: 200 });
      } catch (err) { return new Response("Error", { status: 500 }); }
    }

    if (url.pathname === "/api/proxies") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      if (results) {
        for (let server of results) {
          for (let node of JSON.parse(server.details)) {
            proxyList.push(`socks5://${PROXY_USER}:${PROXY_PASS}@${server.ip}:${node.port}#${node.country}_Port${node.port}_${node.node_ip || 'IP'}`);
          }
        }
      }
      return new Response(proxyList.join('\n'), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/api/nodes") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT * FROM servers ORDER BY last_seen DESC`).all();
       return new Response(JSON.stringify((results || []).map(server => {
         let candidates = [];
         try { candidates = JSON.parse(server.candidates || '[]'); } catch (e) {}
         return {...server, candidates};
       })), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/") {
      return new Response(DASHBOARD_HTML(domain, WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS, PROXY_PORT, shq), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const DASHBOARD_HTML = (domain, webUser, webPass, proxyUser, proxyPass, proxyPort, shq) => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>免费住宅IP智能调度系统 (多服务器独立策略版)</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex flex-col">
    <div class="max-w-[1440px] mx-auto w-full flex-grow relative px-4 md:px-6 pt-4 md:pt-6 pb-8">
        <div class="absolute -top-24 -left-24 w-72 h-72 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div class="absolute top-20 right-0 w-80 h-80 bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>

        <div class="relative flex flex-col lg:flex-row lg:justify-between lg:items-end gap-5 mb-5">
            <div>
                <div class="flex items-center gap-3 mb-3">
                    <div class="w-3 h-3 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(52,211,153,.8)] animate-pulse"></div>
                    <span class="text-xs tracking-[0.28em] uppercase text-cyan-300/80 font-semibold">Residential Edge Control</span>
                </div>
                <h1 class="text-3xl md:text-4xl font-black tracking-tight bg-gradient-to-r from-cyan-300 via-blue-400 to-violet-400 bg-clip-text text-transparent">住宅代理调度中心</h1>
                <p class="text-slate-400 mt-2 text-sm md:text-base">多服务器独立策略 · 单端口智能编排 · Alpine/Debian 自适应</p>
                <a href="/api/proxies" target="_blank" class="inline-flex items-center gap-2 mt-3 text-xs text-cyan-300 hover:text-cyan-200 transition">提取代理列表 <span class="font-mono bg-slate-900/80 border border-cyan-400/20 rounded px-2 py-1">${domain}/api/proxies</span></a>
            </div>
            <div class="flex flex-col items-end gap-2">
                <div class="glass-card p-4 rounded-2xl border border-white/10 max-w-full">
                    <p class="text-[11px] tracking-widest uppercase text-slate-500 mb-2">Provision New VPS（Debian/Ubuntu/Alpine 通用）</p>
                    <code class="text-emerald-300 text-xs md:text-sm select-all break-all">bash &lt;(curl -sSL --user ${shq(webUser + ':' + webPass)} ${domain}/agent)</code>
                    <p class="text-[11px] tracking-widest uppercase text-slate-500 mt-3 mb-2">Uninstall Agent（卸载 VPS 端，同样自适应系统）</p>
                    <code class="text-red-300/90 text-xs md:text-sm select-all break-all">bash &lt;(curl -sSL --user ${shq(webUser + ':' + webPass)} ${domain}/uninstall)</code>
                </div>
                <div class="glass-card p-3 px-4 rounded-2xl border border-white/10 w-full text-right text-xs text-slate-400">
                    <div>面板凭证 <span class="text-cyan-300 font-bold font-mono">${webUser}</span> <span class="text-slate-600">/</span> <span class="text-cyan-300 font-bold font-mono">${webPass}</span></div>
                    <div class="mt-1">代理凭证 <span class="text-amber-300 font-bold font-mono">${proxyUser}</span> <span class="text-slate-600">/</span> <span class="text-amber-300 font-bold font-mono">${proxyPass}</span></div>
                </div>
            </div>
        </div>

        <div id="machine-bar" class="sticky top-0 z-20 -mx-4 md:-mx-6 px-4 md:px-6 py-3 mb-5 bg-slate-950/85 backdrop-blur-md border-b border-white/10">
            <div class="flex items-center gap-2 flex-wrap">
                <span class="text-[11px] tracking-widest uppercase text-slate-500 mr-1">VPS 母机</span>
                <div id="machine-buttons" class="flex items-center gap-2 flex-wrap flex-1">
                    <span class="text-slate-500 text-xs">加载中...</span>
                </div>
                <button onclick="saveConfig()" class="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white px-5 py-2.5 rounded-xl text-sm font-bold shadow-lg shadow-cyan-900/30 transition">保存并下发</button>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-5 mb-5 relative">
            <div class="lg:col-span-1 glass-card p-5 rounded-2xl border border-white/10 flex flex-col min-h-[280px] max-h-[360px]">
                <div class="flex items-start justify-between mb-1">
                    <div><p class="text-[11px] tracking-widest uppercase text-slate-500">Global Pool</p><h2 class="text-xl font-bold text-slate-100 mt-1">可用国家</h2></div>
                    <span class="px-2 py-1 rounded-full text-[10px] bg-cyan-400/10 text-cyan-300 border border-cyan-400/20">LIVE</span>
                </div>
                <p class="text-xs text-slate-500 mb-4">点击国家可填入默认策略的国家输入框。</p>
                <div id="countries-list" class="flex flex-wrap gap-2 overflow-y-auto custom-scrollbar flex-grow content-start">
                    <span class="text-slate-500 text-sm">正在拉取节点数据库...</span>
                </div>
            </div>
            <div class="lg:col-span-3 glass-card p-5 rounded-2xl border border-white/10">
                <div class="mb-4">
                    <p class="text-[11px] tracking-widest uppercase text-slate-500">Policy Console</p>
                    <h2 class="text-xl font-bold text-slate-100 mt-1">连接策略控制（多服务器独立）</h2>
                    <p class="text-xs text-slate-500 mt-1">每台 VPS 按公网 IP 独立设置国家与端口；未单独配置的服务器自动走默认策略。卡片显示 <span class="text-cyan-300">下发配置</span> 与 <span class="text-emerald-300">agent 实际生效</span> 对比。</p>
                </div>
                <div class="flex flex-wrap gap-4 mb-4 bg-slate-900/60 border border-white/10 rounded-xl p-4">
                    <label class="flex flex-col gap-1">
                        <span class="text-[11px] text-slate-500">Agent 拉配置间隔（秒）</span>
                        <input type="number" id="gi-config" value="15" min="5" max="3600" class="bg-slate-800 border border-white/10 rounded-lg p-2 text-center font-bold w-32 focus:outline-none focus:border-cyan-400" />
                    </label>
                    <label class="flex flex-col gap-1">
                        <span class="text-[11px] text-slate-500">Agent 心跳间隔（秒）</span>
                        <input type="number" id="gi-heartbeat" value="30" min="10" max="3600" class="bg-slate-800 border border-white/10 rounded-lg p-2 text-center font-bold w-32 focus:outline-none focus:border-cyan-400" />
                    </label>
                    <label class="flex flex-col gap-1">
                        <span class="text-[11px] text-slate-500">面板轮询间隔（秒）</span>
                        <input type="number" id="gi-frontend" value="5" min="5" max="300" class="bg-slate-800 border border-white/10 rounded-lg p-2 text-center font-bold w-32 focus:outline-none focus:border-cyan-400" />
                    </label>
                </div>
                <div class="flex flex-col gap-4" id="config-form">
                    <span class="text-gray-500 text-sm">加载中...</span>
                </div>
            </div>
        </div>

        <div class="glass-card rounded-2xl shadow-2xl shadow-black/20 overflow-hidden border border-white/10 mb-5">
            <div class="px-4 pt-4 pb-1 flex items-center justify-between">
                <h2 class="text-lg font-bold text-slate-100">在线节点</h2>
                <span id="nodes-filter-label" class="text-xs text-slate-500"></span>
            </div>
            <table class="w-full text-left border-collapse">
                <thead>
                    <tr class="bg-white/[0.04] text-slate-400 border-b border-white/10">
                        <th class="py-3 px-4 font-semibold text-sm w-1/6">VPS 母机 IP</th>
                        <th class="py-3 px-4 font-semibold text-sm">已就绪的特优代理 (国家 | 节点IP:端口)</th>
                        <th class="py-3 px-4 font-semibold text-sm w-1/12">心跳状态</th>
                        <th class="py-3 px-4 font-semibold text-sm text-right w-1/12">在线率</th>
                    </tr>
                </thead>
                <tbody id="nodes-table" class="divide-y divide-gray-700">
                    <tr><td colspan="4" class="py-8 text-center text-gray-500">正在与调度中心数据库通信...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="bg-[#050a12] border border-white/10 rounded-2xl shadow-2xl flex flex-col h-64 relative overflow-hidden">
            <div class="bg-white/[0.04] border-b border-white/10 px-4 py-3 flex items-center justify-between">
                <div class="flex items-center gap-2">
                    <div class="w-3 h-3 rounded-full bg-red-500"></div>
                    <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
                    <div class="w-3 h-3 rounded-full bg-green-500"></div>
                    <span class="text-xs text-slate-400 ml-2 font-mono">agent 实时日志</span>
                    <span id="log-filter-label" class="text-[10px] text-slate-500 ml-2"></span>
                </div>
                <div class="text-[10px] text-green-400 font-mono animate-pulse">● 实时直播</div>
            </div>
             <div id="mock-terminal" class="hidden"></div>
             <pre id="remote-log" class="hidden p-4 overflow-y-auto flex-grow bg-black/40 text-xs text-green-300 whitespace-pre-wrap custom-scrollbar"></pre>
        </div>
    </div>

    <style>
        body { background-image: radial-gradient(circle at 20% 0%, rgba(14, 165, 233, .08), transparent 32rem), linear-gradient(135deg, #020617 0%, #0b1120 55%, #111827 100%); }
        .glass-card { background: linear-gradient(145deg, rgba(15, 23, 42, .88), rgba(15, 23, 42, .62)); box-shadow: 0 18px 60px rgba(0, 0, 0, .22), inset 0 1px rgba(255,255,255,.04); backdrop-filter: blur(16px); }
        th { letter-spacing: .08em; text-transform: uppercase; font-size: 10px !important; }
        td { border-color: rgba(255,255,255,.06) !important; }
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(15,23,42,.6); border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #155e75; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #22d3ee; }
        .srv-card { transition: box-shadow .25s, border-color .25s; }
        .srv-card.flash { border-color: rgba(34,211,238,.7) !important; box-shadow: 0 0 0 2px rgba(34,211,238,.35), 0 18px 60px rgba(0,0,0,.25); }
        .mbtn { transition: all .15s; }
        .mbtn.active { background: rgba(34,211,238,.15) !important; border-color: rgba(34,211,238,.6) !important; color: #a5f3fc !important; }
        @keyframes pulse-dot { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
        .dot-live { animation: pulse-dot 1.6s infinite; }
        @media (max-width: 640px) { table { min-width: 680px; } .glass-card { border-radius: 16px; } }
    </style>

    <script>
        const EXPECTED_AGENT = '2.4.0';
        const terminalLogs = [];
        const policyState = { servers: {}, defaults: null, intervals: { config: 15, heartbeat: 30, frontend: 5 }, known: new Map() };
        const manualIps = new Set();
        let selectedMachine = 'all';
        let lastNodes = [];

        function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
        function sidOf(ip) { return ip === '__default__' ? 'default' : String(ip).replace(/[^a-zA-Z0-9]/g, '_'); }
        function ago(ts) { const s = Math.max(0, Math.floor((Date.now() - ts) / 1000)); return s < 60 ? s + 's 前' : Math.floor(s / 60) + 'm 前'; }
        function isOnline(ts) { return Date.now() - ts < 45000; }

        function pushLog(msg, type="INFO") {
            const term = document.getElementById('mock-terminal');
            if (!term) return;
            const now = new Date();
            const timeStr = now.getHours().toString().padStart(2, '0') + ':' +
                            now.getMinutes().toString().padStart(2, '0') + ':' +
                            now.getSeconds().toString().padStart(2, '0');
            let color = 'text-gray-300';
            if(type === 'WARN') color = 'text-yellow-400';
            if(type === 'ERR') color = 'text-red-400';
            if(type === 'SUCCESS') color = 'text-green-400';
            if(type === 'SYS') color = 'text-blue-300';
            terminalLogs.push(\`<span class="text-gray-500">[\${timeStr}]</span> <span class="\${color}">[\${type}] \${msg}</span>\`);
            if(terminalLogs.length > 50) terminalLogs.shift();
            term.innerHTML = terminalLogs.join('<br>');
            term.scrollTop = term.scrollHeight;
        }

        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const container = document.getElementById('countries-list');
                list.sort();
                container.innerHTML = list.map(c => \`<span class="bg-gray-700 px-2 py-1 rounded text-xs font-bold text-gray-300 border border-gray-600 cursor-pointer hover:bg-gray-600 transition" onclick="var el=document.getElementById('country-default'); if(el) el.value='\${c}'">\${c}</span>\`).join('');
            } catch(e) {}
        }

        // ================= 机器选择栏 =================
        function machineStatus(ip) {
            const meta = policyState.known.get(ip);
            if (!meta) return { cls: 'bg-slate-500', label: '未上报' };
            if (isOnline(meta.last_seen)) return { cls: 'bg-emerald-400 dot-live', label: '在线' };
            return { cls: 'bg-yellow-400', label: '心跳超时' };
        }

        function renderMachineBar() {
            const box = document.getElementById('machine-buttons');
            const ips = [...policyState.known.keys()].sort();
            let html = \`<button data-m="all" onclick="selectMachine('all')" class="mbtn \${selectedMachine === 'all' ? 'active' : ''} px-3 py-2 rounded-xl text-xs font-bold bg-white/5 border border-white/10 text-slate-300 hover:bg-white/10">全部</button>\`;
            for (const ip of ips) {
                const st = machineStatus(ip);
                const meta = policyState.known.get(ip);
                let ap = {};
                try { ap = JSON.parse(meta.applied || '{}'); } catch(e) {}
                const sub = ap.port ? \`\${esc(ap.country || '--')}:\${esc(ap.port)}\` : '—';
                html += \`<button data-m="\${esc(ip)}" onclick="selectMachine('\${esc(ip)}')" title="\${st.label} · \${ago(meta.last_seen)}"
                    class="mbtn \${selectedMachine === ip ? 'active' : ''} px-3 py-2 rounded-xl text-xs font-mono bg-white/5 border border-white/10 text-slate-300 hover:bg-white/10 flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full \${st.cls}"></span>\${esc(ip)}<span class="text-slate-500">\${sub}</span>
                </button>\`;
            }
            if (!ips.length) html += '<span class="text-slate-500 text-xs">暂无上报机器，请在 VPS 运行顶部命令接入</span>';
            box.innerHTML = html;
        }

        function selectMachine(ip) {
            selectedMachine = ip;
            renderMachineBar();
            renderTable();
            renderLogs();
            if (ip !== 'all') {
                const card = document.querySelector('[data-server-card="' + ip + '"]');
                if (card) {
                    if (card.scrollIntoView) card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    card.classList.add('flash');
                    setTimeout(() => card.classList.remove('flash'), 1600);
                }
            }
            const label = ip === 'all' ? '' : '当前：' + ip;
            document.getElementById('nodes-filter-label').textContent = label;
            document.getElementById('log-filter-label').textContent = label;
        }

        // ================= 策略卡片 =================
        function effectiveConfig(ip) {
            if (ip === '__default__') return policyState.defaults;
            return policyState.servers[ip] || policyState.defaults;
        }

        function appliedOf(ip) {
            const meta = policyState.known.get(ip);
            if (!meta || !meta.applied) return null;
            try { return JSON.parse(meta.applied); } catch(e) { return null; }
        }

        function statusHTML(ip, isDefault) {
            if (isDefault) return '<span class="text-[11px] text-violet-300/80">未单独配置的服务器自动使用此策略</span>';
            const meta = policyState.known.get(ip);
            const eff = effectiveConfig(ip) || {};
            const ap = appliedOf(ip);
            const ver = meta && meta.version ? meta.version : '';
            let verBadge;
            if (!meta) verBadge = '<span class="px-2 py-0.5 rounded-full text-[10px] bg-slate-500/15 text-slate-400 border border-white/10">未上报</span>';
            else if (ver === EXPECTED_AGENT) verBadge = '<span class="px-2 py-0.5 rounded-full text-[10px] bg-emerald-400/10 text-emerald-300 border border-emerald-400/30">agent v' + esc(ver) + '</span>';
            else verBadge = '<span class="px-2 py-0.5 rounded-full text-[10px] bg-amber-400/10 text-amber-300 border border-amber-400/30" title="旧版 agent 不支持独立策略/状态上报，请重跑 /agent">旧版 v' + esc(ver || '?') + ' 请升级</span>';
            const hb = meta ? '<span class="text-[11px] text-slate-500">心跳 ' + ago(meta.last_seen) + '</span>' : '<span class="text-[11px] text-slate-500">手动添加，等待上报</span>';
            let cmp;
            if (!ap || !ap.port) {
                cmp = '<span class="text-[11px] text-slate-500">实际：等待 agent 上报…</span>';
            } else {
                const same = String(eff.country).toUpperCase() === String(ap.country).toUpperCase() && Number(eff.port) === Number(ap.port) && eff.mode === ap.mode;
                cmp = '<span class="text-[11px] text-slate-400">实际：<span class="font-mono text-slate-200">' + esc(ap.country) + ':' + esc(ap.port) + ' ' + esc(ap.mode) + '</span></span> ' +
                    (same ? '<span class="text-[11px] text-emerald-300">✓ 已生效</span>' : '<span class="text-[11px] text-amber-300">⚠️ 与下发不一致</span>');
            }
            let manualLine = '';
            if (eff.mode === 'manual') {
                const ms = (ap && ap.manual_status) ? ap.manual_status : '等待上报…';
                const mcls = ms.indexOf('connected') === 0 ? 'text-emerald-300' : (ms.indexOf('cooling') === 0 || ms.indexOf('waiting') === 0 ? 'text-amber-300' : 'text-slate-400');
                manualLine = '<div class="mt-1 text-[11px] ' + mcls + '">手动状态：' + esc(ms) + '</div>';
            }
            return '<div class="flex items-center gap-2 flex-wrap">' + verBadge + hb + '</div>' +
                '<div class="mt-1.5 text-[11px] text-slate-400">下发：<span class="font-mono text-cyan-300">' + esc(eff.country) + ':' + esc(eff.port) + ' ' + esc(eff.mode) + '</span></div>' +
                '<div class="mt-0.5">' + cmp + '</div>' + manualLine;
        }

        function policyCardHTML(ip, cfg, meta, isDefault) {
            const sid = sidOf(ip);
            const title = isDefault ? '默认策略' : ip;
            const st = isDefault ? null : machineStatus(ip);
            const dot = isDefault ? '<span class="w-2.5 h-2.5 rounded-full bg-violet-400"></span>'
                : '<span class="w-2.5 h-2.5 rounded-full ' + (st ? st.cls : 'bg-slate-500') + '"></span>';
            let body;
            if (!isDefault && !cfg) {
                body = \`<div class="flex items-center justify-between gap-3">
                    <span class="text-xs text-slate-500">当前跟随默认策略</span>
                    <button onclick="enableIndependent('\${esc(ip)}')" class="text-xs px-3 py-2 rounded-lg bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 hover:bg-cyan-500/25 transition">设为独立配置</button>
                </div>\`;
            } else {
                const c = cfg;
                const cands = (meta && meta.candidates) || [];
                const candOpts = cands.map(n => \`<option value="\${esc(n.ip)}">\${esc(n.country || '--')} | \${esc(n.ip)} | \${n.ping == null ? '?' : n.ping} ms</option>\`).join('');
                const selManual = c.manual_node_ip ? \` data-sel="\${esc(c.manual_node_ip)}"\` : '';
                body = \`
                <div class="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
                    <label class="flex flex-col gap-1">
                        <span class="text-[11px] text-slate-500">国家/地区</span>
                        <input id="country-\${sid}" value="\${esc(c.country || 'JP')}" maxlength="2" class="bg-slate-800 border border-white/10 rounded-lg p-2 text-center font-bold uppercase focus:outline-none focus:border-cyan-400" />
                    </label>
                    <label class="flex flex-col gap-1">
                        <span class="text-[11px] text-slate-500">代理端口</span>
                        <input id="port-\${sid}" type="number" value="\${esc(c.port || 10001)}" min="1" max="65535" class="bg-slate-800 border border-white/10 rounded-lg p-2 text-center font-bold focus:outline-none focus:border-cyan-400" />
                    </label>
                    <label class="flex flex-col gap-1">
                        <span class="text-[11px] text-slate-500">连接模式</span>
                        <select id="mode-\${sid}" onchange="toggleManualModes()" class="bg-slate-800 border border-white/10 rounded-lg p-2 font-bold focus:outline-none focus:border-cyan-400">
                            <option value="auto" \${c.mode === 'manual' ? '' : 'selected'}>自动连接</option>
                            <option value="manual" \${c.mode === 'manual' ? 'selected' : ''}>手动选择</option>
                        </select>
                    </label>
                    <label class="flex flex-col gap-1 col-span-2 md:col-span-3 xl:col-span-3">
                        <span class="text-[11px] text-slate-500">手动节点 <button type="button" onclick="refreshCandidates('\${esc(ip)}')" class="ml-1 text-cyan-300 hover:text-cyan-200 underline">刷新候选</button></span>
                        <select id="manual-\${sid}"\${selManual} class="bg-slate-800 border border-white/10 rounded-lg p-2 font-mono text-xs focus:outline-none focus:border-cyan-400">
                            <option value="">请选择可用节点</option>
                            \${candOpts}
                        </select>
                    </label>
                </div>
                <div class="flex flex-wrap items-center gap-3 mt-3">
                    <label class="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
                        <input type="checkbox" id="yt-\${sid}" \${c.youtube_check ? 'checked' : ''} class="w-4 h-4 accent-cyan-400" />
                        YouTube 可用检测
                    </label>
                    <div class="flex-1"></div>
                    \${isDefault ? '' : \`<button onclick="forceSwitchIP('\${esc(ip)}')" title="强制刷新该服务器当前节点 IP" class="text-xs px-3 py-2 rounded-lg bg-red-500/10 text-red-300 border border-red-400/30 hover:bg-red-500/20 transition">⚡ 强制换 IP</button>\`}
                    \${isDefault ? '' : \`<button onclick="removeServerCard('\${esc(ip)}')" class="text-xs px-3 py-2 rounded-lg bg-white/5 text-slate-400 border border-white/10 hover:bg-white/10 transition">删除独立配置</button>\`}
                </div>\`;
            }
            return \`<div data-server-card="\${esc(ip)}" data-sid="\${sid}" class="srv-card bg-slate-900/60 border \${isDefault ? 'border-violet-400/30' : 'border-white/10'} rounded-2xl p-4">
                <div class="flex items-center gap-2 mb-2">\${dot}<div class="font-mono font-bold \${isDefault ? 'text-violet-300' : 'text-cyan-300'}">\${esc(title)}</div></div>
                <div class="card-status mb-3" data-status-for="\${esc(ip)}">\${statusHTML(ip, isDefault)}</div>
                \${body}
            </div>\`;
        }

        function renderPolicyCards() {
            const c = document.getElementById('config-form');
            const { servers, defaults, known } = policyState;
            const dft = defaults || { country: 'JP', port: 10001, mode: 'auto', manual_node_ip: '', youtube_check: false };
            let html = policyCardHTML('__default__', dft, null, true);
            const rendered = new Set();
            for (const ip of Object.keys(servers)) {
                html += policyCardHTML(ip, servers[ip], known.get(ip) || null, false);
                rendered.add(ip);
            }
            for (const ip of known.keys()) {
                if (!rendered.has(ip)) { html += policyCardHTML(ip, null, known.get(ip), false); rendered.add(ip); }
            }
            for (const ip of manualIps) {
                if (!rendered.has(ip) && !known.has(ip)) {
                    html += policyCardHTML(ip, Object.assign({}, dft), null, false);
                    rendered.add(ip);
                }
            }
            html += \`<div class="flex gap-2 items-center bg-slate-900/60 border border-dashed border-white/15 rounded-2xl p-4">
                <input id="add-server-ip" placeholder="输入 VPS 公网 IP，提前为其配置独立策略" class="bg-slate-800 border border-white/10 rounded-lg p-2 font-mono text-sm flex-1 focus:outline-none focus:border-cyan-400" />
                <button onclick="addServerCard()" class="text-xs px-4 py-2 rounded-lg bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 hover:bg-cyan-500/25 transition whitespace-nowrap">+ 添加服务器</button>
            </div>\`;
            c.innerHTML = html;
            document.querySelectorAll('select[id^="manual-"][data-sel]').forEach(sel => {
                const v = sel.getAttribute('data-sel');
                if (v && Array.from(sel.options).some(o => o.value === v)) sel.value = v;
                sel.removeAttribute('data-sel');
            });
            toggleManualModes();
        }

        // 重渲染前先把用户已填的值同步回 state，避免未保存的修改丢失
        function syncPolicyStateFromDOM() {
            document.querySelectorAll('[data-server-card]').forEach(card => {
                const ip = card.getAttribute('data-server-card');
                const sid = card.getAttribute('data-sid');
                const countryEl = document.getElementById('country-' + sid);
                if (!countryEl) return;
                const entry = {
                    country: (countryEl.value || 'JP').toUpperCase().trim(),
                    port: Number.parseInt(document.getElementById('port-' + sid).value, 10) || 10001,
                    mode: document.getElementById('mode-' + sid).value,
                    manual_node_ip: document.getElementById('manual-' + sid).value,
                    youtube_check: document.getElementById('yt-' + sid).checked
                };
                if (ip === '__default__') policyState.defaults = entry;
                else policyState.servers[ip] = entry;
            });
            const num = (id, dft) => { const v = Number.parseInt(document.getElementById(id).value, 10); return Number.isInteger(v) ? v : dft; };
            policyState.intervals = { config: num('gi-config', 15), heartbeat: num('gi-heartbeat', 30), frontend: num('gi-frontend', 5) };
        }

        function updateCardStatus() {
            document.querySelectorAll('.card-status').forEach(el => {
                const ip = el.getAttribute('data-status-for');
                const card = el.closest('[data-server-card]');
                const isDefault = card && card.getAttribute('data-server-card') === '__default__';
                el.innerHTML = statusHTML(ip, isDefault);
            });
        }

        function enableIndependent(ip) {
            syncPolicyStateFromDOM();
            const dft = policyState.defaults || { country: 'JP', port: 10001, mode: 'auto', manual_node_ip: '', youtube_check: false };
            policyState.servers[ip] = Object.assign({}, dft);
            renderPolicyCards();
        }

        function removeServerCard(ip) {
            syncPolicyStateFromDOM();
            delete policyState.servers[ip];
            manualIps.delete(ip);
            renderPolicyCards();
        }

        function addServerCard() {
            const el = document.getElementById('add-server-ip');
            const ip = (el.value || '').trim();
            if (!ip) { alert('请输入 VPS 公网 IP'); return; }
            syncPolicyStateFromDOM();
            manualIps.add(ip);
            enableIndependent(ip);
        }

        async function refreshCandidates(ip) {
            try {
                const res = await fetch('/api/nodes');
                const servers = await res.json();
                const s = (servers || []).find(x => x.ip === ip);
                if (!s) { alert('该机器暂无上报数据'); return; }
                let cands = [];
                try { cands = JSON.parse(s.candidates || '[]'); } catch(e) {}
                const meta = policyState.known.get(ip) || { ip: ip, last_seen: 0, candidates: [] };
                meta.candidates = cands;
                policyState.known.set(ip, meta);
                const sid = sidOf(ip);
                const sel = document.getElementById('manual-' + sid);
                if (sel) {
                    const cur = sel.value;
                    sel.innerHTML = '<option value="">请选择可用节点</option>' + cands.map(n =>
                        \`<option value="\${esc(n.ip)}">\${esc(n.country || '--')} | \${esc(n.ip)} | \${n.ping == null ? '?' : n.ping} ms</option>\`).join('');
                    if (cur && Array.from(sel.options).some(o => o.value === cur)) sel.value = cur;
                }
                pushLog('已刷新 ' + ip + ' 的候选节点（' + cands.length + ' 个）', 'SYS');
            } catch(e) { alert('刷新失败'); }
        }

        function toggleManualModes() {
            document.querySelectorAll('[data-server-card]').forEach(card => {
                const sid = card.getAttribute('data-sid');
                const mode = document.getElementById('mode-' + sid);
                const node = document.getElementById('manual-' + sid);
                if (!mode || !node) return;
                node.disabled = mode.value !== 'manual';
                node.classList.toggle('opacity-50', node.disabled);
            });
        }

async function initPolicyConsole() {
try {
const [cfgRes, nodesRes] = await Promise.all([fetch('/api/config'), fetch('/api/nodes')]);
const cfg = await cfgRes.json();
let nodes = [];
try { nodes = await nodesRes.json();} catch (e) {}
policyState.servers = (cfg.servers && typeof cfg.servers === 'object')? cfg.servers: {};
policyState.defaults = cfg.defaults || null;
policyState.intervals = {
config: cfg.config_fetch_interval || 15,
heartbeat: cfg.heartbeat_interval || 30,
frontend: cfg.frontend_poll_interval || 5
};
ingestNodes(nodes);
document.getElementById('gi-config').value = policyState.intervals.config;
document.getElementById('gi-heartbeat').value = policyState.intervals.heartbeat;
document.getElementById('gi-frontend').value = policyState.intervals.frontend;
renderPolicyCards();
renderMachineBar();
} catch (e) {
document.getElementById('config-form').innerHTML = '<span class="text-red-400 text-sm">策略加载失败，请检查 Worker 与 D1 是否正常</span>';
}
}

function ingestNodes(nodes) {
policyState.known = new Map();
for (const s of (nodes || [])) {
let cands = [];
try { cands = s.candidates || []; if (typeof cands === 'string') cands = JSON.parse(cands);} catch(e) { cands = [];}
policyState.known.set(s.ip, {
ip: s.ip, last_seen: s.last_seen, candidates: cands,
version: s.version || '', applied: s.applied || '',
details: s.details || '[]', log: s.log || ''
});
}
lastNodes = nodes || [];
}

async function saveConfig() {
syncPolicyStateFromDOM();
const servers = policyState.servers;
const defaults = policyState.defaults;
try {
for (const [ip, e] of Object.entries(servers)) {
if (!Number.isInteger(e.port) || e.port < 1 || e.port > 65535) throw new Error('服务器 ' + ip + '：端口必须是 1-65535 的整数');
if (!/^[A-Z]{2}$/.test(e.country)) throw new Error('服务器 ' + ip + '：国家代码必须是 2 位字母');
if (e.mode === 'manual' &&!e.manual_node_ip) throw new Error('服务器 ' + ip + '：手动模式必须选择一个节点');
}
if (!Number.isInteger(defaults.port) || defaults.port < 1 || defaults.port > 65535) throw new Error('默认策略：端口必须是 1-65535 的整数');
if (!/^[A-Z]{2}$/.test(defaults.country)) throw new Error('默认策略：国家代码必须是 2 位字母');
if (defaults.mode === 'manual' &&!defaults.manual_node_ip) throw new Error('默认策略：手动模式必须选择一个节点');
} catch (err) {
alert(err.message || err);
return;
}
const res = await fetch('/api/config', {
method: 'POST',
headers: { 'Content-Type': 'application/json'},
body: JSON.stringify({
servers: servers,
defaults: defaults,
config_fetch_interval: policyState.intervals.config,
heartbeat_interval: policyState.intervals.heartbeat,
frontend_poll_interval: policyState.intervals.frontend
})
});
if (!res.ok) {
const t = await res.text().catch(() => '');
alert('配置保存失败：' + t);
return;
}
pushLog('[控制中心广播] 多服务器独立策略已下发，agent 将在 ' + policyState.intervals.config + 's 内生效。', 'SYS');
alert('配置已下发，agent 拉取后生效（端口变更会自动重启 agent）。可在卡片上对比“下发 vs 实际”确认。');
restartNodePolling(policyState.intervals.frontend);
}

async function forceSwitchIP(ip) {
if (!confirm('确认要强行断开并刷新当前的节点 IP 吗？\\n(该IP仅会进入 1 分钟临时冷却，不会被从池中删除。)')) return;
try {
const res = await fetch('/api/switch', {
method: 'POST',
headers: { 'Content-Type': 'application/json'},
body: JSON.stringify({ server_ip: ip, slot: 0})
});
if (res.ok) {
pushLog('[指令下达] 已向 ' + ip + ' 发送手动熔断强杀指令', 'WARN');
alert('⚡ 指令下达成功！\\nVPS 监控引擎已收到杀机指令。');
} else {
alert('网络指令下发失败，请重试');
}
} catch (e) {
alert('网络指令下发异常');
}
}

let nodePollingTimer;
function restartNodePolling(seconds) {
if (nodePollingTimer) clearInterval(nodePollingTimer);
nodePollingTimer = setInterval(fetchNodes, seconds * 1000);
}

async function fetchNodes() {
try {
const res = await fetch('/api/nodes');
const servers = await res.json();
ingestNodes(servers);
renderMachineBar();
renderTable();
renderLogs();
updateCardStatus();

(servers || []).forEach(s => {
if (Math.random() > 0.6) {
const dList = JSON.parse(s.details || '[]');
const evtRand = Math.random();
if (evtRand > 0.8) {
pushLog(\`节点 [\${s.ip}] 心跳数据已同步，当前健康存活链路: \${dList.length}/1\`, 'SUCCESS');
} else if (evtRand > 0.5 && dList.length < 1) {
pushLog(\`节点 [\${s.ip}] 正在从黄金储备池中提取“免死金牌”极品节点...\`, 'INFO');
} else if (evtRand > 0.3) {
pushLog(\`节点 [\${s.ip}] 路由表重组完成，黄金历史节点已豁免下发。\`, 'SYS');
}
}
});
} catch (err) {}
}

function visibleServers() {
if (selectedMachine === 'all') return lastNodes;
return lastNodes.filter(s => s.ip === selectedMachine);
}

function renderTable() {
const tbody = document.getElementById('nodes-table');
const servers = visibleServers();
if (!servers || servers.length === 0) {
tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-gray-500">' +
(selectedMachine === 'all'? '当前没有被纳管的机器，请在 VPS 运行顶部命令接入': '该机器暂无上报数据') + '</td></tr>';
return;
}
tbody.innerHTML = servers.map(server => {
const details = JSON.parse(server.details || '[]');
const timeAgo = ago(server.last_seen);
details.sort((a,b) => a.port - b.port);
let proxyBadges = details.map(d =>
\`<div class="inline-flex items-center bg-gray-700 border border-gray-600 rounded px-2 py-1 mr-2 mb-2 text-xs">
<span class="text-blue-400 font-bold mr-2">\${d.country}</span>
<span class="font-mono text-blue-200 mr-2" title="节点物理IP">\${d.node_ip || '分配中...'}:\${d.port}</span>
</div>\`
).join('');
if (details.length === 0) proxyBadges = '<span class="text-yellow-500 text-xs">高容错极速调度中... 正在建立单端口稳定网络...</span>';
return \`
<tr class="hover:bg-gray-750 transition-colors">
<td class="py-4 px-4 font-mono text-lg text-blue-300 align-top">\${server.ip}</td>
<td class="py-4 px-4 align-top">\${proxyBadges}</td>
<td class="py-4 px-4 text-gray-400 align-top">\${timeAgo}</td>
<td class="py-4 px-4 align-top text-right">
<span class="\${details.length === 1? 'bg-green-900 text-green-300': 'bg-yellow-900 text-yellow-300'} py-1 px-3 rounded-full text-xs font-bold">\${details.length} / 1</span>
</td>
</tr>
\`;
}).join('');
}

function renderLogs() {
const servers = visibleServers();
const log = servers.map(server => {
const text = String(server.log || '').trim();
return text? \`===== \${server.ip} =====\\n\${text}\`: '';
}).filter(Boolean).join('\\n');
const remoteLog = document.getElementById('remote-log');
if (log) {
remoteLog.textContent = log.slice(-24000);
remoteLog.classList.remove('hidden');
} else {
remoteLog.classList.add('hidden');
}
}

fetchCountries();
initPolicyConsole();
fetchNodes();
fetch('/api/config').then(res => res.json()).then(config => restartNodePolling(config.frontend_poll_interval || 5)).catch(() => restartNodePolling(5));
</script>
</body>
</html>
`;
