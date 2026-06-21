// ====== Proxy Controller (Active-Standby Multi-Tunnel + Verified Independent Per-VPS Policy) ======

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;

    // --- 提取并处理云端安全隔离变量 ---
    const WEB_USER = env.WEB_USER || "admin";        
    const WEB_PASS = env.WEB_PASS || "admin888";     
    const PROXY_USER = env.PROXY_USER || "proxy";    
    const PROXY_PASS = env.PROXY_PASS || "888888";   

    const authenticate = (request) => {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(" ");
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const [username, password] = decoded.split(":");
        return username === WEB_USER && password === WEB_PASS;
      } catch (e) {
        return false;
      }
    };

    const unauthorizedResponse = () => {
      return new Response("Unauthorized Access. Scanner Blocked.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Proxy System Security Control"',
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    };

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS servers (
        ip TEXT PRIMARY KEY,
        details TEXT,
        last_seen INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS server_logs (
        ip TEXT PRIMARY KEY,
        logs TEXT,
        updated_at INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS global_config (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS server_configs (
        ip TEXT PRIMARY KEY,
        value TEXT,
        updated_at INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS server_runtime (
        ip TEXT PRIMARY KEY,
        status TEXT,
        updated_at INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS server_identity (
        ip TEXT PRIMARY KEY,
        agent_id TEXT,
        hostname TEXT,
        first_seen INTEGER,
        updated_at INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS policy_targets (
        target TEXT PRIMARY KEY,
        ip TEXT,
        agent_id TEXT,
        value TEXT,
        updated_at INTEGER
      )
    `).run();

    const DEFAULT_CONFIG = { "0": "JP", "port": 7920, "switch_trigger": 0, "generation": 0 };

    const normalizeIp = (ip) => String(ip || "").trim().replace(/^::ffff:/, "");
    const normalizeAgentId = (id) => String(id || "").trim().replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 128);

    const normalizePolicyTarget = (target) => {
      const raw = String(target || "").trim();
      if (!raw) return "";
      if (raw.startsWith("id:")) {
        const id = normalizeAgentId(raw.slice(3));
        return id ? `id:${id}` : "";
      }
      if (raw.startsWith("ip:")) {
        const ip = normalizeIp(raw.slice(3));
        return ip ? `ip:${ip}` : "";
      }
      return "";
    };

    const buildPolicyTargets = (data = {}) => {
      const out = [];
      const explicit = normalizePolicyTarget(data.target || data.policy_target || "");
      if (explicit) out.push(explicit);
      const agentId = normalizeAgentId(data.agent_id || data.id || "");
      const ip = normalizeIp(data.ip || "");
      if (agentId) out.push(`id:${agentId}`);
      if (ip) out.push(`ip:${ip}`);
      return [...new Set(out)];
    };

    const parseConfigValue = (raw) => {
      if (!raw) return null;
      try {
        const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
        return parsed && typeof parsed === "object" ? parsed : null;
      } catch (err) {
        return null;
      }
    };

    const sanitizeConfig = (data = {}, base = DEFAULT_CONFIG) => {
      const source = data || {};
      const fallback = base || DEFAULT_CONFIG;
      const countryRaw = source["0"] !== undefined ? source["0"] : (fallback["0"] || DEFAULT_CONFIG["0"]);
      let country = String(countryRaw || "JP").trim().toUpperCase();
      if (!country) country = "JP";
      if (country.length > 2) country = country.slice(0, 2);

      let port = parseInt(source.port !== undefined ? source.port : (fallback.port || DEFAULT_CONFIG.port), 10);
      if (!Number.isFinite(port) || port < 1 || port > 65535) port = DEFAULT_CONFIG.port;

      const switchRaw = source.switch_trigger !== undefined ? source.switch_trigger : (fallback.switch_trigger || 0);
      const switchTrigger = Number(switchRaw || 0);
      const generationRaw = source.generation !== undefined ? source.generation : (fallback.generation || 0);
      const generation = Number(generationRaw || 0);

      return {
        "0": country,
        "port": port,
        "switch_trigger": Number.isFinite(switchTrigger) && switchTrigger > 0 ? Math.floor(switchTrigger) : 0,
        "generation": Number.isFinite(generation) && generation > 0 ? Math.floor(generation) : 0
      };
    };

    const getGlobalConfig = async () => {
      const { results } = await env.DB.prepare(`SELECT value FROM global_config WHERE key = 'slot_map'`).all();
      if (results && results.length > 0) {
        const parsed = parseConfigValue(results[0].value);
        if (parsed) return sanitizeConfig(parsed, DEFAULT_CONFIG);
      }
      return { ...DEFAULT_CONFIG };
    };

    const getPolicyRecordByTarget = async (target) => {
      const normalized = normalizePolicyTarget(target);
      if (!normalized) return null;
      const { results } = await env.DB.prepare(`SELECT target, ip, agent_id, value, updated_at FROM policy_targets WHERE target = ?1`).bind(normalized).all();
      if (results && results.length > 0) {
        const parsed = parseConfigValue(results[0].value);
        if (parsed) return { ...results[0], config: sanitizeConfig(parsed, DEFAULT_CONFIG), source: "policy_targets" };
      }
      return null;
    };

    const getLegacyServerOverride = async (ip) => {
      const normalized = normalizeIp(ip);
      if (!normalized) return null;
      const { results } = await env.DB.prepare(`SELECT value, updated_at FROM server_configs WHERE ip = ?1`).bind(normalized).all();
      if (results && results.length > 0) {
        const parsed = parseConfigValue(results[0].value);
        if (parsed) return { target: `ip:${normalized}`, ip: normalized, agent_id: "", updated_at: results[0].updated_at || 0, config: sanitizeConfig(parsed, DEFAULT_CONFIG), source: "legacy_server_configs" };
      }
      return null;
    };

    const getPolicyRecord = async ({ agent_id = "", id = "", ip = "", target = "" } = {}) => {
      const targets = buildPolicyTargets({ agent_id: agent_id || id, ip, target });
      for (const t of targets) {
        const rec = await getPolicyRecordByTarget(t);
        if (rec) return rec;
      }
      const legacy = await getLegacyServerOverride(ip);
      if (legacy) return legacy;
      return null;
    };

    const getEffectiveConfig = async ({ agent_id = "", id = "", ip = "", target = "" } = {}) => {
      const agentId = normalizeAgentId(agent_id || id || "");
      const normalizedIp = normalizeIp(ip || "");
      const globalCfg = await getGlobalConfig();
      const policyRec = await getPolicyRecord({ agent_id: agentId, ip: normalizedIp, target });
      const effective = policyRec ? sanitizeConfig({ ...globalCfg, ...policyRec.config }, globalCfg) : sanitizeConfig(globalCfg, DEFAULT_CONFIG);
      return {
        ...effective,
        _agent_id: agentId,
        _ip: normalizedIp,
        _scope: policyRec ? "server" : "default",
        _using_default: !policyRec,
        _policy_target: policyRec ? policyRec.target : "default",
        _policy_source: policyRec ? policyRec.source : "global_config",
        _policy_updated_at: policyRec ? (policyRec.updated_at || 0) : 0,
        _default: globalCfg,
        _override: policyRec ? policyRec.config : null,
        _match_keys: buildPolicyTargets({ agent_id: agentId, ip: normalizedIp, target })
      };
    };

    const savePolicyForTargets = async ({ agent_id = "", ip = "", target = "", config = DEFAULT_CONFIG }) => {
      const agentId = normalizeAgentId(agent_id || "");
      const normalizedIp = normalizeIp(ip || "");
      const targets = buildPolicyTargets({ agent_id: agentId, ip: normalizedIp, target });
      if (!targets.length) return [];
      const saved = [];
      for (const t of targets) {
        await env.DB.prepare(`INSERT INTO policy_targets (target, ip, agent_id, value, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(target) DO UPDATE SET ip = excluded.ip, agent_id = excluded.agent_id, value = excluded.value, updated_at = excluded.updated_at`).bind(t, normalizedIp, agentId, JSON.stringify(config), Date.now()).run();
        saved.push(t);
      }
      // 兼容旧版 manager：如果只有旧 Agent 还在用 ?ip=，也能读到同一份独立策略。
      if (normalizedIp) {
        await env.DB.prepare(`INSERT INTO server_configs (ip, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`).bind(normalizedIp, JSON.stringify(config), Date.now()).run();
      }
      return saved;
    };

    const deletePolicyForTargets = async ({ agent_id = "", ip = "", target = "" } = {}) => {
      const targets = buildPolicyTargets({ agent_id, ip, target });
      for (const t of targets) {
        await env.DB.prepare(`DELETE FROM policy_targets WHERE target = ?1`).bind(t).run();
      }
      const normalizedIp = normalizeIp(ip || "");
      if (normalizedIp) await env.DB.prepare(`DELETE FROM server_configs WHERE ip = ?1`).bind(normalizedIp).run();
      return targets;
    };

    if (url.pathname === "/scripts/proxy_server.py") {
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64
from typing import Any

PROXY_USER = b"${PROXY_USER}"
PROXY_PASS = b"${PROXY_PASS}"

# 全局软开关：由 lite_manager 动态更新，实现秒切
ACTIVE_BIND = "tun_main"

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

def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    global ACTIVE_BIND
    bind_interface = ACTIVE_BIND
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

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
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
        
        upstream = create_connection((host, port), timeout=20)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes) -> None:
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
            upstream = create_connection((host, parse_int(port_text) or 443), timeout=20)
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
        upstream = create_connection((parsed.hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first)
        else: http_client(client, first)
    except:
        try: client.close()
        except: pass

def start_proxy_server(host: str, port: int) -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
    except Exception as e: return
    while True:
        try:
            client, address = server.accept()
            threading.Thread(target=proxy_client, args=(client, address), daemon=True).start()
        except: time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/scripts/lite_manager.py") {
      const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, signal, socket, subprocess, threading, time, urllib.request, urllib.parse, json, uuid
from pathlib import Path
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = "${domain}"

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"
LOG_FILE = WORKSPACE / "proxy-lite.log"
AGENT_ID_FILE = WORKSPACE / "agent_id.txt"

WEB_USER = "${WEB_USER}"
WEB_PASS = "${WEB_PASS}"

PROXY_PORT = 7920
target_country = "JP"
last_switch_trigger = 0  

state_lock = threading.Lock()
dead_ips = set()
last_blacklist_clear = time.time()
last_harvest_attempt = 0
public_ip = ""
agent_id = ""
agent_hostname = socket.gethostname() or "unknown"
current_policy_target = "default"
current_policy_scope = "default"
last_policy_generation = 0

harvest_event = threading.Event()

global_node_reservoir = {} 
reservoir_lock = threading.Lock()

class Tunnel:
    def __init__(self, name: str, table_id: int):
        self.name = name
        self.table_id = table_id
        self.process = None
        self.node = None
        self.entry_ip = ""
        self.egress_ip = ""
        self.country = ""
        self.ready = False
        self.connected_at = 0
        self.is_connecting = False
        self.generation = 0

tun_main = Tunnel("tun_main", 101)
tun_backup = Tunnel("tun_backup", 102)

def load_agent_id():
    global agent_id
    try:
        WORKSPACE.mkdir(parents=True, exist_ok=True)
        if AGENT_ID_FILE.exists():
            saved = AGENT_ID_FILE.read_text(encoding="utf-8", errors="ignore").strip()
            if saved:
                agent_id = saved
                return agent_id
        seed = f"{agent_hostname}-{uuid.uuid4().hex}"
        agent_id = "pc-" + uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex[:24]
        AGENT_ID_FILE.write_text(agent_id + "\\n", encoding="utf-8")
        AGENT_ID_FILE.chmod(0o600)
    except Exception:
        agent_id = "pc-" + uuid.uuid4().hex[:24]
    return agent_id

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except: public_ip = "Unknown_IP"

def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Authorization": f"Basic {auth_ptr}"
    }

def tail_file(path, max_lines: int = 40):
    try:
        p = Path(path)
        if not p.exists():
            return ""
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            return ""
        return "\\n".join(lines[-max_lines:])
    except Exception:
        return ""

def get_recent_logs():
    # Debian/Ubuntu 使用 systemd journal；Alpine/OpenRC 使用本地日志文件。
    sections = []
    try:
        res = subprocess.run(["journalctl", "-u", "proxy-lite.service", "-n", "60", "--no-pager", "--output=cat"], capture_output=True, text=True, errors="replace")
        if res.stdout.strip():
            sections.append("===== proxy-lite service log =====\\n" + res.stdout.strip())
    except Exception:
        pass
    local_log = tail_file(LOG_FILE, 80)
    if local_log:
        sections.append("===== /opt/proxy_lite/proxy-lite.log =====\\n" + local_log)
    main_err = tail_file(WORKSPACE / "tun_main_err.log", 45)
    if main_err:
        sections.append("===== tun_main OpenVPN log =====\\n" + main_err)
    backup_err = tail_file(WORKSPACE / "tun_backup_err.log", 45)
    if backup_err:
        sections.append("===== tun_backup OpenVPN log =====\\n" + backup_err)
    if not sections:
        return "Waiting for logs..."
    merged = "\\n\\n".join(sections)
    # D1 单行不要无限膨胀，保留尾部关键拨号信息。
    return merged[-16000:]

def fetch_remote_config():
    global public_ip, agent_id
    params = {}
    if not agent_id:
        load_agent_id()
    if agent_id:
        params["id"] = agent_id
        params["agent_id"] = agent_id
    if public_ip and public_ip != "Unknown_IP":
        params["ip"] = public_ip
    if agent_hostname:
        params["hostname"] = agent_hostname
    query = urllib.parse.urlencode(params)
    config_url = f"{C2_URL}/api/config" + ("?" + query if query else "")
    req = urllib.request.Request(config_url, headers=get_c2_headers())
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))

def terminate_process(process, timeout: int = 2):
    if not process:
        return
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
    except Exception:
        try:
            process.kill()
        except Exception:
            pass

def cleanup_routing(tun_name: str, table_id: int):
    subprocess.run(["ip", "rule", "del", "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "pref", str(table_id + 1000)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)

def reset_tunnel_locked(tun: Tunnel, blacklist: bool = False, bump_generation: bool = True):
    # 调用方必须已经持有 state_lock。
    if blacklist and tun.entry_ip:
        dead_ips.add(tun.entry_ip)
    if bump_generation:
        tun.generation += 1
    process = tun.process
    tun.process = None
    tun.node = None
    tun.entry_ip = ""
    tun.egress_ip = ""
    tun.country = ""
    tun.ready = False
    tun.connected_at = 0
    tun.is_connecting = False
    return process

def connection_is_stale(tun: Tunnel, generation: int, country: str) -> bool:
    with state_lock:
        return tun.generation != generation or target_country != country

def trigger_fast_harvest():
    try:
        harvest_event.set()
    except Exception:
        pass

def update_config_loop():
    global target_country, last_switch_trigger, PROXY_PORT, tun_main, tun_backup, current_policy_target, current_policy_scope, last_policy_generation
    while True:
        procs_to_stop = []
        should_cleanup = False
        try:
            if not public_ip or public_ip == "Unknown_IP":
                get_public_ip()
            data = fetch_remote_config()
            desired_country = str(data.get("0", "JP")).upper()
            switch_trigger = int(data.get("switch_trigger", 0) or 0)
            policy_generation = int(data.get("generation", 0) or 0)
            policy_target = str(data.get("_policy_target", data.get("_scope", "default")) or "default")
            policy_scope = str(data.get("_scope", "default") or "default")
            new_port = int(data.get("port", 7920) or 7920)
            
            if new_port != PROXY_PORT:
                print(f"[*] 收到端口变更指令 ({PROXY_PORT} -> {new_port})，重启守护进程...", flush=True)
                os._exit(0)
            
            with state_lock:
                policy_target_changed = (current_policy_target != policy_target)
                current_policy_target = policy_target
                current_policy_scope = policy_scope
                last_policy_generation = policy_generation
                country_changed = (target_country != desired_country)
                force_switch = (switch_trigger > last_switch_trigger)
                if country_changed or force_switch:
                    if country_changed:
                        print(f"[*] 策略热切换: 目标重定向到 {desired_country}，清空旧通道并重建...", flush=True)
                        dead_ips.clear()
                    else:
                        print(f"[*] 收到强制更换指令，正在清退通道并拉黑当前 IP...", flush=True)
                    
                    target_country = desired_country
                    last_switch_trigger = max(last_switch_trigger, switch_trigger)
                    blacklist_current = force_switch and not country_changed
                    for tun in [tun_main, tun_backup]:
                        proc = reset_tunnel_locked(tun, blacklist=blacklist_current, bump_generation=True)
                        if proc:
                            procs_to_stop.append(proc)
                    proxy_server.ACTIVE_BIND = tun_main.name
                    should_cleanup = True
        except Exception:
            pass

        for proc in procs_to_stop:
            terminate_process(proc)
        if should_cleanup:
            cleanup_routing("tun_main", 101)
            cleanup_routing("tun_backup", 102)
            kill_existing_openvpn()
            trigger_fast_harvest()
        time.sleep(15)

def get_runtime_status_snapshot():
    try:
        with state_lock:
            tunnels = []
            for tun in [tun_main, tun_backup]:
                process_alive = bool(tun.process and tun.process.poll() is None)
                if tun.ready and process_alive:
                    stage = "ready"
                elif tun.is_connecting or process_alive:
                    stage = "connecting"
                else:
                    stage = "idle"
                tunnels.append({
                    "tunnel": tun.name,
                    "stage": stage,
                    "ready": bool(tun.ready),
                    "connecting": bool(tun.is_connecting),
                    "process_alive": process_alive,
                    "active": proxy_server.ACTIVE_BIND == tun.name,
                    "country": tun.country or target_country,
                    "entry_ip": tun.entry_ip,
                    "egress_ip": tun.egress_ip,
                    "generation": tun.generation,
                    "uptime": int(time.time() - tun.connected_at) if tun.connected_at else 0
                })
            desired_country = target_country
        with reservoir_lock:
            pool_total = len(global_node_reservoir)
            pool_target = sum(1 for n in global_node_reservoir.values() if n.get("country") == desired_country)
        return {
            "agent_id": agent_id,
            "hostname": agent_hostname,
            "target_country": desired_country,
            "proxy_port": PROXY_PORT,
            "public_ip": public_ip,
            "policy_target": current_policy_target,
            "policy_scope": current_policy_scope,
            "policy_generation": last_policy_generation,
            "last_switch_trigger": last_switch_trigger,
            "dead_count": len(dead_ips),
            "pool_total": pool_total,
            "pool_target": pool_target,
            "tunnels": tunnels,
            "updated_at": int(time.time())
        }
    except Exception as e:
        return {"target_country": target_country, "proxy_port": PROXY_PORT, "error": str(e), "tunnels": []}

def c2_heartbeat_loop():
    global public_ip, PROXY_PORT, target_country, tun_main, tun_backup
    while True:
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with state_lock:
            for tun in [tun_main, tun_backup]:
                if tun.ready and tun.process and tun.process.poll() is None:
                    uptime = time.time() - tun.connected_at
                    details.append({
                        "tunnel": tun.name,
                        "active": proxy_server.ACTIVE_BIND == tun.name,
                        "country": tun.country, 
                        "port": PROXY_PORT, 
                        "connected_time": int(uptime), 
                        "node_ip": tun.egress_ip if tun.egress_ip else tun.entry_ip
                    })
        
        payload = json.dumps({"ip": public_ip, "agent_id": agent_id, "hostname": agent_hostname, "details": details, "logs": get_recent_logs(), "status": get_runtime_status_snapshot(), "target_country": target_country, "proxy_port": PROXY_PORT}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
        except Exception as e: pass
        time.sleep(8)

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        LOG_FILE.touch(exist_ok=True)
        LOG_FILE.chmod(0o644)
    except: pass
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n", encoding="utf-8")
        AUTH_FILE.chmod(0o600)
    # Alpine 容器/轻量 VPS 有时未预创建 TUN 设备，这里做一次幂等兜底。
    try:
        Path("/dev/net").mkdir(parents=True, exist_ok=True)
        if not Path("/dev/net/tun").exists():
            subprocess.run(["mknod", "/dev/net/tun", "c", "10", "200"], capture_output=True)
        subprocess.run(["chmod", "600", "/dev/net/tun"], capture_output=True)
    except: pass
    # 强制系统解除反向路径过滤，防止策略路由双拨时数据包被内核丢弃
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"], capture_output=True)

def harvest_snapshot_nodes() -> list:
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip, 
                "ping": int(raw_ping) if raw_ping.isdigit() else 9999, 
                "country": row.get("CountryShort", "").upper(), 
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        return nodes
    except Exception as e: return []

def refresh_reservoir_once(reason: str = "") -> bool:
    snapshot = harvest_snapshot_nodes()
    if snapshot:
        with reservoir_lock:
            for n in snapshot:
                # 节点库保留全量节点，dead_ips 只在挑选时过滤；这样黑名单清空后不会丢节点。
                global_node_reservoir[n["ip"]] = n
            total = len(global_node_reservoir)
        tag = f"({reason})" if reason else ""
        print(f"[*] ⚡ 节点库更新{tag}，当前囤积有效节点 -> {total} 个", flush=True)
        return True
    return False

def vpngate_fetch_loop():
    while True:
        refresh_reservoir_once("定时")
        harvest_event.wait(300)
        harvest_event.clear()

def setup_routing(tun_name: str, table_id: int):
    cleanup_routing(tun_name, table_id)
    subprocess.run(["ip", "route", "add", "default", "dev", tun_name, "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", tun_name, "lookup", str(table_id), "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "iif", tun_name, "lookup", str(table_id), "pref", str(table_id + 1000)], capture_output=True)

def connect_node(tun: Tunnel, node: dict):
    global dead_ips
    process = None
    node_country = str(node.get("country", "")).upper()
    node_ip = node.get("ip", "")
    with state_lock:
        start_generation = tun.generation
        expected_country = target_country
    if node_country != expected_country:
        return

    def mark_failed_if_current():
        if not connection_is_stale(tun, start_generation, node_country) and node_ip:
            dead_ips.add(node_ip)

    try:
        cfg_path = CONFIG_DIR / f"{tun.name}.ovpn"
        log_file = WORKSPACE / f"{tun.name}_err.log"
        cfg_path.write_text(node["config"], encoding="utf-8")
        
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", tun.name, "--dev-type", "tun", 
               "--nobind", "--route-nopull",
               "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", 
               "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", 
               "--connect-timeout", "5", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
               
        with open(log_file, "w") as f:
            process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)

        # 关键修复：进程一启动就写入 tunnel 状态。否则 maintain_pool/update_config_loop
        # 在未 ready 阶段无法杀掉连接中的 OpenVPN，强制换 IP/保存默认策略会造成同名 tun 竞争。
        terminate_now = False
        with state_lock:
            if tun.generation != start_generation or target_country != node_country:
                terminate_now = True
            else:
                tun.process = process
                tun.node = node
                tun.entry_ip = node_ip
                tun.egress_ip = ""
                tun.country = node_country
                tun.ready = False
        if terminate_now:
            terminate_process(process)
            return
        
        success = False
        for _ in range(20):
            time.sleep(1)
            if connection_is_stale(tun, start_generation, node_country):
                terminate_process(process)
                return
            if process.poll() is not None:
                break
            try:
                if "Initialization Sequence Completed" in log_file.read_text(encoding="utf-8", errors="replace"):
                    success = True
                    break
            except Exception:
                pass
                
        if success and process.poll() is None and not connection_is_stale(tun, start_generation, node_country):
            setup_routing(tun.name, tun.table_id)
            time.sleep(1)
            if connection_is_stale(tun, start_generation, node_country):
                terminate_process(process)
                return
            
            true_ip = ""
            try:
                true_ip_res = subprocess.run(["curl", "-s", "-m", "10", "--interface", tun.name, "https://api.ipify.org"], capture_output=True, text=True)
                candidate_ip = true_ip_res.stdout.strip()
                if candidate_ip and candidate_ip.count('.') == 3:
                    true_ip = candidate_ip
            except Exception:
                pass
            
            egress_ip = true_ip if true_ip else node_ip
            
            if true_ip and true_ip != node_ip:
                print(f"[*] {tun.name} 探测到真实出口 IP 与入口不一致: 入口 {node_ip} -> 出口 {true_ip}", flush=True)

            is_residential = True
            try:
                req_url = f"https://ip.net.coffee/api/ip/lookup/{egress_ip}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, method="GET")
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    data = json.loads(check_res.read().decode("utf-8"))
                    is_dc = data.get("is_datacenter", False)
                    company_type = str(data.get("company_type", "")).lower()
                    asn_kind = str(data.get("asn_kind", "")).lower()
                    if is_dc or company_type == "hosting" or asn_kind == "hosting":
                        is_residential = False
            except Exception:
                pass
            
            if connection_is_stale(tun, start_generation, node_country):
                terminate_process(process)
                return
            if not is_residential:
                print(f"[-] {tun.name} 节点出口 ({egress_ip}) 检测为机房 IP，残忍抛弃！", flush=True)
                mark_failed_if_current()
                terminate_process(process)
                return

            print(f"[*] {tun.name} 进行流媒体质检 (YouTube)...", flush=True)
            res = subprocess.run(["curl", "-I", "-s", "-A", "Mozilla/5.0", "-m", "5", "--interface", tun.name, "https://www.youtube.com"], capture_output=True)
            if connection_is_stale(tun, start_generation, node_country):
                terminate_process(process)
                return
            if res.returncode != 0:
                print(f"[-] {tun.name} 节点出口无法连通 YouTube，拉黑更换: {node_ip}", flush=True)
                mark_failed_if_current()
                terminate_process(process)
                return

            with state_lock:
                if tun.generation != start_generation or target_country != node_country:
                    terminate_now = True
                else:
                    tun.process = process
                    tun.node = node
                    tun.entry_ip = node_ip
                    tun.egress_ip = egress_ip
                    tun.country = node_country
                    tun.connected_at = time.time()
                    tun.ready = True
                    terminate_now = False
            if terminate_now:
                terminate_process(process)
                return
            role = "主网卡" if proxy_server.ACTIVE_BIND == tun.name else "备用网卡"
            print(f"[+] {tun.name} ({role}) 完全就绪: 入口 {node_ip} -> 出口 {egress_ip}", flush=True)
        else:
            mark_failed_if_current()
            terminate_process(process)
    finally:
        with state_lock:
            if tun.generation == start_generation:
                tun.is_connecting = False
                if process is not None and tun.process == process and not tun.ready:
                    tun.process = None
                    tun.node = None
                    tun.entry_ip = ""
                    tun.egress_ip = ""
                    tun.country = ""

def health_check_loop():
    global tun_main, dead_ips
    fail_count = 0
    while True:
        # 如果处于异常容错状态，缩短检测间隔进行快速复核
        time.sleep(15 if fail_count == 0 else 5)
        
        target_tun = ""
        target_entry_ip = ""
        proc_ref = None
        
        with state_lock:
            if tun_main.ready and tun_main.process and tun_main.process.poll() is None:
                if time.time() - tun_main.connected_at > 20:
                    target_tun = tun_main.name
                    target_entry_ip = tun_main.entry_ip
                    proc_ref = tun_main.process
        
        if not target_tun:
            fail_count = 0
            continue
            
        # 1. 应用层：多维 HTTP 探针 (包含域名与直连IP，规避单点限流和DNS污染)
        endpoints = [
            "http://www.gstatic.com/generate_204",
            "http://cp.cloudflare.com/generate_204",
            "http://1.1.1.1",
            "http://8.8.8.8"
        ]
        
        is_alive = False
        for ep in endpoints:
            res = subprocess.run(["curl", "-I", "-s", "-m", "5", "--interface", target_tun, ep], capture_output=True)
            if res.returncode == 0:
                is_alive = True
                break
                
        # 2. 网络层：如果应用层全挂，尝试底层 ICMP (Ping) 作为终极底线
        if not is_alive:
            ping_res = subprocess.run(["ping", "-c", "2", "-W", "3", "-I", target_tun, "8.8.8.8"], capture_output=True)
            if ping_res.returncode == 0:
                is_alive = True
                
        # 3. 容错评估与处决
        if not is_alive:
            fail_count += 1
            if fail_count >= 3:
                print(f"[!] {target_tun} 连续 {fail_count} 次多维探针(HTTP/ICMP)均无响应，确认为真死断流，执行踢线: {target_entry_ip}", flush=True)
                dead_ips.add(target_entry_ip)
                try: proc_ref.terminate(); proc_ref.wait(timeout=2)
                except: proc_ref.kill()
                with state_lock:
                    if tun_main.process == proc_ref: tun_main.ready = False
                fail_count = 0
            else:
                print(f"[*] {target_tun} 探针无响应，启动快频深度复核容错机制 ({fail_count}/3)...", flush=True)
        else:
            fail_count = 0

def get_best_candidate():
    global global_node_reservoir, dead_ips, target_country, tun_main, tun_backup, last_harvest_attempt

    def pick_from_pool():
        with state_lock:
            desired_country = target_country
            active_ips = []
            if tun_main.entry_ip:
                active_ips.append(tun_main.entry_ip)
            if tun_backup.entry_ip:
                active_ips.append(tun_backup.entry_ip)
        with reservoir_lock:
            all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x["ping"])
            candidates = [n for n in all_pool_nodes if n["country"] == desired_country and n["ip"] not in dead_ips and n["ip"] not in active_ips]
            if candidates:
                return candidates[0]
            has_target = any(n["country"] == desired_country for n in all_pool_nodes)
            if has_target and dead_ips:
                dead_ips.clear()
                print(f"[!] ⚡ 紧急熔断：[{desired_country}] 节点枯竭，解锁历史黑名单救场！", flush=True)
                candidates = [n for n in all_pool_nodes if n["country"] == desired_country and n["ip"] not in active_ips]
                if candidates:
                    return candidates[0]
        return None

    node = pick_from_pool()
    if node:
        return node

    now = time.time()
    if now - last_harvest_attempt > 20:
        last_harvest_attempt = now
        print(f"[*] 当前目标 [{target_country}] 节点池为空，立即刷新节点库...", flush=True)
        refresh_reservoir_once("按需")
        return pick_from_pool()
    return None

def maintain_pool():
    global dead_ips, last_blacklist_clear, tun_main, tun_backup
    while True:
        if time.time() - last_blacklist_clear > 600:
            dead_ips.clear()
            last_blacklist_clear = time.time()

        with reservoir_lock:
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips:
                global_node_reservoir.pop(ip, None)

        procs_to_stop = []
        with state_lock:
            # 关键修复：正在拨号的 tunnel 不能被当成 dead 反复清理，否则会无限并发拨号并卡在震荡熔断。
            main_dead = (not tun_main.is_connecting) and (tun_main.process is None or tun_main.process.poll() is not None or not tun_main.ready)
            if main_dead:
                if tun_backup.ready and tun_backup.process and tun_backup.process.poll() is None:
                    print(f"[*] ⚡ 主通道暴毙，软开关秒切！无缝接管业务至备用通道: 出口 {tun_backup.egress_ip or tun_backup.entry_ip}", flush=True)
                    tun_main, tun_backup = tun_backup, tun_main
                    proxy_server.ACTIVE_BIND = tun_main.name
                    proc = reset_tunnel_locked(tun_backup, blacklist=False, bump_generation=True)
                    if proc:
                        procs_to_stop.append(proc)
                else:
                    proc = reset_tunnel_locked(tun_main, blacklist=False, bump_generation=True)
                    if proc:
                        procs_to_stop.append(proc)

            needs_main = not tun_main.ready and not tun_main.is_connecting
            needs_backup = not tun_backup.ready and not tun_backup.is_connecting

        for proc in procs_to_stop:
            terminate_process(proc)

        if needs_main:
            node = get_best_candidate()
            if node:
                with state_lock:
                    if not tun_main.ready and not tun_main.is_connecting:
                        tun_main.is_connecting = True
                        threading.Thread(target=connect_node, args=(tun_main, node,), daemon=True).start()
                time.sleep(1)
        if needs_backup:
            node = get_best_candidate()
            if node:
                with state_lock:
                    if not tun_backup.ready and not tun_backup.is_connecting:
                        tun_backup.is_connecting = True
                        threading.Thread(target=connect_node, args=(tun_backup, node,), daemon=True).start()

        time.sleep(2)

def kill_existing_openvpn():
    # 不依赖 pkill/psmisc，直接扫描 /proc，兼容 Alpine BusyBox 环境。
    victims = []
    try:
        for pid_text in os.listdir("/proc"):
            if not pid_text.isdigit():
                continue
            try:
                cmdline = (Path("/proc") / pid_text / "cmdline").read_bytes().replace(b"\\x00", b" ").decode("utf-8", errors="ignore")
                if "openvpn" in cmdline and ("tun_main" in cmdline or "tun_backup" in cmdline):
                    victims.append(int(pid_text))
            except: pass
        for pid in victims:
            try: os.kill(pid, signal.SIGTERM)
            except: pass
        if victims:
            time.sleep(1)
        for pid in victims:
            try: os.kill(pid, signal.SIGKILL)
            except: pass
    except: pass

def main():
    global PROXY_PORT, target_country, last_switch_trigger, tun_main, current_policy_target, current_policy_scope, last_policy_generation
    if os.geteuid() != 0:
        return
    get_public_ip()
    setup_env()
    load_agent_id()
    kill_existing_openvpn()
    cleanup_routing("tun_main", 101)
    cleanup_routing("tun_backup", 102)
    
    proxy_server.ACTIVE_BIND = tun_main.name
    
    try:
        data = fetch_remote_config()
        PROXY_PORT = int(data.get("port", 7920) or 7920)
        target_country = str(data.get("0", "JP")).upper()
        current_policy_target = str(data.get("_policy_target", data.get("_scope", "default")) or "default")
        current_policy_scope = str(data.get("_scope", "default") or "default")
        last_policy_generation = int(data.get("generation", 0) or 0)
        # 启动时同步云端 switch_trigger，避免 Agent 重启后把旧触发器当成新命令反复清退通道。
        last_switch_trigger = int(data.get("switch_trigger", 0) or 0)
    except Exception:
        pass

    print("========================================", flush=True)
    print(f"  Proxy Controller 启动！ID: {agent_id} 端口: {PROXY_PORT} 目标: {target_country} 策略: {current_policy_target}", flush=True)
    print("========================================", flush=True)

    refresh_reservoir_once("启动")
    threading.Thread(target=vpngate_fetch_loop, daemon=True).start()
    threading.Thread(target=update_config_loop, daemon=True).start()
    threading.Thread(target=proxy_server.start_proxy_server, args=("0.0.0.0", PROXY_PORT), daemon=True).start()
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
`;
      return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/agent") {
      const agentScript = `#!/bin/sh
set -eu

DOMAIN="${domain}"
WORKSPACE="/opt/proxy_lite"
SERVICE_NAME="proxy-lite"

echo "=========================================================="
echo "     Proxy Controller (Active-Standby Multi-Tunnel)    "
echo "     Alpine/OpenRC + Debian/systemd Compatible Agent    "
echo "=========================================================="

if [ "$(id -u)" != "0" ]; then
    echo "[!] 请使用 root 权限运行此脚本。"
    exit 1
fi

fetch_file() {
    url="$1"
    out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$out"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$out" "$url"
    else
        echo "[!] 未找到 curl 或 wget，无法拉取核心脚本。"
        exit 1
    fi
}

apply_sysctl() {
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-proxy-lite.conf << 'EOF'
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/99-proxy-lite.conf >/dev/null 2>&1 || {
        sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1 || true
    }
}

ensure_tun_device() {
    modprobe tun >/dev/null 2>&1 || true
    mkdir -p /dev/net
    if [ ! -c /dev/net/tun ]; then
        mknod /dev/net/tun c 10 200 >/dev/null 2>&1 || true
    fi
    chmod 600 /dev/net/tun >/dev/null 2>&1 || true
}

install_core_files() {
    mkdir -p "$WORKSPACE/configs"
    cd "$WORKSPACE"
    echo "[1/4] 从安全中心拉取双活极速引擎..."
    fetch_file "$DOMAIN/scripts/lite_manager.py" "lite_manager.py"
    fetch_file "$DOMAIN/scripts/proxy_server.py" "proxy_server.py"
    chmod 700 "$WORKSPACE"
    chmod 600 "$WORKSPACE"/*.py
}

install_alpine_openrc() {
    echo "[0/4] 检测到 Alpine Linux，使用 apk + OpenRC 部署..."
    apk update
    apk add --no-cache openvpn python3 curl iproute2 iptables iputils procps-ng ca-certificates kmod openrc
    update-ca-certificates >/dev/null 2>&1 || true

    apply_sysctl
    ensure_tun_device
    install_core_files

    echo "[2/4] 配置 OpenRC 守护服务..."
    cat > /etc/init.d/proxy-lite << 'EOF'
#!/sbin/openrc-run

name="proxy-lite"
description="Proxy Core Engine (Active-Standby)"
supervisor="supervise-daemon"
command="/usr/bin/python3"
command_args="-u /opt/proxy_lite/lite_manager.py"
command_user="root:root"
directory="/opt/proxy_lite"
pidfile="/run/proxy-lite.pid"
output_log="/opt/proxy_lite/proxy-lite.log"
error_log="/opt/proxy_lite/proxy-lite.log"
respawn_delay=5
respawn_max=0

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -d -m 0755 /opt/proxy_lite/configs
    checkpath -f -m 0644 /opt/proxy_lite/proxy-lite.log
    modprobe tun >/dev/null 2>&1 || true
    mkdir -p /dev/net
    if [ ! -c /dev/net/tun ]; then
        mknod /dev/net/tun c 10 200 >/dev/null 2>&1 || true
    fi
    chmod 600 /dev/net/tun >/dev/null 2>&1 || true
}
EOF
    chmod +x /etc/init.d/proxy-lite

    echo "[3/4] 启用并重启 OpenRC 服务..."
    rc-update add proxy-lite default >/dev/null 2>&1 || true
    rc-service proxy-lite restart
    echo "[+] Alpine 引擎更新成功！主备双活通道、异步刷 IP 逻辑已全量加载。"
}

install_debian_systemd() {
    echo "[0/4] 检测到 Debian/Ubuntu，使用 apt + systemd 部署..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y openvpn python3 curl iproute2 iptables cron psmisc ca-certificates kmod iputils-ping
    update-ca-certificates >/dev/null 2>&1 || true

    apply_sysctl
    ensure_tun_device
    install_core_files

    echo "[2/4] 配置 systemd 守护服务..."
    mkdir -p /lib/systemd/system
    cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=Proxy Core Engine (Active-Standby)
After=network.target

[Service]
Type=simple
Environment="PYTHONIOENCODING=utf-8"
Environment="PYTHONUNBUFFERED=1"
Environment="LANG=C.UTF-8"
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    if command -v systemctl >/dev/null 2>&1; then
        echo "[3/4] 启用并重启 systemd 服务..."
        systemctl daemon-reload
        systemctl enable proxy-lite.service
        systemctl restart proxy-lite.service
        echo "[+] Debian/Ubuntu 引擎更新成功！主备双活通道、异步刷 IP 逻辑已全量加载。"
    else
        echo "[!] 当前系统未检测到 systemctl，核心文件已安装到 $WORKSPACE，请手动以 root 启动："
        echo "    cd $WORKSPACE && /usr/bin/python3 -u lite_manager.py"
    fi
}

if [ -f /etc/alpine-release ] || { [ -f /etc/os-release ] && grep -qi '^ID=alpine' /etc/os-release; }; then
    install_alpine_openrc
elif command -v apt-get >/dev/null 2>&1; then
    install_debian_systemd
else
    echo "[!] 暂不支持的系统：未检测到 Alpine/apk 或 Debian/apt。"
    exit 1
fi
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname.startsWith("/api/coffee-lookup/")) {
        if (!authenticate(request)) return unauthorizedResponse();
        const targetIp = url.pathname.replace("/api/coffee-lookup/", "");
        try {
            const reqUrl = `https://ip.net.coffee/api/ip/lookup/${targetIp}`;
            const resp = await fetch(reqUrl, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Accept": "application/json",
                    "Referer": "https://ip.net.coffee/"
                }
            });
            const data = await resp.text();
            return new Response(data, { 
                status: resp.status,
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } 
            });
        } catch (err) {
            return new Response(JSON.stringify({ error: err.message }), { status: 500 });
        }
    }

    if (url.pathname === "/api/countries") {
        try {
            const response = await fetch("https://www.vpngate.net/api/iphone/");
            const text = await response.text();
            const lines = text.split('\n');
            const dynamicCountries = new Set();
            for (let i = 2; i < lines.length; i++) {
                const parts = lines[i].split(',');
                if (parts.length > 6) {
                    const country = parts[6];
                    if (country && country.length === 2 && country !== "xx" && country !== "--") {
                        dynamicCountries.add(country.toUpperCase());
                    }
                }
            }
            const predefinedCountries = ["US", "JP", "KR", "SG", "HK", "TW", "GB", "DE", "FR", "NL", "CA", "AU", "IN", "VN", "BR", "AE", "MY", "TH", "PH", "ID", "TR", "ZA", "IT", "ES", "RU", "CH", "SE", "PL", "NO", "DK", "FI", "IE", "AT", "NZ", "BE", "PT", "CZ", "GR", "HU", "RO", "BG", "HR", "SK", "SI", "LT", "LV", "EE", "UA", "RS", "BA", "CY", "MT", "IS", "LU"];
            const allCountries = new Set([...predefinedCountries, ...Array.from(dynamicCountries)]);
            return new Response(JSON.stringify(Array.from(allCountries).sort()), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        } catch(err) {
            return new Response(JSON.stringify(["US", "JP", "KR", "SG", "HK", "TW"]), { headers: { "Content-Type": "application/json" } }); 
        }
    }

    if (url.pathname === "/" || url.pathname === "/api/config" || url.pathname === "/api/nodes" || url.pathname === "/api/proxies" || url.pathname === "/api/report") {
      if (!authenticate(request)) return unauthorizedResponse();
    }

    if (url.pathname === "/api/config" && request.method === "GET") {
        const scope = String(url.searchParams.get("scope") || "").toLowerCase();
        if (scope === "default" || url.searchParams.get("global") === "1") {
            return new Response(JSON.stringify(await getGlobalConfig()), { headers: { "Content-Type": "application/json" } });
        }
        const requestedIp = normalizeIp(url.searchParams.get("ip") || "");
        const requestedId = normalizeAgentId(url.searchParams.get("id") || url.searchParams.get("agent_id") || "");
        const requestedTarget = normalizePolicyTarget(url.searchParams.get("target") || "");
        if (requestedIp || requestedId || requestedTarget) {
            return new Response(JSON.stringify(await getEffectiveConfig({ agent_id: requestedId, ip: requestedIp, target: requestedTarget })), { headers: { "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify(await getGlobalConfig()), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
        const data = await request.json();
        const targetIp = normalizeIp(data.ip || url.searchParams.get("ip") || "");
        const targetId = normalizeAgentId(data.agent_id || data.id || url.searchParams.get("id") || url.searchParams.get("agent_id") || "");
        const explicitTarget = normalizePolicyTarget(data.target || data.policy_target || url.searchParams.get("target") || "");
        const hasServerTarget = !!(targetIp || targetId || explicitTarget);

        if (data.reset && hasServerTarget) {
            const deleted = await deletePolicyForTargets({ agent_id: targetId, ip: targetIp, target: explicitTarget });
            return new Response(JSON.stringify({ ok: true, scope: "server", reset: true, ip: targetIp, agent_id: targetId, deleted, config: await getEffectiveConfig({ agent_id: targetId, ip: targetIp, target: explicitTarget }) }), { headers: { "Content-Type": "application/json" } });
        }

        if (hasServerTarget) {
            const globalCfg = await getGlobalConfig();
            const oldRecord = await getPolicyRecord({ agent_id: targetId, ip: targetIp, target: explicitTarget });
            const oldCfg = oldRecord ? oldRecord.config : globalCfg;
            const sanitizedMap = sanitizeConfig(data, oldCfg);
            const changedCountryOrPort = String(sanitizedMap["0"]) !== String(oldCfg["0"]) || Number(sanitizedMap.port) !== Number(oldCfg.port);
            const explicitSwitch = data.switch_trigger !== undefined || data.force_switch || data.switch;
            if (changedCountryOrPort || explicitSwitch) {
                sanitizedMap.generation = Math.max(Number(oldCfg.generation || 0), Number(sanitizedMap.generation || 0)) + 1;
            }
            if (explicitSwitch && !sanitizedMap.switch_trigger) sanitizedMap.switch_trigger = Date.now();
            const saved = await savePolicyForTargets({ agent_id: targetId, ip: targetIp, target: explicitTarget, config: sanitizedMap });
            return new Response(JSON.stringify({ ok: true, scope: "server", ip: targetIp, agent_id: targetId, target: saved[0] || explicitTarget, aliases: saved, config: sanitizedMap, effective: await getEffectiveConfig({ agent_id: targetId, ip: targetIp, target: explicitTarget }) }), { headers: { "Content-Type": "application/json" } });
        }

        const oldGlobal = await getGlobalConfig();
        const sanitizedMap = sanitizeConfig(data, oldGlobal);
        const changedCountryOrPort = String(sanitizedMap["0"]) !== String(oldGlobal["0"]) || Number(sanitizedMap.port) !== Number(oldGlobal.port);
        const explicitSwitch = data.switch_trigger !== undefined || data.force_switch || data.switch;
        if (changedCountryOrPort || explicitSwitch) {
            sanitizedMap.generation = Math.max(Number(oldGlobal.generation || 0), Number(sanitizedMap.generation || 0)) + 1;
        }
        if (explicitSwitch && !sanitizedMap.switch_trigger) sanitizedMap.switch_trigger = Date.now();
        await env.DB.prepare(`INSERT INTO global_config (key, value) VALUES ('slot_map', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(JSON.stringify(sanitizedMap)).run();
        return new Response(JSON.stringify({ ok: true, scope: "default", config: sanitizedMap }), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        const cfIp = normalizeIp(request.headers.get("CF-Connecting-IP") || "");
        const reportIp = normalizeIp(data.ip && data.ip !== "Unknown_IP" ? data.ip : cfIp);
        const reportId = normalizeAgentId(data.agent_id || data.id || (data.status && data.status.agent_id) || "");
        const hostname = String(data.hostname || (data.status && data.status.hostname) || "").slice(0, 128);
        if (!reportIp) return new Response("Missing IP", { status: 400 });
        await env.DB.prepare(`INSERT INTO servers (ip, details, last_seen) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET details = excluded.details, last_seen = excluded.last_seen`).bind(reportIp, JSON.stringify(data.details || []), Date.now()).run();
        if (data.logs) {
          await env.DB.prepare(`INSERT INTO server_logs (ip, logs, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET logs = excluded.logs, updated_at = excluded.updated_at`).bind(reportIp, data.logs, Date.now()).run();
        }
        if (data.status) {
          await env.DB.prepare(`INSERT INTO server_runtime (ip, status, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at`).bind(reportIp, JSON.stringify(data.status || {}), Date.now()).run();
        }
        if (reportId || hostname) {
          await env.DB.prepare(`INSERT INTO server_identity (ip, agent_id, hostname, first_seen, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(ip) DO UPDATE SET agent_id = excluded.agent_id, hostname = excluded.hostname, updated_at = excluded.updated_at`).bind(reportIp, reportId, hostname, Date.now(), Date.now()).run();
        }
        return new Response("OK", { status: 200 });
      } catch (err) { return new Response("Error: " + err.message, { status: 500 }); }
    }

    if (url.pathname === "/api/proxies") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      if (results) {
        for (let server of results) {
          const details = JSON.parse(server.details || '[]');
          // API 提取节点时，只提取当前 Active 的流量节点
          const activeNode = details.find(d => d.active) || details[0];
          if (activeNode) {
            proxyList.push(`socks5://${PROXY_USER}:${PROXY_PASS}@${server.ip}:${activeNode.port}#${activeNode.country}_ActiveNode_${activeNode.node_ip || 'IP'}`);
          }
        }
      }
      return new Response(proxyList.join('\n'), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/api/nodes") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const defaultCfg = await getGlobalConfig();
      const rawLogsScope = url.searchParams.has("logs_ip") ? String(url.searchParams.get("logs_ip") || "") : "__all__";
      const logsScope = rawLogsScope === "__all__" ? "__all__" : normalizeIp(rawLogsScope);
      const { results } = await env.DB.prepare(`
        SELECT s.*,
               CASE WHEN ?1 = '__all__' OR s.ip = ?1 THEN l.logs ELSE NULL END AS logs,
               sr.status AS runtime_status,
               si.agent_id AS agent_id,
               si.hostname AS hostname
        FROM servers s
        LEFT JOIN server_logs l ON s.ip = l.ip
        LEFT JOIN server_runtime sr ON s.ip = sr.ip
        LEFT JOIN server_identity si ON s.ip = si.ip
        ORDER BY s.last_seen DESC
      `).bind(logsScope).all();

      const policyRows = (await env.DB.prepare(`SELECT target, ip, agent_id, value, updated_at FROM policy_targets`).all()).results || [];
      const legacyRows = (await env.DB.prepare(`SELECT ip, value, updated_at FROM server_configs`).all()).results || [];
      const policyMap = new Map();
      for (const pr of policyRows) {
        const parsed = parseConfigValue(pr.value);
        if (parsed) policyMap.set(pr.target, { ...pr, config: sanitizeConfig(parsed, defaultCfg), source: "policy_targets" });
      }
      const legacyMap = new Map();
      for (const lr of legacyRows) {
        const parsed = parseConfigValue(lr.value);
        const ip = normalizeIp(lr.ip);
        if (parsed && ip) legacyMap.set(`ip:${ip}`, { target: `ip:${ip}`, ip, agent_id: "", updated_at: lr.updated_at || 0, config: sanitizeConfig(parsed, defaultCfg), source: "legacy_server_configs" });
      }

      const mapped = (results || []).map((row) => {
        const runtimeStatus = parseConfigValue(row.runtime_status);
        const agentId = normalizeAgentId(row.agent_id || (runtimeStatus && runtimeStatus.agent_id) || "");
        const ip = normalizeIp(row.ip);
        const policyRec = (agentId && policyMap.get(`id:${agentId}`)) || policyMap.get(`ip:${ip}`) || legacyMap.get(`ip:${ip}`) || null;
        const effectiveCfg = policyRec ? sanitizeConfig({ ...defaultCfg, ...policyRec.config }, defaultCfg) : sanitizeConfig(defaultCfg, DEFAULT_CONFIG);
        const { runtime_status, ...safeRow } = row;
        return {
          ...safeRow,
          ip,
          agent_id: agentId,
          hostname: row.hostname || (runtimeStatus && runtimeStatus.hostname) || "",
          status: runtimeStatus,
          config: policyRec ? policyRec.config : null,
          policy_target: policyRec ? policyRec.target : "default",
          policy_source: policyRec ? policyRec.source : "global_config",
          policy_updated_at: policyRec ? (policyRec.updated_at || 0) : 0,
          effective_config: effectiveCfg,
          default_config: defaultCfg,
          using_default: !policyRec
        };
      });
      return new Response(JSON.stringify(mapped), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/") {
      return new Response(DASHBOARD_HTML(domain, WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const DASHBOARD_HTML = (domain, webUser, webPass, proxyUser, proxyPass) => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Controller - 双活引擎总控</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.5); }
        ::-webkit-scrollbar-thumb { background: rgba(51, 65, 85, 0.8); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(71, 85, 105, 1); }
        input[type=number]::-webkit-inner-spin-button, 
        input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
    </style>
</head>
<body class="min-h-screen bg-[#090E17] text-slate-300 relative overflow-x-hidden selection:bg-indigo-500/30">
    <div class="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/20 blur-[120px] rounded-full pointer-events-none z-0"></div>
    <div class="fixed bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 blur-[120px] rounded-full pointer-events-none z-0"></div>

    <div class="max-w-7xl mx-auto p-6 relative z-10">
        <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-10 gap-6">
            <div>
                <h1 class="text-4xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 tracking-tight drop-shadow-sm">Proxy Controller</h1>
                <p class="text-slate-400 mt-2 text-sm flex items-center gap-2">
                    <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                    直链提取 API: <a href="/api/proxies" target="_blank" class="text-indigo-400 hover:text-indigo-300 border-b border-indigo-400/30 hover:border-indigo-300 transition-colors">${domain}/api/proxies</a>
                </p>
            </div>
            
            <div class="flex flex-col gap-3 w-full md:w-auto">
                <div class="bg-slate-900/80 backdrop-blur-md border border-slate-700/50 rounded-xl overflow-hidden shadow-lg">
                    <div class="bg-slate-800/50 px-4 py-2 border-b border-slate-700/50 flex items-center gap-2">
                        <div class="flex gap-1.5">
                            <div class="w-3 h-3 rounded-full bg-rose-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-amber-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                        </div>
                        <span class="text-xs text-slate-400 font-mono ml-2">VPS 纳管命令 (Root / Alpine 兼容)</span>
                    </div>
                    <div class="p-3 bg-[#0D1117] text-sm font-mono text-emerald-400 select-all overflow-x-auto whitespace-nowrap">
                        安装 bash <(curl -sL ${domain}<br>
                        卸载 bash <(curl -sL https://paste.aniu.hidns.co/api/raw/xx)
                    </div>
                </div>

                <div class="flex gap-4 text-xs font-mono">
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">面板凭证</span>
                        <span class="text-indigo-300 font-bold ml-4">${webUser} <span class="text-slate-600">/</span> ${webPass}</span>
                    </div>
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">代理凭证</span>
                        <span class="text-amber-300 font-bold ml-4">${proxyUser} <span class="text-slate-600">/</span> ${proxyPass}</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
            <div class="lg:col-span-1 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20">
                <div class="flex items-center gap-2 mb-4">
                    <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <h2 class="text-lg font-bold text-slate-200">全量国家代码库</h2>
                </div>
                <p class="text-xs text-slate-500 mb-4 leading-relaxed">系统已合并预设代码及实时的网络探测代码，提供最全面的目标锁定选择。</p>
                <div id="countries-list" class="flex flex-wrap gap-2 max-h-[160px] overflow-y-auto pr-1">
                    <span class="text-slate-600 text-sm animate-pulse">正在同步数据库...</span>
                </div>
            </div>

            <div class="lg:col-span-3 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20 flex flex-col justify-center relative overflow-hidden">
                <div class="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
                    <svg class="w-32 h-32" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                </div>
                
                <div class="mb-6 relative z-10">
                    <h2 class="text-2xl font-bold text-slate-100 tracking-wide mb-1 flex items-center gap-2">全局默认策略 <span class="bg-indigo-500/20 text-indigo-400 text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border border-indigo-500/30">Default Policy</span></h2>
                    <p class="text-sm text-slate-400">这里保存默认国家/端口；每台 VPS 可单独覆盖。全局“触发换 IP”会广播到所有在线 VPS，选中 VPS 的快捷操作在下方近况栏。</p>
                </div>
                
                <div class="flex flex-wrap items-center bg-slate-950/50 border border-slate-800/80 rounded-xl p-5 relative z-10 gap-y-4">
                    <div class="flex items-center gap-3 mr-3 border-r border-slate-700/50 pr-4">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">默认地区:</span>
                        <input type="text" id="slot-cfg-0" value="JP" maxlength="2" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-16 text-white font-bold text-lg uppercase text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="US" />
                    </div>
                    
                    <div class="flex items-center gap-3 mr-4">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">默认端口:</span>
                        <input type="number" id="slot-port" value="7920" min="1024" max="65535" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-24 text-white font-bold text-lg text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="7920" />
                    </div>
                    
                    <button onclick="saveConfig()" class="group relative px-6 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-sm font-bold shadow-lg shadow-blue-900/20 hover:shadow-indigo-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden ml-auto">
                        <div class="absolute inset-0 bg-white/20 group-hover:translate-x-full -translate-x-full transform transition-transform duration-300 ease-in-out skew-x-12"></div>
                        <span class="flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"></path></svg>
                            保存默认策略
                        </span>
                    </button>
                    
                    <div class="h-8 w-px bg-slate-800 mx-2 hidden sm:block"></div>

                    <button onclick="switchIP()" class="group relative px-6 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 text-white text-sm font-bold shadow-lg shadow-purple-900/20 hover:shadow-pink-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden">
                         <div class="absolute inset-0 bg-white/20 group-hover:translate-x-full -translate-x-full transform transition-transform duration-300 ease-in-out skew-x-12"></div>
                         <span class="flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                            全局触发换 IP
                         </span>
                    </button>
                </div>
            </div>
        </div>
        
        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex flex-col md:flex-row justify-between md:items-center gap-2">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <div class="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse"></div>
                    活跃节点矩阵 / 多 VPS 独立策略
                </h3>
                <span class="text-xs text-slate-500">点击“查看近况”只锁定日志/质检；行内按钮或下方快捷按钮才会对这台 VPS 下发/换 IP。</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-900/80 text-slate-400 text-xs uppercase tracking-wider">
                            <th class="py-4 px-6 font-medium w-1/6">母机宿主 IP</th>
                            <th class="py-4 px-6 font-medium">主备双路出口状态 (Active / Standby)</th>
                            <th class="py-4 px-6 font-medium w-[340px]">独立策略</th>
                            <th class="py-4 px-6 font-medium w-32">心跳延迟</th>
                            <th class="py-4 px-6 font-medium text-right w-24">负载率</th>
                        </tr>
                    </thead>
                    <tbody id="nodes-table" class="divide-y divide-slate-800/50 text-sm">
                        <tr><td colspan="5" class="py-12 text-center text-slate-500">正在与 D1 数据库建立量子纠缠...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div id="ip-score-section" style="display: none;" class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    选中 VPS 原生深度质检报告 (ip.net.coffee)
                </h3>
                <a id="ip-score-link" href="#" target="_blank" class="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors">
                    原版页面 <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                </a>
            </div>
            
            <div id="native-score-container" class="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 bg-[#090E17]">
                <div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500">
                    <svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    <span>穿透请求中，正在构建原生质检报告...</span>
                </div>
            </div>
        </div>

        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 pb-8">
            <div class="px-4 py-3 border-b border-slate-800 bg-slate-900/80 flex flex-col md:flex-row justify-between md:items-center gap-3">
                <span class="text-xs text-slate-400 font-mono flex items-center gap-2">
                    <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M4 17h16a2 2 0 002-2V5a2 2 0 00-2-2H4a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                    选中 VPS 实时运行日志 / 近况 (按需刷新)
                </span>
                <div class="flex items-center gap-3">
                    <span id="selected-vps-label" class="text-xs font-mono text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 px-2.5 py-1 rounded-md">未选择 VPS</span>
                    <button id="selected-save-vps" onclick="saveSelectedVps()" style="display:none" class="text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-500 border border-indigo-500 px-2.5 py-1 rounded-md transition-colors">给选中 VPS 下发</button>
                    <button id="selected-switch-vps" onclick="switchSelectedVps()" style="display:none" class="text-xs font-bold text-white bg-pink-600 hover:bg-pink-500 border border-pink-500 px-2.5 py-1 rounded-md transition-colors">选中 VPS 换 IP</button>
                    <button id="clear-selected-vps" onclick="clearSelectedVps()" style="display:none" class="text-xs font-bold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 px-2.5 py-1 rounded-md transition-colors">取消选择</button>
                    <span class="flex gap-1.5">
                        <div class="w-3 h-3 rounded-full bg-rose-500/80 shadow-[0_0_5px_rgba(244,63,94,0.5)]"></div>
                        <div class="w-3 h-3 rounded-full bg-amber-500/80 shadow-[0_0_5px_rgba(245,158,11,0.5)]"></div>
                        <div class="w-3 h-3 rounded-full bg-emerald-500/80 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div>
                    </span>
                </div>
            </div>
            <div class="p-4 h-64 overflow-y-auto bg-[#0D1117] font-mono text-[13px] leading-relaxed text-slate-300" id="terminal-output">
                <div class="text-slate-500">请选择上方某台 VPS 的“查看近况”，日志和质检将只跟随该 VPS 刷新。</div>
            </div>
        </div>
    </div>

    <script>
        let currentScoreIp = "";
        let selectedServerIp = localStorage.getItem('proxy_selected_vps') || "";
        let policyDrafts = {};
        let lastServersByIp = {};
        let lastServersSnapshot = [];
        let defaultConfig = { "0": "JP", "port": 7920, "switch_trigger": 0 };

        function safeId(ip) {
            return String(ip || '').replace(/[^a-zA-Z0-9_-]/g, '_');
        }

        function escapeHtml(value) {
            return String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const container = document.getElementById('countries-list');
                container.innerHTML = list.map(c => \`<span class="bg-slate-800/80 hover:bg-indigo-500/20 text-slate-300 hover:text-indigo-300 transition-colors border border-slate-700/50 px-2.5 py-1 rounded-md text-xs font-mono font-bold shadow-sm cursor-default">\${c}</span>\`).join('');
            } catch(e) {}
        }

        async function loadConfig() {
            try {
                const res = await fetch('/api/config?scope=default');
                const map = await res.json();
                defaultConfig = map || defaultConfig;
                document.getElementById('slot-cfg-0').value = defaultConfig["0"] || 'JP';
                document.getElementById('slot-port').value = defaultConfig["port"] || 7920;
            } catch(e) {}
        }

        function serverIdentityPayload(ip) {
            const server = lastServersByIp[ip] || {};
            const status = server.status || {};
            const agentId = server.agent_id || status.agent_id || '';
            return {
                ip: ip || '',
                agent_id: agentId || '',
                id: agentId || '',
                target: agentId ? ('id:' + agentId) : (ip ? ('ip:' + ip) : '')
            };
        }

        function readPolicy(ip) {
            if (ip) {
                const id = safeId(ip);
                const countryEl = document.getElementById('vps-country-' + id);
                const portEl = document.getElementById('vps-port-' + id);
                return {
                    "0": (countryEl?.value || defaultConfig["0"] || 'JP').toUpperCase().trim(),
                    "port": parseInt(portEl?.value || defaultConfig["port"] || 7920) || 7920
                };
            }
            return {
                "0": (document.getElementById('slot-cfg-0').value || 'JP').toUpperCase().trim(),
                "port": parseInt(document.getElementById('slot-port').value) || 7920
            };
        }

        async function postConfig(body) {
            await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
        }

        async function saveConfig(ip) {
            const policy = readPolicy(ip);
            if (ip) Object.assign(policy, serverIdentityPayload(ip));
            await postConfig(policy);
            if (ip) delete policyDrafts[ip];
            if (!ip) defaultConfig = { ...defaultConfig, ...policy };
            alert(ip ? ('🚀 已给 VPS ' + ip + ' 下发独立策略，下一心跳周期应用。') : '🚀 默认策略已同步；仅未设置独立策略的 VPS 会应用它。');
            fetchNodes();
        }

        async function switchIP(ip) {
            const policy = readPolicy(ip);
            policy.switch_trigger = Date.now();
            policy.force_switch = true;
            if (ip) Object.assign(policy, serverIdentityPayload(ip));
            await postConfig(policy);
            alert(ip ? ('🔄 已向 VPS ' + ip + ' 下发独立换 IP 指令。') : '🔄 已向默认组下发换 IP 指令；独立策略 VPS 不会受影响。');
            fetchNodes();
        }

        async function resetVpsConfig(ip) {
            await postConfig({ ...serverIdentityPayload(ip), reset: true });
            delete policyDrafts[ip];
            alert('↩️ VPS ' + ip + ' 已恢复使用全局默认策略。');
            fetchNodes();
        }

        async function loadNativeIpScore(ip) {
            const container = document.getElementById('native-score-container');
            container.innerHTML = '<div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500"><svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg><span>穿透请求中，正在构建原生质检报告...</span></div>';
            
            try {
                const res = await fetch('/api/coffee-lookup/' + encodeURIComponent(ip));
                const d = await res.json();
                
                if (d.error && !d.cidr) {
                    container.innerHTML = \`<div class="col-span-full text-center py-8 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">无法获取报告: \${d.error}</div>\`;
                    return;
                }

                const score = d.trust_score ?? '-';
                const scoreColor = score >= 75 ? 'text-emerald-400 bg-emerald-500/20 border-emerald-500/30' : (score >= 45 ? 'text-amber-400 bg-amber-500/20 border-amber-500/30' : 'text-rose-400 bg-rose-500/20 border-rose-500/30');
                
                const cc = (d.countryCode||'').toLowerCase();
                const regCc = (d.registered_country_code||'').toLowerCase();
                const isNative = cc && regCc && (cc === regCc);
                
                let tags = '';
                if (d.is_datacenter || d.company_type === 'hosting' || d.asn_kind === 'hosting') tags += '<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/20 text-xs font-bold">机房IP</span> ';
                else tags += '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 text-xs font-bold">家庭住宅</span> ';
                
                if (d.is_proxy) tags += '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-bold">Proxy</span> ';
                if (d.is_abuser) tags += '<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/20 text-xs font-bold">历史滥用</span> ';

                const locStr = [d.country, d.region, d.city].filter(Boolean).join(" ");
                const orgStr = d.company_name || d.asOrganization || '-';
                
                const threats = (d.intelligence?.threats || []).map(t => \`<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-bold">\${t.label}</span>\`).join(' ') || '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 text-xs font-bold">纯净无异常</span>';

                container.innerHTML = \`
                    <div class="col-span-full bg-slate-800/60 border border-slate-700/80 p-5 rounded-2xl flex flex-wrap gap-4 justify-between items-center mb-2 shadow-lg">
                        <div class="flex items-center gap-4">
                            <span class="text-3xl font-extrabold font-mono text-white tracking-tight drop-shadow-sm">\${ip}</span>
                            <span class="text-slate-400 text-sm hidden sm:flex items-center border-l border-slate-700 pl-4 h-6">
                                <span class="uppercase tracking-widest text-indigo-400 mr-2 text-xs font-bold">\${d.countryCode || 'N/A'}</span> 
                                \${locStr} · \${orgStr}
                            </span>
                        </div>
                        <div class="flex items-center gap-3 px-5 py-2 rounded-xl border \${scoreColor} shadow-inner">
                            <span class="text-sm uppercase font-extrabold opacity-90 tracking-wider">IP 评分</span>
                            <span class="text-3xl font-black font-mono">\${score}</span>
                        </div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">使用场景 / 类型</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">IP 原生性</span> <span class="font-medium text-sm">\${isNative ? '<span class="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold">原生 IP</span>' : '<span class="px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-bold">广播 IP ('+(d.registered_country_code||'').toUpperCase()+')</span>'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">标记</span> <div class="flex gap-1">\${tags}</div></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">运营类型</span> <span class="font-medium text-slate-200 text-sm capitalize">\${d.company_type || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">人机流量</span> <span class="font-medium text-xs px-2.5 py-1 rounded-full border \${d.is_datacenter ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'}">\${d.is_datacenter ? '🤖 机器偏多' : '👤 人类偏多'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">归属机构</span> <span class="font-medium text-slate-300 text-sm truncate max-w-[150px]" title="\${orgStr}">\${orgStr}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">ASN / 运营商</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">ASN</span> <span class="font-medium text-indigo-300 text-sm font-mono">AS\${d.asn || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">CIDR</span> <span class="font-medium text-slate-300 text-sm font-mono">\${d.cidr || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">自报类型</span> <span class="font-medium \${d.asn_kind === 'residential' ? 'text-emerald-400' : 'text-slate-200'} text-sm capitalize">\${d.asn_kind || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">IP 范围</span> <span class="font-medium text-slate-400 text-xs font-mono">\${d.range?.first || '-'} - \${d.range?.last || ''}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">分配日期</span> <span class="font-medium text-slate-400 text-xs font-mono">\${d.asn_allocated || '-'}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">风险深度检测</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">VPN / 代理</span> <span class="\${(d.is_vpn || d.is_proxy) ? 'px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-bold' : 'px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold'}">\${(d.is_vpn || d.is_proxy) ? '已检测到' : '未检测到'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">Tor 节点</span> <span class="\${d.is_tor ? 'px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-bold' : 'px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold'}">\${d.is_tor ? '已检测到' : '未检测到'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">威胁情报</span> <div class="flex gap-1">\${threats}</div></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">Bogon (广播)</span> <span class="font-medium text-xs font-bold \${d.is_bogon ? 'text-rose-400' : 'text-emerald-400'}">\${d.is_bogon ? '是' : '否 (公网可达)'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">反向 DNS</span> <span class="font-medium text-slate-400 text-xs font-mono truncate max-w-[150px]" title="\${d.rdns || '-'}">\${d.rdns || '-'}</span></div>
                    </div>
                \`;
            } catch (e) {
                container.innerHTML = \`<div class="col-span-full text-center py-10 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">渲染失败: \${e.message}</div>\`;
            }
        }

        function isPolicyInputFocused() {
            const active = document.activeElement;
            return !!(active && active.closest && active.closest('#nodes-table') && active.tagName === 'INPUT');
        }

        function rememberPolicyDraft(ip) {
            const id = safeId(ip);
            const countryEl = document.getElementById('vps-country-' + id);
            const portEl = document.getElementById('vps-port-' + id);
            policyDrafts[ip] = {
                country: (countryEl?.value || '').toUpperCase(),
                port: portEl?.value || ''
            };
        }

        function selectVps(ip) {
            selectedServerIp = ip || "";
            currentScoreIp = "";
            if (selectedServerIp) localStorage.setItem('proxy_selected_vps', selectedServerIp);
            else localStorage.removeItem('proxy_selected_vps');
            fetchNodes();
        }

        function clearSelectedVps() {
            selectVps("");
        }

        function getSelectedServer() {
            if (!selectedServerIp) return null;
            return (lastServersSnapshot || []).find(s => s.ip === selectedServerIp) || null;
        }

        async function saveSelectedVps() {
            if (!selectedServerIp) {
                alert('请先点击某台 VPS 的“查看近况”，再使用选中 VPS 快捷下发。');
                return;
            }
            await saveConfig(selectedServerIp);
        }

        async function switchSelectedVps() {
            if (!selectedServerIp) {
                alert('请先点击某台 VPS 的“查看近况”，再使用选中 VPS 换 IP。');
                return;
            }
            await switchIP(selectedServerIp);
        }

        function showTerminalMessage(message, tone = 'slate') {
            const terminal = document.getElementById('terminal-output');
            const toneClass = tone === 'rose' ? 'text-rose-400 bg-rose-500/10 border-rose-500/20' : (tone === 'amber' ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-slate-500 bg-slate-900/40 border-slate-800');
            terminal.innerHTML = '<div class="border rounded-xl px-4 py-3 ' + toneClass + '">' + escapeHtml(message) + '</div>';
        }

        function renderLogs(logText) {
            const terminal = document.getElementById('terminal-output');
            const isAtBottom = terminal.scrollHeight - terminal.scrollTop <= terminal.clientHeight + 30;
            if (!logText) {
                showTerminalMessage('这台 VPS 暂时还没有回传日志，等待下一次心跳。', 'slate');
                return;
            }
            let logHTML = escapeHtml(logText)
                .replace(/\\[\\*\\]/g, '<span class="text-indigo-400 font-bold">[*]</span>')
                .replace(/\\[\\+\\]/g, '<span class="text-emerald-400 font-bold">[+]</span>')
                .replace(/\\[\\-\\]/g, '<span class="text-rose-400 font-bold">[-]</span>')
                .replace(/\\[\\!\\]/g, '<span class="text-amber-400 font-bold">[!]</span>');
            terminal.innerHTML = '<pre class="whitespace-pre-wrap break-all">' + logHTML + '</pre>';
            if (isAtBottom) terminal.scrollTop = terminal.scrollHeight;
        }

        function getStageLabel(stage) {
            if (stage === 'ready') return '已就绪';
            if (stage === 'connecting') return '正在拨号';
            return '空闲等待';
        }

        function getRuntimeTunnels(server) {
            const status = server && server.status ? server.status : {};
            return Array.isArray(status.tunnels) ? status.tunnels : [];
        }

        function renderDialingStatus(server) {
            const status = server && server.status ? server.status : {};
            const tunnels = getRuntimeTunnels(server);
            const policy = server.effective_config || status || { "0": "--", "port": "--" };
            const country = status.target_country || policy["0"] || '--';
            const port = status.proxy_port || policy.port || '--';
            let tunnelHtml = '';
            if (tunnels.length) {
                tunnelHtml = tunnels.map(function(t) {
                    const stage = t.stage || 'idle';
                    const cls = stage === 'ready' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' : (stage === 'connecting' ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-slate-400 bg-slate-800/60 border-slate-700/60');
                    const node = t.egress_ip || t.entry_ip || '等待节点';
                    return '<div class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 flex flex-col gap-2">'
                        + '<div class="flex justify-between items-center"><span class="font-mono text-indigo-300 font-bold">' + escapeHtml(t.tunnel || '-') + '</span><span class="px-2 py-0.5 rounded-md border text-xs font-bold ' + cls + '">' + getStageLabel(stage) + '</span></div>'
                        + '<div class="text-xs text-slate-400 font-mono">目标: ' + escapeHtml(t.country || country) + ' / 节点: ' + escapeHtml(node) + '</div>'
                        + '<div class="text-xs text-slate-500 font-mono">进程: ' + (t.process_alive ? 'alive' : 'none') + ' / generation: ' + escapeHtml(String(t.generation ?? '-')) + '</div>'
                        + '</div>';
                }).join('');
            } else {
                tunnelHtml = '<div class="col-span-full bg-slate-950/60 border border-slate-800 rounded-xl p-4 text-slate-400">等待 Agent 下一次心跳回传拨号状态。</div>';
            }
            return '<div class="col-span-full bg-amber-500/10 border border-amber-500/20 rounded-2xl p-5 text-left">'
                + '<div class="text-amber-300 font-bold mb-2">所选 VPS 尚未产生 Active 出口</div>'
                + '<div class="text-sm text-slate-300 mb-4">这通常不是前端故障，而是该 VPS 还在拨号、节点池为空、OpenVPN 失败、或节点被机房/IP/YouTube 质检过滤。下面会显示该 VPS 当前拨号状态；具体原因看下方日志里的 <span class="font-mono text-indigo-300">tun_main OpenVPN log</span> / <span class="font-mono text-indigo-300">tun_backup OpenVPN log</span>。</div>'
                + '<div class="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">'
                + '<div class="bg-slate-950/60 border border-slate-800 rounded-xl p-3"><div class="text-xs text-slate-500">目标国家</div><div class="font-mono text-lg text-white font-bold">' + escapeHtml(String(country)) + '</div></div>'
                + '<div class="bg-slate-950/60 border border-slate-800 rounded-xl p-3"><div class="text-xs text-slate-500">代理端口</div><div class="font-mono text-lg text-white font-bold">' + escapeHtml(String(port)) + '</div></div>'
                + '<div class="bg-slate-950/60 border border-slate-800 rounded-xl p-3"><div class="text-xs text-slate-500">目标节点池</div><div class="font-mono text-lg text-white font-bold">' + escapeHtml(String(status.pool_target ?? '-')) + '</div></div>'
                + '<div class="bg-slate-950/60 border border-slate-800 rounded-xl p-3"><div class="text-xs text-slate-500">临时黑名单</div><div class="font-mono text-lg text-white font-bold">' + escapeHtml(String(status.dead_count ?? '-')) + '</div></div>'
                + '</div><div class="grid grid-cols-1 md:grid-cols-2 gap-3">' + tunnelHtml + '</div>'
                + '</div>';
        }

        function updateSelectedVpsLabel(server) {
            const label = document.getElementById('selected-vps-label');
            const clearBtn = document.getElementById('clear-selected-vps');
            const saveBtn = document.getElementById('selected-save-vps');
            const switchBtn = document.getElementById('selected-switch-vps');
            if (!selectedServerIp) {
                label.textContent = '未选择 VPS';
                clearBtn.style.display = 'none';
                saveBtn.style.display = 'none';
                switchBtn.style.display = 'none';
                return;
            }
            clearBtn.style.display = 'inline-flex';
            saveBtn.style.display = 'inline-flex';
            switchBtn.style.display = 'inline-flex';
            if (!server) {
                label.textContent = '已选择 ' + selectedServerIp + '（离线或无心跳）';
                return;
            }
            const details = JSON.parse(server.details || '[]');
            const activeNode = details.find(d => d.active) || details[0];
            const tunnels = getRuntimeTunnels(server);
            const runningCount = tunnels.filter(t => t.stage === 'connecting' || t.stage === 'ready').length;
            const statusText = runningCount ? (' / ' + runningCount + ' 路拨号中') : ' / 等待节点';
            const suffix = activeNode ? (' / Active: ' + (activeNode.country || '--') + ' ' + (activeNode.node_ip || '等待出口')) : statusText;
            label.textContent = selectedServerIp + suffix;
        }

        function renderSelectedPanels(servers) {
            const scoreSection = document.getElementById('ip-score-section');
            const scoreContainer = document.getElementById('native-score-container');
            if (!selectedServerIp) {
                updateSelectedVpsLabel(null);
                currentScoreIp = "";
                scoreSection.style.display = 'none';
                showTerminalMessage('请选择上方某台 VPS 的“查看近况”。选择后，下方日志和 IP 质检只刷新该 VPS；近况栏会出现“选中 VPS 换 IP/下发”快捷按钮。', 'slate');
                return;
            }

            const server = (servers || []).find(s => s.ip === selectedServerIp);
            updateSelectedVpsLabel(server);
            if (!server) {
                currentScoreIp = "";
                scoreSection.style.display = 'none';
                showTerminalMessage('所选 VPS 当前离线或超过 120 秒没有心跳：' + selectedServerIp, 'amber');
                return;
            }

            renderLogs(server.logs || '');

            const details = JSON.parse(server.details || '[]');
            const activeNode = details.find(d => d.active) || details[0];
            if (activeNode && activeNode.node_ip) {
                const newIp = activeNode.node_ip;
                scoreSection.style.display = 'block';
                document.getElementById('ip-score-link').href = 'https://ip.net.coffee/ip/' + encodeURIComponent(newIp);
                if (newIp !== currentScoreIp) {
                    currentScoreIp = newIp;
                    loadNativeIpScore(newIp);
                }
            } else {
                currentScoreIp = "";
                scoreSection.style.display = 'block';
                document.getElementById('ip-score-link').href = '#';
                scoreContainer.innerHTML = renderDialingStatus(server);
            }
        }

        async function fetchNodes() {
            try {
                const nodesUrl = selectedServerIp ? ('/api/nodes?logs_ip=' + encodeURIComponent(selectedServerIp)) : '/api/nodes?logs_ip=__none__';
                const res = await fetch(nodesUrl);
                const servers = await res.json();
                lastServersSnapshot = servers || [];
                const tbody = document.getElementById('nodes-table');
                const freezeRows = isPolicyInputFocused();
                
                if (!servers || servers.length === 0) {
                    if (!freezeRows) {
                        tbody.innerHTML = '<tr><td colspan="5" class="py-12 text-center text-slate-500 flex-col items-center justify-center"><svg class="w-12 h-12 mx-auto text-slate-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>未检测到在线母机，请在 VPS 运行纳管命令接入</td></tr>';
                    }
                    renderSelectedPanels([]);
                    return;
                }

                if (!freezeRows) {
                    tbody.innerHTML = servers.map(server => {
                        const details = JSON.parse(server.details || '[]');
                        const timeAgo = Math.floor((Date.now() - server.last_seen) / 1000);
                        const rowId = safeId(server.ip);
                        const rowSelected = selectedServerIp === server.ip;
                        const policy = server.effective_config || defaultConfig || { "0": "JP", "port": 7920 };
                        const policyCountry = (policy["0"] || 'JP').toUpperCase();
                        const policyPort = parseInt(policy["port"] || 7920) || 7920;
                        const draft = policyDrafts[server.ip] || {};
                        const inputCountry = draft.country !== undefined ? draft.country : policyCountry;
                        const inputPort = draft.port !== undefined ? draft.port : policyPort;
                        const isDefaultPolicy = !!server.using_default;
                        const policyBadge = isDefaultPolicy
                            ? '<span class="px-2 py-0.5 rounded-full bg-slate-700/60 text-slate-300 border border-slate-600/50 text-[10px] font-bold">继承默认</span>'
                            : '<span class="px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-bold">独立策略</span>';
                        const safeIp = escapeHtml(server.ip);
                        const agentShort = server.agent_id ? String(server.agent_id).slice(0, 10) : "IP模式";
                        const selectBtn = rowSelected
                            ? '<button onclick="selectVps(\\'' + safeIp + '\\')" class="mt-2 px-2.5 py-1 rounded-md bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-bold">查看中</button>'
                            : '<button onclick="selectVps(\\'' + safeIp + '\\')" class="mt-2 px-2.5 py-1 rounded-md bg-slate-800 hover:bg-indigo-600/80 text-slate-200 border border-slate-700 hover:border-indigo-500 text-xs font-bold transition-colors">查看近况</button>';
                        const policyControls = \`
                            <div class="flex flex-col gap-2 min-w-[320px]">
                                <div class="flex items-center gap-2 text-xs text-slate-500">
                                    <span>目标策略</span>\${policyBadge}<span class="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 text-[10px] font-mono">\${escapeHtml(agentShort)}</span>
                                </div>
                                <div class="flex flex-wrap items-center gap-2">
                                    <input type="text" id="vps-country-\${rowId}" value="\${escapeHtml(inputCountry)}" maxlength="2" oninput="rememberPolicyDraft('\${safeIp}')" class="bg-slate-950 border border-slate-700 rounded-md py-1.5 w-14 text-white font-bold text-xs uppercase text-center outline-none focus:border-indigo-500" />
                                    <input type="number" id="vps-port-\${rowId}" value="\${escapeHtml(inputPort)}" min="1" max="65535" oninput="rememberPolicyDraft('\${safeIp}')" class="bg-slate-950 border border-slate-700 rounded-md py-1.5 w-20 text-white font-bold text-xs text-center outline-none focus:border-indigo-500" />
                                    <button onclick="saveConfig('\${safeIp}')" class="px-2.5 py-1.5 rounded-md bg-indigo-600/80 hover:bg-indigo-500 text-white text-xs font-bold transition-colors">下发</button>
                                    <button onclick="switchIP('\${safeIp}')" class="px-2.5 py-1.5 rounded-md bg-pink-600/80 hover:bg-pink-500 text-white text-xs font-bold transition-colors">换IP</button>
                                    <button onclick="resetVpsConfig('\${safeIp}')" class="px-2.5 py-1.5 rounded-md bg-slate-700/80 hover:bg-slate-600 text-slate-200 text-xs font-bold transition-colors">默认</button>
                                </div>
                            </div>\`;
                        
                        let proxyBadges = '';
                        if (details.length === 0) {
                            const runtimeTunnels = getRuntimeTunnels(server);
                            const connectingCount = runtimeTunnels.filter(t => t.stage === 'connecting').length;
                            const status = server.status || {};
                            const targetPool = status.pool_target ?? '-';
                            const noActiveText = connectingCount > 0
                                ? ('正在拨号中：' + connectingCount + ' 路 / 目标节点池 ' + targetPool)
                                : ('暂无 Active 出口：目标节点池 ' + targetPool + '，请点“查看近况”看日志');
                            proxyBadges = '<div class="inline-flex items-center bg-slate-900 border border-amber-500/30 rounded-xl px-3 py-1.5 shadow-inner text-amber-400/90 text-sm">'
                                + '<svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-amber-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>'
                                + escapeHtml(noActiveText)
                                + '</div>';
                        } else {
                            proxyBadges = '<div class="flex flex-col gap-2">' + details.map(d => {
                                const isActive = d.active;
                                const statusColorClass = isActive ? 'bg-emerald-500' : 'bg-sky-500';
                                const statusText = isActive ? 'ACTIVE (业务出口)' : 'STANDBY (热备就绪)';
                                const borderColorClass = isActive ? 'border-emerald-500/30' : 'border-sky-500/30';
                                const bgColorClass = isActive ? 'bg-emerald-500/10' : 'bg-sky-500/10';
                                const textColorClass = isActive ? 'text-emerald-400' : 'text-sky-400';
                                return \`
                                <div class="inline-flex items-center bg-slate-950 border border-slate-800/80 rounded-xl px-2.5 py-1.5 shadow-inner">
                                    <span class="bg-slate-800 text-slate-300 font-mono text-xs px-2 py-0.5 rounded-md mr-3 border border-slate-700 font-bold">\${d.tunnel}</span>
                                    <span class="bg-indigo-500/20 text-indigo-400 font-bold font-mono text-xs px-2 py-0.5 rounded-md mr-3 border border-indigo-500/20">\${d.country}</span>
                                    <span class="font-mono text-slate-300 text-sm tracking-wide mr-3" title="出口物理 IP">\${d.node_ip || '---.---.---.---'}:\${d.port}</span>
                                    <span class="flex items-center gap-1.5 \${textColorClass} \${bgColorClass} px-2 py-0.5 rounded-md border \${borderColorClass} text-xs font-medium">
                                        <span class="w-1.5 h-1.5 rounded-full \${statusColorClass} shadow-[0_0_5px_currentColor]"></span> \${statusText}
                                    </span>
                                </div>\`;
                            }).join('') + '</div>';
                        }

                        const rowClass = rowSelected ? 'bg-indigo-500/10 ring-1 ring-inset ring-indigo-500/30' : 'hover:bg-slate-800/30';
                        return \`
                            <tr class="\${rowClass} transition-colors group">
                                <td class="py-5 px-6 font-mono text-indigo-300 align-middle">
                                    <div class="flex flex-col gap-1">
                                        <div class="flex items-center gap-2">
                                            <svg class="w-4 h-4 text-slate-600 group-hover:text-indigo-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                                            <span>\${safeIp}</span>
                                        </div>
                                        \${selectBtn}
                                    </div>
                                </td>
                                <td class="py-5 px-6 align-middle">\${proxyBadges}</td>
                                <td class="py-5 px-6 align-middle">\${policyControls}</td>
                                <td class="py-5 px-6 align-middle">
                                    <span class="flex items-center gap-1.5 \${timeAgo < 20 ? 'text-emerald-400' : 'text-rose-400'} font-mono text-xs">
                                        <span class="w-1.5 h-1.5 rounded-full \${timeAgo < 20 ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}"></span>
                                        \${timeAgo}s 前
                                    </span>
                                </td>
                                <td class="py-5 px-6 align-middle text-right">
                                    <span class="\${details.length === 2 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : (details.length === 1 ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30')} py-1 px-3 rounded-md text-xs font-mono font-bold">
                                        \${details.length} / 2
                                    </span>
                                </td>
                            </tr>\`;
                    }).join('');
                }

                renderSelectedPanels(servers);
            } catch (err) {
                showTerminalMessage('节点刷新失败：' + (err?.message || err), 'rose');
            }
        }
        
        fetchCountries();
        loadConfig();
        fetchNodes();
        setInterval(fetchNodes, 5000);
    </script>
</body>
</html>
`;
