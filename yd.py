import requests

import re

import asyncio

import ssl

URL = "https://raw.githubusercontent.com/HandsomeMJZ/cfip/refs/heads/main/full_ips.txt"

TOP_N = 3

TIMEOUT = 1.5

CONCURRENCY = 100

# ========= 获取IP =========

text = requests.get(URL).text

ips = list(set(re.findall(r'\b\d+\.\d+\.\d+\.\d+:\d+\b', text)))

sem = asyncio.Semaphore(CONCURRENCY)

# ========= TCP =========

async def tcp_test(ip_port):

    ip, port = ip_port.split(":")

    port = int(port)

    try:

        async with sem:

            start = asyncio.get_event_loop().time()

            reader, writer = await asyncio.wait_for(

                asyncio.open_connection(ip, port),

                timeout=TIMEOUT

            )

            delay = (asyncio.get_event_loop().time() - start) * 1000

            writer.close()

            await writer.wait_closed()

            return ip_port, delay

    except:

        return None

# ========= TLS =========

async def tls_test(ip_port):

    ip, port = ip_port.split(":")

    port = int(port)

    try:

        ctx = ssl.create_default_context()

        reader, writer = await asyncio.wait_for(

            asyncio.open_connection(ip, port, ssl=ctx, server_hostname="cloudflare.com"),

            timeout=TIMEOUT

        )

        writer.close()

        await writer.wait_closed()

        return True

    except:

        return False

# ========= HTTP =========

async def http_test(ip_port):

    ip, port = ip_port.split(":")

    port = int(port)

    try:

        reader, writer = await asyncio.wait_for(

            asyncio.open_connection(ip, port),

            timeout=TIMEOUT

        )

        start = asyncio.get_event_loop().time()

        req = f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n"

        writer.write(req.encode())

        await writer.drain()

        await reader.read(100)

        delay = (asyncio.get_event_loop().time() - start) * 1000

        writer.close()

        await writer.wait_closed()

        return delay

    except:

        return None

# ========= 主流程 =========

async def main():

    print("TCP测速中...")

    tcp_results = await asyncio.gather(*[tcp_test(ip) for ip in ips])

    tcp_results = [r for r in tcp_results if r]

    # 取前100进入下一阶段

    tcp_results.sort(key=lambda x: x[1])

    candidates = tcp_results[:100]

    print("TLS验证中...")

    valid = []

    for ip, delay in candidates:

        ok = await tls_test(ip)

        if ok:

            valid.append((ip, delay))

    print("HTTP测速中...")

    final_results = []

    for ip, tcp_delay in valid:

        http_delay = await http_test(ip)

        if http_delay:

            score = tcp_delay * 0.7 + http_delay * 0.3

            final_results.append((ip, score))

    final_results.sort(key=lambda x: x[1])

    best = final_results[:TOP_N]

    with open("best_ips.txt", "w") as f:

        for ip, score in best:

            f.write(f"{ip} # {round(score,2)}ms\n")

    print("最终:", best)

asyncio.run(main())
