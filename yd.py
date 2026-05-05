import requests
import re
import asyncio
import websockets
import json
from statistics import mean

# ========= 配置 =========
URL = "https://raw.githubusercontent.com/HandsomeMJZ/cfip/refs/heads/main/full_ips.txt"

BATCH_SIZE = 50
TOP_PER_BATCH = 5
CANDIDATE_POOL = 20   # 初选后进入TCP测试
FINAL_TOP = 3

NODE_IDS = ["1274", "1226"]  # 福建移动

TCP_TIMEOUT = 1.0  # 秒（关键）

# ========= 获取IP =========
text = requests.get(URL).text
ips = list(set(re.findall(r'\b\d+\.\d+\.\d+\.\d+:\d+\b', text)))

# ========= itdog测速 =========
async def test_ip_delay(ip):
    delays = []

    for node in NODE_IDS:
        try:
            uri = "wss://ws.itdog.cn/v1/ping"
            async with websockets.connect(uri) as ws:
                payload = {
                    "host": ip.split(":")[0],
                    "node_id": node
                }
                await ws.send(json.dumps(payload))
                res = await ws.recv()
                data = json.loads(res)

                delays.append(data.get("delay", 9999))

        except:
            delays.append(9999)

        await asyncio.sleep(0.05)

    return ip, mean(delays)

# ========= 测一批 =========
async def test_batch(batch):
    tasks = [test_ip_delay(ip) for ip in batch]
    results = await asyncio.gather(*tasks)

    results.sort(key=lambda x: x[1])
    return results[:TOP_PER_BATCH]

# ========= TCP测试 =========
async def tcp_test(ip_port):
    ip, port = ip_port.split(":")
    port = int(port)

    try:
        start = asyncio.get_event_loop().time()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=TCP_TIMEOUT
        )

        delay = (asyncio.get_event_loop().time() - start) * 1000

        writer.close()
        await writer.wait_closed()

        return ip_port, delay

    except:
        return None  # 失败直接丢弃

# ========= 主流程 =========
async def main():
    all_best = []

    # ===== 第一阶段：itdog筛选 =====
    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i:i+BATCH_SIZE]
        print(f"批次 {i//BATCH_SIZE + 1}")

        batch_best = await test_batch(batch)
        all_best.extend(batch_best)

    # 全局排序 → 取候选
    all_best.sort(key=lambda x: x[1])
    candidates = [ip for ip, _ in all_best[:CANDIDATE_POOL]]

    print("进入TCP测试:", len(candidates))

    # ===== 第二阶段：TCP过滤 =====
    tcp_tasks = [tcp_test(ip) for ip in candidates]
    tcp_results = await asyncio.gather(*tcp_tasks)

    # 过滤失败
    tcp_results = [r for r in tcp_results if r]

    # 按TCP延迟排序
    tcp_results.sort(key=lambda x: x[1])

    final = tcp_results[:FINAL_TOP]

    # 保存
    with open("best_ips.txt", "w") as f:
        for ip, delay in final:
            f.write(f"{ip} # {round(delay,2)}ms\n")

    print("最终结果:", final)

asyncio.run(main())
