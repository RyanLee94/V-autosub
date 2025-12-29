import requests
import re
import socket
import base64
import time

SOURCE_URL = "https://v2raya.net/free-nodes/2025-02-02-free-v2ray-node-subscriptions.html"
TIMEOUT = 2      # 测速超时时间（秒）
MAX_LATENCY = 2 # 超过 2 秒认为不可用

def extract_sub_urls(html):
    urls = re.findall(r'https?://[^\s"\']+', html)
    return list(set([u for u in urls if 'sub' in u or 'subscribe' in u]))

def decode_subscription(text):
    try:
        decoded = base64.b64decode(text + '===').decode('utf-8', errors='ignore')
        return decoded.splitlines()
    except:
        return text.splitlines()

def tcp_ping(host, port):
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.close()
        return time.time() - start
    except:
        return None

def parse_node(line):
    if line.startswith("vmess://"):
        try:
            data = base64.b64decode(line[8:] + "===")
            info = eval(data.decode(errors='ignore'))
            return info.get("add"), int(info.get("port"))
        except:
            return None, None
    return None, None

html = requests.get(SOURCE_URL, timeout=15).text
sub_urls = extract_sub_urls(html)

nodes = set()

for url in sub_urls:
    try:
        raw = requests.get(url, timeout=10).text.strip()
        for line in decode_subscription(raw):
            if line.startswith(("VMess://", "Trojan://", "Vless://", "Hysteria2://")):
                nodes.add(line.strip())
    except:
        pass

usable = []

for node in nodes:
    host, port = parse_node(node)
    if not host or not port:
        continue
    latency = tcp_ping(host, port)
    if latency and latency < MAX_LATENCY:
        usable.append((latency, node))

usable.sort(key=lambda x: x[0])

with open("sub.txt", "w", encoding="utf-8") as f:
    for _, node in usable:
        f.write(node + "\n")

print(f"✅ 输出可用节点数: {len(usable)}")
