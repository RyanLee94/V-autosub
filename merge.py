import re
import socket
import requests
import time
from urllib.parse import urlparse

# 抓取页
SOURCE_URL = "https://v2raya.net/free-nodes/2025-02-02-free-v2ray-node-subscriptions.html"

# 超时设置
TCP_TIMEOUT = 10
DOWNLOAD_TIMEOUT = 10
TEST_FILE = "https://cachefly.cachefly.net/50mb.test"

def extract_urls(html):
    # 用正则提取所有 https:// 开头的链接
    urls = re.findall(r'https?://[A-Za-z0-9./?=&_-]+', html)
    return list(set(urls))

def get_host_port_from_url(link):
    try:
        parsed = urlparse(link)
        return parsed.hostname, parsed.port
    except:
        return None, None

def test_tcp_connect(host, port):
    if not host or not port:
        return None
    try:
        sock = socket.create_connection((host, port), timeout=TCP_TIMEOUT)
        sock.close()
        return True
    except:
        return None

def test_download_speed(host, port):
    # 测试下载速度，发起请求到测试文件
    try:
        start = time.time()
        r = requests.get(TEST_FILE, timeout=DOWNLOAD_TIMEOUT)
        r.raise_for_status()
        duration = time.time() - start
        return duration
    except:
        return None

html = requests.get(SOURCE_URL, timeout=15).text
sub_urls = extract_urls(html)

nodes = []

for sub in sub_urls:
    try:
        data = requests.get(sub, timeout=10).text.strip()
        for line in data.splitlines():
            line = line.strip()
            if line.startswith(("vmess://", "trojan://", "hysteria2://")):
                nodes.append(line)
    except:
        pass

nodes = list(set(nodes))

usable = []

for node in nodes:
    host, port = get_host_port_from_url(node)
    ok = test_tcp_connect(host, port)
    if ok:
        speed = test_download_speed(host, port)
        if speed:
            usable.append((speed, node))

usable.sort(key=lambda x: x[0])

with open("sub.txt", "w", encoding="utf-8") as f:
    for speed, node in usable:
        f.write(node + "\n")

print(f"Total usable nodes: {len(usable)}")