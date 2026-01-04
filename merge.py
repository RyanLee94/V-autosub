#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
更新/合并订阅脚本（适合在 GitHub Actions 中运行）
功能：
- 从 SOURCE_LISTING_URL 抓取订阅页面中的订阅链接（或你也可以直接把订阅列表写死到 SUB_LIST 中）
- 逐个下载订阅内容，解析出 vmess/trojan/hysteria2 节点
- 解析节点备注中的“剩余流量”，仅保留剩余流量 > MIN_REMAIN_GB 的节点
- 对通过流量筛选的节点做 TCP 连接测速（并发），仅保留延迟 <= MAX_LATENCY 的节点
- 输出合并订阅文件 OUTPUT_FILE（每行一个节点）
"""
import requests
import re
import time
import base64
import socket
import json
import math
import sys
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Set

# ================ 配置 ================
SOURCE_LISTING_URL = "https://v2raya.net/free-nodes/2025-02-02-free-v2ray-node-subscriptions.html"
FETCH_RETRIES = 6
FETCH_WAIT_SECONDS = 6   # 基本重试等待（会做指数退避）
FETCH_TIMEOUT = 20
SUB_TIMEOUT = 15

TCP_TIMEOUT = 8          # 单节点 TCP 连接超时（秒）
MAX_LATENCY = float(int(10))  # 秒，超过则丢弃
MIN_REMAIN_GB = float(5.0)    # 保留流量阈值（GB），可修改或通过环境变量传入
OUTPUT_FILE = "sub.txt"
HEADERS = {"User-Agent": "Mozilla/5.0 (GitHub Actions)"}
MAX_WORKERS = 30        # 并发线程数（测速用）

# 正则：匹配可能的节点行（简单筛选）
NODE_PATTERN = re.compile(r'(vmess://[A-Za-z0-9+/=._-]+|trojan://[^\s\'"<>]+|hysteria2://[^\s\'"<>]+)', re.IGNORECASE)

# ================ 工具函数 ================

def _b64_fix_padding(s: str) -> bytes:
    """修正 base64 padding 并 decode，返回 bytes；若失败抛出异常"""
    s = s.strip()
    # remove possible URI-safe characters
    # try standard base64
    padding = len(s) % 4
    if padding:
        s += '=' * (4 - padding)
    return base64.b64decode(s)

def fetch_with_retry(url: str, retries=FETCH_RETRIES, timeout=FETCH_TIMEOUT, headers=HEADERS) -> str:
    last_exc = None
    for i in range(1, retries+1):
        try:
            print(f"[fetch] ({i}/{retries}) GET {url}")
            r = requests.get(url, headers=headers, timeout=timeout)
            r.raise_for_status()
            return r.text
        except Exception as e:
            last_exc = e
            wait = FETCH_WAIT_SECONDS * (2 ** (i-1))  # 指数退避
            print(f"  -> fetch failed: {e!r}. wait {wait}s then retry.")
            time.sleep(wait)
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts") from last_exc

def extract_links_from_listing(html: str) -> List[str]:
    """从源页中提取所有 http(s) 链接（去重），后续根据内容筛选为订阅链接"""
    raw_links = re.findall(r'https?://[^\s"\'<>]+', html)
    # 一般页面内可能带有很多静态资源链接，先去重并返回
    uniq = list(dict.fromkeys(raw_links))
    print(f"[extract_links] total links found: {len(uniq)}")
    return uniq

def is_likely_subscription_content(text: str) -> bool:
    """判断某个下载到的文本是否可能是订阅内容（含 vmess/trojan/hysteria 或 base64 编码后的这些）"""
    if "vmess://" in text or "trojan://" in text or "hysteria2://" in text:
        return True
    # 有些订阅是 base64 编码的，解码后可能包含 vmess:// 等
    try:
        dec = _b64_fix_padding(text)
        txt = dec.decode('utf-8', errors='ignore')
        if "vmess://" in txt or "trojan://" in txt or "hysteria2://" in txt:
            return True
    except Exception:
        pass
    # 也可能是 json base64（vmess 单独的 base64 json），但这里做通用判断即可
    return False

def extract_nodes_from_text(text: str) -> List[str]:
    """从一个文本中抽取 vmess/trojan/hysteria2 节点（不解码 vmess base64 JSON 的内容）
       text 可能已经是解码后的文本，也可能是直接的订阅文本"""
    nodes = set()
    # 直接寻找行内的 vmess:// trojan:// hysteria2://
    for m in NODE_PATTERN.finditer(text):
        nodes.add(m.group(0).strip())

    # 有些订阅是把整段节点列表用 base64 编码在 body 里，此时尝试 base64 解码并再提取
    try:
        dec = _b64_fix_padding(text)
        s = dec.decode('utf-8', errors='ignore')
        for m in NODE_PATTERN.finditer(s):
            nodes.add(m.group(0).strip())
    except Exception:
        pass

    # return list
    return list(nodes)

def decode_vmess_json_from_node(vmess_node: str) -> Optional[dict]:
    """给定 vmess://base64json 返回 dict（或 None）"""
    try:
        payload = vmess_node[8:].strip()
        raw = _b64_fix_padding(payload)
        s = raw.decode('utf-8', errors='ignore')
        # some vmess servers encode as JSON or as base64(json)
        # parse json safely
        data = json.loads(s)
        return data
    except Exception:
        # 有些 vmess 节点本身是 vmess://{...}（rare），试一下直接去掉 vmess:// 并 json.loads
        try:
            if vmess_node.startswith("vmess://"):
                alt = vmess_node[8:].strip()
                data = json.loads(alt)
                return data
        except Exception:
            return None
    return None

def parse_node_remark_and_remaining(node: str) -> Tuple[Optional[str], Optional[int]]:
    """
    解析节点的备注（remark/ps）和备注中可能包含的“剩余流量”
    返回 (remark_text, remaining_bytes_or_None)
    """
    remark = None
    remain_bytes = None

    try:
        if node.startswith("vmess://"):
            info = decode_vmess_json_from_node(node)
            if info:
                remark = info.get("ps") or info.get("remark") or info.get("ps") or info.get("remarks")
        else:
            # trojan, hysteria2 等 URI 形式：fragment 或 userinfo 中可能有备注（后缀 #remark）
            u = urlparse(node)
            # fragment is the part after '#'
            if u.fragment:
                remark = unquote(u.fragment)
            # sometimes remark is appended as query param or at end of path
            if not remark:
                # trojan://password@host:port#remark -> fragment handled above
                # try URL-decoded whole node after '#'
                if "#" in node:
                    remark = unquote(node.split("#", 1)[1])
    except Exception:
        pass

    if remark:
        # 寻找中文“剩余流量：20.55 GB” 或英文 "Remaining: 20.55 GB" 等
        # 支持单位：B, KB, MB, GB, TB（含大小写，包含中文空格）
        m = re.search(r'剩余流量[:：]\s*([0-9,.]+)\s*([KMGT]?B|[KMGT]?b|[KMGT]|GB|MB|KB|TB)', remark, re.IGNORECASE)
        if not m:
            # 兼容英文或简写，例如 "剩余: 20.55G", "Remaining:20.5 GB"
            m = re.search(r'(剩余|remaining|remain)[:：]?\s*([0-9,.]+)\s*([KMGT]?B|[KMGT]?b|[KMGT]|GB|MB|KB|TB)', remark, re.IGNORECASE)
            if m:
                num = m.group(2)
                unit = m.group(3)
                # unify
                try:
                    remain_bytes = convert_size_to_bytes(num, unit)
                except Exception:
                    remain_bytes = None
        else:
            num = m.group(1)
            unit = m.group(2)
            try:
                remain_bytes = convert_size_to_bytes(num, unit)
            except Exception:
                remain_bytes = None

    return remark, remain_bytes

def convert_size_to_bytes(num_str: str, unit_str: str) -> int:
    """把诸如 '20.55' + 'GB' 转成字节整数"""
    # 清理数字（含逗号）
    num = float(num_str.replace(',', ''))
    unit = unit_str.upper().replace('.', '')
    # 常见单位映射
    if unit in ('B', ''):
        mul = 1
    elif unit in ('K', 'KB'):
        mul = 1024
    elif unit in ('M', 'MB'):
        mul = 1024 ** 2
    elif unit in ('G', 'GB'):
        mul = 1024 ** 3
    elif unit in ('T', 'TB'):
        mul = 1024 ** 4
    else:
        mul = 1
    return int(num * mul)

def parse_host_port(node: str) -> Tuple[Optional[str], Optional[int]]:
    """尽量解析出主机和端口，供 TCP 测速使用"""
    try:
        if node.startswith("vmess://"):
            info = decode_vmess_json_from_node(node)
            if info:
                host = info.get("add") or info.get("address") or info.get("host")
                port = info.get("port")
                try:
                    port = int(port)
                except Exception:
                    port = None
                return host, port
        else:
            u = urlparse(node)
            # urlparse for trojan will parse hostname and port
            return u.hostname, (u.port if u.port else None)
    except Exception:
        pass
    return None, None

def tcp_test(host: str, port: int, timeout=TCP_TIMEOUT) -> Optional[float]:
    """对指定 host:port 做 TCP 建连测试，返回耗时（秒），失败返回 None"""
    if not host or not port:
        return None
    try:
        start = time.time()
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        sock.close()
        return time.time() - start
    except Exception:
        return None

# ================ 主流程 ================

def main():
    print("🚀 开始合并与筛选订阅节点")
    print(f"源页面: {SOURCE_LISTING_URL}")
    try:
        listing_html = fetch_with_retry(SOURCE_LISTING_URL)
    except Exception as e:
        print(f"❌ 无法获取源页面：{e}")
        sys.exit(1)

    candidate_links = extract_links_from_listing(listing_html)

    # 第二步：逐个尝试这些链接，保留那些返回的内容看起来像订阅的链接
    subscription_urls = []
    for link in candidate_links:
        # 过滤一些静态资源（简单规则）
        if any(link.lower().endswith(ext) for ext in ('.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff', '.ttf')):
            continue
        # 只保留 http/https
        if not link.lower().startswith(('http://', 'https://')):
            continue
        try:
            txt = requests.get(link, headers=HEADERS, timeout=SUB_TIMEOUT).text
            if is_likely_subscription_content(txt):
                subscription_urls.append(link)
                print(f"  [OK] subscription candidate: {link}")
        except Exception as e:
            # 忽略请求失败的链接
            # print(f"  [skip] {link} -> {e}")
            continue

    # 如果没有从页面自动识别到订阅链接，也可以手动在这里补充（SUB_LIST）
    if not subscription_urls:
        print("⚠️ 未在页面中自动识别到订阅链接。请检查页面是否通过 JS 动态生成或手动设置订阅列表。")
        # 退出或继续？这里退出
        sys.exit(1)

    print(f"🔗 识别到订阅链接数量: {len(subscription_urls)}")

    # 从每个订阅链接中抽取节点
    all_nodes: Set[str] = set()
    # 同时记录每个订阅链接中的节点与其解析到的剩余流量（用于按订阅保留或调试）
    subs_info = {}

    for su in subscription_urls:
        try:
            txt = requests.get(su, headers=HEADERS, timeout=SUB_TIMEOUT).text.strip()
        except Exception as e:
            print(f"  [warn] 无法下载订阅 {su}: {e}")
            continue
        nodes = extract_nodes_from_text(txt)
        print(f"  [sub] {su} -> nodes found: {len(nodes)}")
        subs_info[su] = nodes
        for n in nodes:
            all_nodes.add(n)

    print(f"📦 去重后总节点数: {len(all_nodes)}")

    # 对每个节点解析备注和剩余流量，先按“剩余流量 > MIN_REMAIN_GB” 筛选
    min_remain_bytes = int(MIN_REMAIN_GB * 1024 ** 3)
    candidate_nodes = []  # 存 (node, remain_bytes, remark)
    for node in all_nodes:
        remark, remain_bytes = parse_node_remark_and_remaining(node)
        # 如果没有解析到流量信息，有两种策略：丢弃或保留等待测速
        # 这里我们只保留明确解析到流量且 >= MIN 的节点
        if remain_bytes is not None and remain_bytes >= min_remain_bytes:
            candidate_nodes.append((node, remain_bytes, remark))
        # 若你想保留那些没有流量信息的节点，请把下面注释取消：
        # else:
        #     candidate_nodes.append((node, remain_bytes, remark))

    print(f"🔎 符合流量阈值（>={MIN_REMAIN_GB} GB）的节点数: {len(candidate_nodes)}")

    if not candidate_nodes:
        print("❌ 未找到满足流量条件的节点。退出。")
        sys.exit(0)

    # 并发 TCP 测速（按 host:port）
    def _test_item(item):
        node, remain_bytes, remark = item
        host, port = parse_host_port(node)
        if not host or not port:
            return None
        latency = tcp_test(host, port, timeout=TCP_TIMEOUT)
        return (latency, node, remain_bytes, remark)

    usable = []
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(candidate_nodes) or 1)) as ex:
        futures = {ex.submit(_test_item, it): it for it in candidate_nodes}
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception:
                continue
            if not result:
                continue
            latency, node, remain_bytes, remark = result
            if latency is not None and latency <= MAX_LATENCY:
                usable.append((latency, node, remain_bytes, remark))
            else:
                # 可选：记录不可用或高延迟的节点
                pass

    usable.sort(key=lambda x: x[0])  # 按延迟排序
    print(f"✅ 最终通过流量与延迟筛选的节点数: {len(usable)}")

    if not usable:
        print("❌ 没有可用节点通过筛选，退出。")
        sys.exit(0)

    # 输出合并订阅（每行一个节点）
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for latency, node, remain, remark in usable:
            f.write(node + "\n")

    print(f"🎉 输出写入: {OUTPUT_FILE}")
    print("完成。")

if __name__ == "__main__":
    main()
