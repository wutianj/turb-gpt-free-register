# -*- coding: utf-8 -*-
"""
代理池配置

每次注册随机抽取一个代理，保证不同 sid 之间彼此独立，避免风控关联。

协议说明：
    - http:// / https://   HTTP(S) 代理
    - socks5://            SOCKS5（DNS 本地解析，可能泄漏）
    - socks5h://           SOCKS5（DNS 在代理端解析，推荐，避免 DNS-IP 错配）
"""
from config.env_loader import apply_env_overrides
import os
import random
from pathlib import Path
from urllib.parse import quote, urlsplit


# 本地代理入口；实际出口地区以代理/分流规则为准。
# 推荐使用 socks5h://（DNS 在代理端解析），避免本地 DNS 与出口 IP 地区错配。
PROXY_POOL = [
    "socks5://127.0.0.1:7897",
]

# 代理池中使用 host:port 或 host:port:user:password 格式时的默认协议。
# 使用显式 http://、https://、socks5://、socks5h:// 前缀的地址不受此项影响。
PROXY_DEFAULT_PROTOCOL = "http"

# 套餐/Plus 试用资格查询与 Codex Agent Token 生成共用这组独立网络策略，
# 避免批量请求被注册代理池中的临时本地代理拖垮，也避免无条件直连造成出口策略失控。
#   auto   = 优先使用 PLAN_CHECK_PROXY 或代理池；本地代理端口未监听时回退直连
#   proxy  = 强制使用 PLAN_CHECK_PROXY 或代理池，失败直接报错
#   direct = 始终直连
PLAN_CHECK_PROXY_MODE = "auto"

# 套餐查询 / Codex Agent Token 生成专用代理。留空时 auto/proxy 模式从 PROXY_POOL 选择。
# 代理可能包含账号密码，因此 WebUI 会把它保存到 .env。
PLAN_CHECK_PROXY = ""

# 查套餐 / 生成 Codex Agent Token 使用独立的短超时和有限重试，避免后台任务长时间卡住。
PLAN_CHECK_TIMEOUT = 15.0
PLAN_CHECK_MAX_ATTEMPTS = 3
PLAN_CHECK_RETRY_DELAY = 2.0

# 新注册账号的权益可能存在短暂同步延迟。首次查询失败，或返回 free 且暂未发现
# Plus 试用资格时，等待该秒数后再复查一次；设为 0 可关闭复查。
PLAN_CHECK_REGISTRATION_RECHECK_DELAY = 2.0

# 自动、手动和批量套餐查询共用同一个后台队列；Codex Agent Token 使用独立队列，
# 但复用这里的网络模式、请求启动间隔与随机抖动，避免批量后台请求过于集中。
PLAN_CHECK_WORKERS = 3
PLAN_CHECK_QUEUE_LIMIT = 500
PLAN_CHECK_MIN_INTERVAL = 1.0
PLAN_CHECK_JITTER = 0.8

# MoMo 检测复用套餐查询的网络策略，但使用独立的低并发队列。
MOMO_CHECK_WORKERS = 2
MOMO_CHECK_TIMEOUT = 20.0


def normalize_proxy_url(value: str | None, *, default_protocol: str | None = None) -> str:
    """将供应商常见代理格式规范化为 curl_cffi 可用的 URL。"""
    text = str(value or "").strip().lstrip("\"'").rstrip("\"'").strip()
    if not text or "://" in text:
        return text
    parts = text.split(":", 3)
    if len(parts) not in (2, 4) or not parts[0] or not parts[1].isdigit():
        raise ValueError("代理格式应为 scheme://user:password@host:port 或 host:port:user:password")
    protocol = str(default_protocol or PROXY_DEFAULT_PROTOCOL or "http").strip().lower()
    if protocol not in {"http", "https", "socks5", "socks5h"}:
        raise ValueError(f"PROXY_DEFAULT_PROTOCOL 无效: {protocol}")
    host, port = parts[0], parts[1]
    if len(parts) == 2:
        return f"{protocol}://{host}:{port}"
    username, password = quote(parts[2], safe=""), quote(parts[3], safe="")
    return f"{protocol}://{username}:{password}@{host}:{port}"


def pick_proxy() -> str:
    """先均衡选择代理提供商，再从该提供商随机抽取线路。"""
    normalized = [normalize_proxy_url(value) for value in PROXY_POOL]
    normalized = [value for value in normalized if value]
    if not normalized:
        return ""
    providers: dict[str, list[str]] = {}
    for value in normalized:
        host = (urlsplit(value).hostname or value).lower()
        providers.setdefault(host, []).append(value)
    provider = random.choice(list(providers))
    return random.choice(providers[provider])


# 兼容入口：默认每次进程启动随机选一个，作为本次注册全程的固定代理
PROXY = pick_proxy()

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'PROXY_POOL': 'list_str_multiline',
    'PROXY_DEFAULT_PROTOCOL': 'str',
    'PLAN_CHECK_PROXY_MODE': 'str',
    'PLAN_CHECK_PROXY': 'str',
    'PLAN_CHECK_TIMEOUT': 'float',
    'PLAN_CHECK_MAX_ATTEMPTS': 'int',
    'PLAN_CHECK_RETRY_DELAY': 'float',
    'PLAN_CHECK_REGISTRATION_RECHECK_DELAY': 'float',
    'PLAN_CHECK_WORKERS': 'int',
    'PLAN_CHECK_QUEUE_LIMIT': 'int',
    'PLAN_CHECK_MIN_INTERVAL': 'float',
    'PLAN_CHECK_JITTER': 'float',
    'MOMO_CHECK_WORKERS': 'int',
    'MOMO_CHECK_TIMEOUT': 'float',
})

# Large pools exceed Windows' 32767-character environment-variable limit.
# When configured, load one proxy per line from a protected local file.
PROXY_POOL_FILE = os.getenv("PROXY_POOL_FILE", "").strip()
if PROXY_POOL_FILE:
    proxy_pool_path = Path(PROXY_POOL_FILE)
    if not proxy_pool_path.is_file():
        raise RuntimeError(f"PROXY_POOL_FILE not found: {proxy_pool_path}")
    PROXY_POOL = [
        line.strip()
        for line in proxy_pool_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
PROXY = pick_proxy()
