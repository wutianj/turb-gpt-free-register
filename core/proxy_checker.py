"""Bounded, redacted proxy connectivity checks for the WebUI."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from curl_cffi import requests

from config.proxy import normalize_proxy_url


CHECK_URL = "https://chatgpt.com/auth/login"


def check_proxy(proxy: str, *, index: int, timeout: float = 10.0) -> dict:
    started = time.perf_counter()
    try:
        normalized = normalize_proxy_url(proxy)
        response = requests.get(
            CHECK_URL,
            proxy=normalized,
            timeout=max(2.0, min(30.0, float(timeout))),
            allow_redirects=False,
            impersonate="chrome",
        )
        status = int(response.status_code)
        ok = 200 <= status < 500 and status != 407
        return {
            "index": int(index),
            "ok": ok,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "status_code": status,
            "error_type": None if ok else f"HTTP_{status}",
        }
    except Exception as exc:
        return {
            "index": int(index),
            "ok": False,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "status_code": None,
            "error_type": type(exc).__name__,
        }


def check_proxy_batch(proxies: list[str], *, timeout: float = 10.0, workers: int = 20) -> list[dict]:
    values = [str(item or "").strip() for item in proxies if str(item or "").strip()]
    if not values:
        return []
    if len(values) > 500:
        raise ValueError("单次最多检测 500 条代理")
    pool_size = max(1, min(20, int(workers), len(values)))
    results = []
    with ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="proxy-check") as executor:
        futures = {
            executor.submit(check_proxy, value, index=index, timeout=timeout): index
            for index, value in enumerate(values)
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: int(item["index"]))
