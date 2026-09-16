# -*- coding: utf-8 -*-
"""RoxyBrowser 本地 API 客户端。"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

import requests

from config import roxybrowser as _cfg

logger = logging.getLogger(__name__)


_LOCAL_API_START_LOCK = threading.Lock()
_PROFILE_CREATE_LOCK = threading.Lock()
_COUNTRY_CODE_RE = re.compile(r"^[A-Za-z]{2}$")
_PROXY_COUNTRY_MARKER_RE = re.compile(
    r"(?:^|[-_.])(?:region|country)[-_.]?([A-Za-z]{2})(?=$|[-_.])",
    re.IGNORECASE,
)


@dataclass
class RoxyOpenResult:
    profile_id: str
    raw: dict
    debugger_address: str | None = None
    webdriver_url: str | None = None
    ws_endpoint: str | None = None
    created_by_run: bool = False
    static_cache_dir: str | None = None


_STATIC_CACHE_LOCK = threading.Lock()


def _is_profile_create_busy_error(exc: Exception) -> bool:
    text = str(exc or "").lower()
    return any(marker in text for marker in ("正在创建", "创建中", "already creating", "creation in progress"))


def _prepare_static_cache_dir() -> Path | None:
    if not bool(getattr(_cfg, "ROXY_STATIC_CACHE_ENABLED", False)):
        return None
    template = Path(str(getattr(_cfg, "ROXY_STATIC_CACHE_TEMPLATE_DIR", "data/roxy-static-cache-template"))).resolve()
    target = (Path(tempfile.gettempdir()).resolve() / f"roxy-static-cache-{uuid.uuid4().hex}").resolve()
    target.mkdir(parents=True)
    with _STATIC_CACHE_LOCK:
        if template.is_dir():
            shutil.copytree(template, target, dirs_exist_ok=True)
    return target


def _cleanup_static_cache_dir(path_value: str | None) -> None:
    if not path_value:
        return
    path = Path(path_value).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if temp_root not in path.parents or not path.name.startswith("roxy-static-cache-"):
        return
    template = Path(str(getattr(_cfg, "ROXY_STATIC_CACHE_TEMPLATE_DIR", "data/roxy-static-cache-template"))).resolve()
    with _STATIC_CACHE_LOCK:
        if path.is_dir() and not template.exists():
            template.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(path, template)
    shutil.rmtree(path, ignore_errors=True)


def _strip_slashes(value: str) -> str:
    return str(value or "").strip().strip("/")


def _join_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _mask_proxy(proxy_url: str) -> str:
    text = str(proxy_url or "").strip().lstrip("\"'").rstrip("\"'").strip()
    parsed = urlparse(text)
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://***:***@{host}{port}"
    # Proxy suppliers commonly use host:port:user:password.  Do not emit
    # credentials to the task log if this format is rejected or malformed.
    parts = text.split(":", 3)
    if len(parts) == 4 and parts[1].isdigit():
        return f"http://***:***@{parts[0]}:{parts[1]}"
    return text


def extract_proxy_country_code(proxy: str | dict | None) -> str:
    """Return a two-letter country code without retaining proxy credentials."""

    if isinstance(proxy, dict):
        for key in ("proxyCountryCode", "countryCode", "country_code", "country", "region"):
            direct = str(proxy.get(key) or "").strip()
            if _COUNTRY_CODE_RE.fullmatch(direct):
                return direct.upper()
        for key in ("proxyUserName", "proxyUsername", "proxyUser", "username", "user"):
            code = extract_proxy_country_code(str(proxy.get(key) or ""))
            if code:
                return code
        return ""

    text = str(proxy or "").strip().lstrip("\"'").rstrip("\"'").strip()
    if not text:
        return ""
    if _COUNTRY_CODE_RE.fullmatch(text):
        return text.upper()

    candidate = text
    if "://" in text:
        parsed = urlparse(text)
        candidate = unquote(parsed.username or "")
    else:
        parts = text.split(":", 3)
        if len(parts) == 4 and parts[1].isdigit():
            candidate = unquote(parts[2])
        else:
            provider_code = re.fullmatch(r"[A-Za-z][A-Za-z0-9_.+-]*:([A-Za-z]{2})", text)
            if provider_code:
                return provider_code.group(1).upper()

    if _COUNTRY_CODE_RE.fullmatch(candidate):
        return candidate.upper()
    marker = _PROXY_COUNTRY_MARKER_RE.search(candidate)
    return marker.group(1).upper() if marker else ""


def _proxy_url_to_roxy_info(proxy_url: str) -> dict:
    """
    将 config/proxy.py 里的代理 URL 转成 Roxy /browser/create 的 proxyInfo。

    支持：
      http://user:pass@host:port
      https://user:pass@host:port
      socks5://user:pass@host:port
      socks5h://user:pass@host:port  -> Roxy 侧按 SOCKS5 处理
      host:port:user:password         -> 由 ROXY_PROXY_DEFAULT_PROTOCOL 决定
    """
    text = str(proxy_url or "").strip().lstrip("\"'").rstrip("\"'").strip()
    if not text:
        raise ValueError("代理为空")
    has_explicit_scheme = "://" in text
    parsed = urlparse(text)
    if not has_explicit_scheme:
        parts = text.split(":", 3)
        if len(parts) not in (2, 4) or not parts[0] or not parts[1].isdigit():
            raise ValueError(f"代理格式无效: {_mask_proxy(text)}")
        host, port = parts[0], parts[1]
        username = parts[2] if len(parts) == 4 else ""
        password = parts[3] if len(parts) == 4 else ""
        default_scheme = str(getattr(_cfg, "ROXY_PROXY_DEFAULT_PROTOCOL", "http") or "http").strip().lower()
        if default_scheme not in ("http", "https", "socks5", "socks5h"):
            raise ValueError(f"ROXY_PROXY_DEFAULT_PROTOCOL 无效: {default_scheme}")
        parsed = urlparse(f"{default_scheme}://{host}:{port}")
    else:
        username = unquote(parsed.username) if parsed.username else ""
        password = unquote(parsed.password) if parsed.password else ""
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https", "socks5", "socks5h"):
        raise ValueError(f"Roxy 暂不支持该代理协议: {scheme or '-'}")
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"代理格式缺少 host/port: {_mask_proxy(text)}")

    protocol = {
        "http": "HTTP",
        "https": "HTTPS",
        "socks5": "SOCKS5",
        "socks5h": "SOCKS5",
    }[scheme]
    # Roxy /browser/create 官方字段是：
    # proxyMethod / proxyCategory / ipType / protocol / host / port / proxyUserName / proxyPassword / checkChannel
    # 之前误用了 proxyType/proxyHost/proxyPort/proxyAccount，Roxy 会忽略，导致创建窗口实际未设置代理。
    info = {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV4",
        "protocol": protocol,
        "host": parsed.hostname,
        "port": str(parsed.port),
    }
    if username:
        info["proxyUserName"] = username
    if password:
        info["proxyPassword"] = password
    check_channel = str(getattr(_cfg, "ROXY_PROXY_CHECK_CHANNEL", "") or "").strip()
    if check_channel:
        info["checkChannel"] = check_channel
    return info


def _dig(payload: dict, *keys: str):
    cur = payload
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first(payload: dict, paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        value = _dig(payload, *path)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _workspace_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_WORKSPACE_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _project_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_PROJECT_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _apply_data_saver_open_args(params: dict) -> dict:
    """在 Roxy 启动参数中尽早关闭图片加载，覆盖无扩展名图片 URL。

    Network.setBlockedURLs 只能按 URL 后缀拦截，而 Roxy 浏览器在 Selenium 连接
    前就已经启动；使用 Chromium 开关可以让图片在首个页面请求前就被禁用。该开关
    只在用户明确开启省流量模式且包含 image 类型时追加。
    """
    try:
        from config import browser as _browser_cfg

        if not bool(getattr(_browser_cfg, "BROWSER_DATA_SAVER_MODE", False)):
            return params
        raw_types = getattr(_browser_cfg, "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", [])
        if isinstance(raw_types, str):
            types = {item.strip().lower() for item in raw_types.replace(",", "\n").splitlines() if item.strip()}
        else:
            types = {str(item or "").strip().lower() for item in (raw_types or []) if str(item or "").strip()}
        if "image" not in types and "images" not in types and "img" not in types:
            return params

        current = params.get("args")
        if isinstance(current, (list, tuple)):
            args = list(current)
        elif current:
            args = [str(current)]
        else:
            args = []
        switch = "--blink-settings=imagesEnabled=false"
        if switch not in args:
            args.append(switch)
        params["args"] = args
    except Exception as exc:
        logger.debug("[Roxy] 添加省流量图片启动参数失败，继续使用原参数：%s", exc)
    return params


def _random_roxy_os() -> str:
    raw = str(getattr(_cfg, "ROXY_RANDOM_OS_CHOICES", "Windows,macOS") or "Windows,macOS")
    choices = [
        x.strip()
        for part in raw.replace("\n", ",").replace(";", ",").split(",")
        for x in [part]
        if x.strip()
    ]
    valid = {"Windows", "macOS", "Linux", "IOS", "Android"}
    choices = [x for x in choices if x in valid]
    if not choices:
        choices = ["Windows", "macOS"]
    return random.choice(choices)


def _random_roxy_locale() -> str:
    """从 ROXY_LOCALE_CHOICES 随机取一个 BCP-47 locale。

    仅对本地无限窗口 API（roxy-api.mjs）生效：该 API 会把 locale 展开为
    appLocale / acceptLang / timeZone 三个互相一致的字段，写进每个档案的
    lumi.conf。官方 API 不认识 locale 字段，会直接忽略，不影响兼容性。
    """
    raw = str(getattr(_cfg, "ROXY_LOCALE_CHOICES", "") or "").strip()
    choices = [
        x.strip()
        for part in raw.replace("\n", ",").replace(";", ",").split(",")
        for x in [part]
        if x.strip()
    ]
    if not choices:
        return ""
    return random.choice(choices)


def _random_roxy_profile_name() -> str:
    prefix = str(getattr(_cfg, "ROXY_PROFILE_NAME_PREFIX", "rb") or "rb").strip() or "rb"
    # Roxy 环境名每次创建都不同：前缀 + 毫秒时间戳 + 随机 4 位十六进制。
    return f"{prefix}-{int(time.time() * 1000)}-{random.randrange(0x10000):04x}"


def _local_api_port(api_base: str) -> int | None:
    """Return the port for a loopback API base; remote/custom hosts are excluded."""
    try:
        parsed = urlparse(str(api_base or "").strip())
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            return None
        return int(parsed.port or (443 if parsed.scheme == "https" else 80))
    except (TypeError, ValueError):
        return None


def _is_connection_refused(exc: Exception) -> bool:
    """Only classify transport-level refusal as safe for API process recovery."""
    if isinstance(exc, requests.exceptions.ConnectionError):
        return True
    text = str(exc or "").lower()
    return any(
        marker in text
        for marker in (
            "failed to establish a new connection",
            "connection refused",
            "max retries exceeded",
            "winerror 10061",
        )
    )


def _start_local_api(api_base: str) -> bool:
    """Start the bundled local API once and wait for its health endpoint."""
    port = _local_api_port(api_base)
    if port is None or os.name != "nt":
        return False

    script = Path(__file__).resolve().parents[1] / "tools" / "roxy-unlimited-windows" / "svc.ps1"
    if not script.is_file():
        logger.warning("[Roxy] 本地 API 已拒绝连接，但未找到自动启动脚本：%s", script)
        return False

    with _LOCAL_API_START_LOCK:
        health_url = _join_url(api_base, "/health")
        try:
            health = requests.get(health_url, timeout=2)
            if health.ok:
                return True
        except requests.RequestException:
            pass

        command = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Action",
            "start",
            "-Port",
            str(port),
        ]
        try:
            # svc.ps1 starts a detached Node process and writes its own logs.  Do
            # not capture its stdio: on Windows the child can retain those pipe
            # handles after the PowerShell wrapper has done its work, leaving
            # subprocess.run waiting forever even though the API is healthy.
            process = subprocess.Popen(
                command,
                cwd=str(script.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            logger.warning("[Roxy] 自动启动本地 API 异常：%s: %s", type(exc).__name__, exc)
            return False

        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            try:
                health = requests.get(health_url, timeout=2)
                if health.ok:
                    logger.warning("[Roxy] 已自动启动本地 API：port=%s pid=%s", port, process.pid)
                    return True
            except requests.RequestException:
                pass
            if process.poll() is not None:
                logger.warning("[Roxy] 自动启动本地 API 失败：exit=%s", process.returncode)
                return False
            time.sleep(0.5)

        logger.warning("[Roxy] 自动启动本地 API 超时：port=%s pid=%s", port, process.pid)
        try:
            process.terminate()
        except Exception:
            pass
        return False


class RoxyBrowserClient:
    def __init__(self, api_base: str | None = None, token: str | None = None):
        self.api_base = (api_base or _cfg.ROXY_API_BASE).strip()
        self.token = (token if token is not None else _cfg.ROXY_API_TOKEN).strip()
        self.http = requests.Session()
        self.last_create_metadata: dict = {}
        if self.token:
            # 官方文档要求所有接口请求头必须加 token。这里同时兼容 token / Authorization。
            self.http.headers.update({
                "token": self.token,
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        text = str(exc or "").lower()
        return (
            "timeout" in text
            or "timed out" in text
            or "connection" in text
            or "temporarily" in text
            or "http 500" in text
            or "http 502" in text
            or "http 503" in text
            or "http 504" in text
            or "http 429" in text
        )

    def request(self, method: str, path: str, *, params: dict | None = None, json_body: dict | None = None) -> dict:
        url = _join_url(self.api_base, path)
        method_u = method.upper()
        # create 超时后服务端可能已创建环境，直接重试可能产生孤儿环境；默认不重试 create。
        is_create = str(path or "").rstrip("/").endswith("/create") or "browser/create" in str(path or "")
        max_attempts = 1 if is_create else max(1, int(getattr(_cfg, "ROXY_API_RETRIES", 3) or 3))
        base_delay = max(0.5, float(getattr(_cfg, "ROXY_API_RETRY_DELAY", 2) or 2))
        api_bootstrap_attempts = 1 if _local_api_port(self.api_base) is not None else 0
        last_exc: Exception | None = None
        attempt = 0
        while attempt < max_attempts:
            attempt += 1
            try:
                logger.debug(
                    "[Roxy] %s %s params=%s body=%s attempt=%s/%s",
                    method, url, params, json_body, attempt, max_attempts,
                )
                resp = self.http.request(
                    method_u,
                    url,
                    params=params or None,
                    json=json_body if json_body is not None else None,
                    timeout=max(5, int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)),
                )
                text = resp.text or ""
                try:
                    payload = resp.json()
                except Exception:
                    payload = {"raw": text}
                if not (200 <= resp.status_code < 300):
                    raise RuntimeError(f"Roxy API 请求失败 {method_u} {path} HTTP {resp.status_code}: {text[:500]}")
                if isinstance(payload, dict):
                    code = payload.get("code")
                    ok = payload.get("ok")
                    success = payload.get("success")
                    if code not in (None, 0, 200, "0", "200") and ok is not True and success is not True:
                        msg = payload.get("msg") or payload.get("message") or payload.get("error") or json.dumps(payload, ensure_ascii=False)[:500]
                        raise RuntimeError(f"Roxy API 返回失败 {method_u} {path}: {msg}")
                if attempt > 1:
                    logger.info("[Roxy] API 重试成功：%s %s attempt=%s/%s", method_u, path, attempt, max_attempts)
                return payload if isinstance(payload, dict) else {"data": payload}
            except Exception as exc:
                last_exc = exc
                if api_bootstrap_attempts and _is_connection_refused(exc):
                    api_bootstrap_attempts = 0
                    if _start_local_api(self.api_base):
                        # A refused TCP connection cannot have reached the API, so one
                        # retry is safe even for /browser/create (which is otherwise
                        # intentionally single-attempt to avoid duplicate profiles).
                        max_attempts = max(max_attempts, attempt + 1)
                        continue
                retryable = self._is_retryable_error(exc)
                if attempt >= max_attempts or not retryable:
                    raise
                delay = base_delay * attempt
                logger.warning(
                    "[Roxy] API 请求失败，将在 %.1fs 后重试：%s %s attempt=%s/%s error=%s",
                    delay, method_u, path, attempt, max_attempts, exc,
                )
                time.sleep(delay)
        raise last_exc or RuntimeError(f"Roxy API 请求失败 {method_u} {path}")

    def try_request(self, method: str, path: str, *, params: dict | None = None, json_body: dict | None = None) -> tuple[bool, dict | str]:
        """宽松请求：用于探测不同 Roxy 版本接口，失败不抛出。"""
        try:
            return True, self.request(method, path, params=params, json_body=json_body)
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _extract_workspace_items(payload: dict) -> list[dict]:
        """解析 /browser/workspace：团队 rows + project_details 项目列表；兼容递归兜底。"""
        out = []

        # 官方结构：data.rows[].id/workspaceName/project_details[].projectId/projectName
        rows = None
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict):
                rows = data.get("rows") or data.get("list") or data.get("records")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                wid = row.get("id") or row.get("workspaceId") or row.get("workspace_id")
                wname = row.get("workspaceName") or row.get("workspace_name") or row.get("name") or str(wid or "")
                projects = row.get("project_details") or row.get("projectDetails") or row.get("projects") or []
                if isinstance(projects, list) and projects:
                    for proj in projects:
                        if not isinstance(proj, dict):
                            continue
                        pid = proj.get("projectId") or proj.get("project_id") or proj.get("id")
                        pname = proj.get("projectName") or proj.get("project_name") or proj.get("name") or str(pid or "")
                        if wid:
                            out.append({
                                "id": str(wid),
                                "name": str(wname),
                                "projectId": str(pid or ""),
                                "projectName": str(pname or ""),
                                "label": f"{wname} / {pname} ({wid}/{pid})" if pid else f"{wname} ({wid})",
                                "raw": {"workspace": row, "project": proj},
                            })
                elif wid:
                    out.append({
                        "id": str(wid),
                        "name": str(wname),
                        "projectId": "",
                        "projectName": "",
                        "label": f"{wname} ({wid})",
                        "raw": row,
                    })

        if out:
            return out

        # 兜底：递归抽 workspace/team/company 结构。
        def pick_id_name(item: dict) -> tuple[str, str]:
            wid = _first(item, [
                ("workspaceId",), ("workspace_id",), ("workspaceID",),
                ("teamId",), ("team_id",), ("teamID",),
                ("companyId",), ("company_id",), ("orgId",), ("org_id",),
                ("id",), ("value",), ("key",),
            ])
            name = _first(item, [
                ("workspaceName",), ("workspace_name",),
                ("teamName",), ("team_name",),
                ("companyName",), ("company_name",),
                ("orgName",), ("org_name",),
                ("name",), ("label",), ("title",), ("remark",),
            ])
            return wid, name

        def looks_like_workspace(item: dict) -> bool:
            keys = {str(k).lower() for k in item.keys()}
            joined = " ".join(keys)
            return any(x in joined for x in ("workspace", "team", "company", "org")) or ("id" in keys and "name" in keys)

        def walk(node):
            if isinstance(node, dict):
                wid, name = pick_id_name(node)
                if wid and looks_like_workspace(node):
                    out.append({"id": wid, "name": name or wid, "projectId": "", "projectName": "", "label": f"{name or wid} ({wid})", "raw": node})
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)
        dedup = {}
        for item in out:
            raw_keys = {str(k).lower() for k in (item.get("raw") or {}).keys()}
            if "dirid" in raw_keys and not any(k in raw_keys for k in ("workspaceid", "teamid", "companyid")):
                continue
            key = f"{item.get('id')}::{item.get('projectId','')}"
            dedup[key] = item
        return list(dedup.values())

    def list_workspaces(self) -> dict:
        """
        获取 Roxy 团队/工作区列表。
        Roxy 不同版本路径可能有差异，因此先试配置路径，再试常见路径。
        """
        configured = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_PATH", "") or "").strip()
        method = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_METHOD", "GET") or "GET").upper()
        candidates = []
        if configured:
            candidates.append((method, configured))
        candidates.extend([
            ("GET", "/browser/workspace"),
            ("POST", "/browser/workspace"),
            ("GET", "/workspace/list"),
            ("POST", "/workspace/list"),
            ("GET", "/workspace"),
            ("POST", "/workspace"),
            ("GET", "/team/list"),
            ("POST", "/team/list"),
            ("GET", "/team"),
            ("POST", "/team"),
            ("GET", "/workspaces"),
            ("GET", "/teams"),
            ("GET", "/user/workspace/list"),
            ("POST", "/user/workspace/list"),
            ("GET", "/user/team/list"),
            ("POST", "/user/team/list"),
            ("GET", "/api/workspace/list"),
            ("POST", "/api/workspace/list"),
            ("GET", "/api/team/list"),
            ("POST", "/api/team/list"),
            ("GET", "/browser/workspace/list"),
            ("POST", "/browser/workspace/list"),
            ("GET", "/browser/team/list"),
            ("POST", "/browser/team/list"),
        ])

        errors = []
        seen = set()
        for m, path in candidates:
            key = (m, path)
            if key in seen:
                continue
            seen.add(key)
            ok, payload = self.try_request(m, path)
            if not ok:
                errors.append({"method": m, "path": path, "error": payload})
                continue
            items = self._extract_workspace_items(payload if isinstance(payload, dict) else {})
            if items:
                return {"ok": True, "path": path, "method": m, "items": items, "raw": payload}
            errors.append({"method": m, "path": path, "error": "响应中未解析到团队/工作区列表", "payload": payload})

        return {"ok": False, "items": [], "errors": errors}

    def create_profile(self, payload: dict | None = None) -> str:
        body = dict(getattr(_cfg, "ROXY_PROFILE_CREATE_PAYLOAD", {}) or {})
        random_name_enabled = bool(getattr(_cfg, "ROXY_RANDOM_PROFILE_NAME_ON_CREATE", True))
        if random_name_enabled:
            # 覆盖 ROXY_PROFILE_CREATE_PAYLOAD 里的固定 name，避免所有 Roxy 窗口同名。
            body["name"] = _random_roxy_profile_name()
        random_os_enabled = bool(getattr(_cfg, "ROXY_RANDOM_OS_ON_CREATE", True))
        if random_os_enabled:
            # 每次创建环境随机 Windows / macOS；覆盖 ROXY_PROFILE_CREATE_PAYLOAD 里的固定 os。
            body["os"] = _random_roxy_os()
            # osVersion 跟 os 强绑定，随机 OS 时不沿用固定版本，避免 macOS 版本传给 Windows。
            body.pop("osVersion", None)
        else:
            default_os = str(getattr(_cfg, "ROXY_DEFAULT_OS", "macOS") or "macOS").strip()
            if default_os:
                # Roxy 官方枚举大小写敏感：Windows / macOS / Linux / IOS / Android。
                body.setdefault("os", default_os)
            default_os_version = str(getattr(_cfg, "ROXY_DEFAULT_OS_VERSION", "") or "").strip()
            if default_os_version:
                body.setdefault("osVersion", default_os_version)
        # 每次创建环境随机语言/时区。本地无限 API 会把 locale 展开成
        # appLocale/acceptLang/timeZone 一并写入指纹，避免所有窗口共用模板的
        # 同一套语言和时区。官方 API 忽略该字段。
        locale_random_enabled = bool(getattr(_cfg, "ROXY_RANDOM_LOCALE_ON_CREATE", True))
        if locale_random_enabled and not body.get("locale"):
            locale_value = _random_roxy_locale()
            if locale_value:
                body["locale"] = locale_value
        workspace_id = _workspace_id_value()
        if workspace_id:
            # Roxy 官方 /browser/create 要求 workspaceId。
            body.setdefault("workspaceId", workspace_id)
        project_id = _project_id_value()
        if project_id:
            body.setdefault("projectId", project_id)
        if bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False)) and not body.get("proxyInfo"):
            from config import proxy as _proxy_cfg

            proxy_url = _proxy_cfg.pick_proxy()
            if proxy_url:
                proxy_info = _proxy_url_to_roxy_info(proxy_url)
                body["proxyInfo"] = proxy_info
                logger.info(
                    "[Roxy] 创建环境启用代理池：proxy=%s type=%s host=%s port=%s",
                    _mask_proxy(proxy_url),
                    proxy_info.get("protocol") or proxy_info.get("proxyCategory"),
                    proxy_info.get("host"),
                    proxy_info.get("port"),
                )
            else:
                logger.warning("[Roxy] 已启用 ROXY_CREATE_USE_PROXY_POOL，但 PROXY_POOL 为空，本次创建环境不设置代理")
        if payload:
            body.update(payload)
        if not body.get("workspaceId"):
            raise RuntimeError(
                "Roxy 创建环境需要 workspaceId。请在 config/roxybrowser.py 或 WebUI 的 RoxyBrowser 配置中填写 ROXY_WORKSPACE_ID，"
                "或直接在 ROXY_PROFILE_CREATE_PAYLOAD 里加入 {'workspaceId': '你的工作区ID'}。"
            )
        logger.info(
            "[Roxy] 创建环境参数：workspaceId=%s projectId=%s name=%s random_name=%s os=%s osVersion=%s random_os=%s locale=%s random_locale=%s",
            body.get("workspaceId"),
            body.get("projectId") or "-",
            body.get("name") or "-",
            random_name_enabled,
            body.get("os") or "-",
            body.get("osVersion") or "-",
            random_os_enabled,
            body.get("locale") or "-",
            locale_random_enabled,
        )
        with _PROFILE_CREATE_LOCK:
            result = None
            for attempt in range(1, 6):
                try:
                    result = self.request(_cfg.ROXY_CREATE_METHOD, _cfg.ROXY_CREATE_PATH, json_body=body)
                    break
                except Exception as exc:
                    if not _is_profile_create_busy_error(exc) or attempt >= 5:
                        raise
                    delay = min(5.0, 1.0 + attempt)
                    logger.warning("[Roxy] 环境创建接口忙，第 %s/5 次尝试，%.1f 秒后重试", attempt, delay)
                    time.sleep(delay)
            if result is None:
                raise RuntimeError("Roxy 创建环境未返回结果")
        profile_id = _first(result, [
            ("id",), ("dirId",), ("dir_id",), ("profile_id",), ("profileId",), ("browser_id",),
            ("data", "id"), ("data", "dirId"), ("data", "dir_id"),
            ("data", "profile_id"), ("data", "profileId"), ("data", "browser_id"),
        ])
        if not profile_id:
            raise RuntimeError(f"Roxy 创建环境成功但未返回 dirId/profile_id: {result}")
        proxy_info = body.get("proxyInfo") if isinstance(body.get("proxyInfo"), dict) else {}
        # Keep only comparison-safe creation settings with the account record.
        # Proxy addresses and credentials intentionally remain out of persistence.
        self.last_create_metadata = {
            "profile_created": True,
            "os": body.get("os"),
            "os_version": body.get("osVersion") or None,
            "random_os": random_os_enabled,
            "random_profile_name": random_name_enabled,
            "locale": body.get("locale") or None,
            "random_locale": bool(getattr(_cfg, "ROXY_RANDOM_LOCALE_ON_CREATE", True)),
            "proxy_pool_enabled": bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False)),
            "proxy_protocol": proxy_info.get("protocol") or proxy_info.get("proxyCategory") or None,
            "proxy_country_code": extract_proxy_country_code(proxy_info) or None,
        }
        return profile_id

    @staticmethod
    def _normalize_profile_id(value: str | None) -> str:
        text = str(value or "").strip()
        # WebUI/人工配置里常用 - 表示“未配置”，这里统一按空处理。
        if text in ("-", "—", "无", "空", "none", "None", "null", "NULL"):
            return ""
        return text

    def open_profile(self, profile_id: str | None = None) -> RoxyOpenResult:
        one_profile = bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
        configured_pid = self._normalize_profile_id(profile_id if profile_id is not None else getattr(_cfg, "ROXY_PROFILE_ID", ""))
        if one_profile and configured_pid:
            raise RuntimeError(
                "已启用 ROXY_ONE_PROFILE_PER_ACCOUNT=True（一号一环境），"
                "不能配置/传入固定 ROXY_PROFILE_ID；请留空以便每个账号创建新环境。"
            )

        pid = configured_pid
        created_by_run = False
        if not pid:
            pid = self.create_profile()
            created_by_run = True
            logger.info("[Roxy] 已创建临时环境：%s", pid)

        path = str(_cfg.ROXY_OPEN_PATH).format(profile_id=pid)
        params = dict(getattr(_cfg, "ROXY_OPEN_EXTRA_PARAMS", {}) or {})
        # Roxy 官方 /browser/open body: {workspaceId, dirId, args, forceOpen, headless}
        params.setdefault("workspaceId", _workspace_id_value())
        params.setdefault("dirId", int(pid) if str(pid).isdigit() else pid)
        params.setdefault("args", [])
        params.setdefault("forceOpen", True)
        static_cache_dir = _prepare_static_cache_dir()
        if static_cache_dir is not None:
            params["args"] = list(params.get("args") or []) + [f"--disk-cache-dir={static_cache_dir}"]
        _apply_data_saver_open_args(params)
        # ROXY_OPEN_HEADLESS 是显式开关，优先级应高于 ROXY_OPEN_EXTRA_PARAMS，
        # 否则 extra 里残留 headless=False 会导致 WebUI 保存无头后仍弹窗口。
        params["headless"] = bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False))
        logger.info("[Roxy] open 参数：profile=%s headless=%s keep_open=%s", pid, params.get("headless"), getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False))
        try:
            result = self.request(
                _cfg.ROXY_OPEN_METHOD,
                path,
                params=params if _cfg.ROXY_OPEN_METHOD.upper() == "GET" else None,
                json_body=params if _cfg.ROXY_OPEN_METHOD.upper() != "GET" else None,
            )
        except Exception:
            _cleanup_static_cache_dir(str(static_cache_dir) if static_cache_dir else None)
            raise
        debugger_address = self._extract_debugger_address(result)
        logger.info("[Roxy] open 返回摘要: debugger=%s raw=%s", debugger_address, json.dumps(result, ensure_ascii=False)[:800])
        webdriver_url = _first(result, [
            ("webdriver",), ("webDriver",), ("webdriver_url",), ("webdriverUrl",),
            ("selenium",), ("selenium_url",), ("seleniumUrl",),
            ("data", "webdriver"), ("data", "webDriver"), ("data", "webdriver_url"), ("data", "webdriverUrl"),
            ("data", "selenium"), ("data", "selenium_url"), ("data", "seleniumUrl"),
        ]) or None
        ws_endpoint = _first(result, [
            ("ws",), ("wsEndpoint",), ("ws_endpoint",), ("debuggerWsUrl",),
            ("data", "ws"), ("data", "wsEndpoint"), ("data", "ws_endpoint"), ("data", "debuggerWsUrl"),
        ]) or None
        if not debugger_address and not webdriver_url:
            raise RuntimeError(f"Roxy 已打开环境但未返回 Selenium/调试地址，请检查 ROXY_OPEN_PATH 或接口响应: {result}")
        return RoxyOpenResult(
            pid,
            result,
            debugger_address=debugger_address,
            webdriver_url=webdriver_url,
            ws_endpoint=ws_endpoint,
            created_by_run=created_by_run,
            static_cache_dir=str(static_cache_dir) if static_cache_dir else None,
        )

    def close_profile(self, profile_id: str) -> None:
        if not profile_id:
            return
        path = str(_cfg.ROXY_CLOSE_PATH).format(profile_id=profile_id)
        try:
            body = {
                "workspaceId": _workspace_id_value(),
                "dirId": int(profile_id) if str(profile_id).isdigit() else profile_id,
            }
            self.request(
                _cfg.ROXY_CLOSE_METHOD,
                path,
                params=body if str(_cfg.ROXY_CLOSE_METHOD).upper() == "GET" else None,
                json_body=body if str(_cfg.ROXY_CLOSE_METHOD).upper() != "GET" else None,
            )
            logger.info("[Roxy] 已关闭环境：%s", profile_id)
        except Exception as exc:
            logger.warning("[Roxy] 关闭环境失败：%s", exc)

    def delete_profile(self, profile_id: str) -> None:
        if not profile_id:
            return
        path = str(getattr(_cfg, "ROXY_DELETE_PATH", "/browser/delete")).format(profile_id=profile_id)
        method = str(getattr(_cfg, "ROXY_DELETE_METHOD", "POST") or "POST")
        try:
            body = {
                "workspaceId": _workspace_id_value(),
                "dirIds": [int(profile_id) if str(profile_id).isdigit() else profile_id],
            }
            self.request(
                method,
                path,
                params=body if method.upper() == "GET" else None,
                json_body=body if method.upper() != "GET" else None,
            )
            logger.info("[Roxy] 已删除环境：%s", profile_id)
        except Exception as exc:
            logger.warning("[Roxy] 删除环境失败：%s", exc)

    def cleanup_profile(self, opened: RoxyOpenResult | None) -> None:
        """任务结束清理：关闭窗口；一号一环境时删除本轮创建的 Profile。"""
        if not opened or not opened.profile_id:
            return
        keep_open = bool(getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False))
        if not keep_open:
            self.close_profile(opened.profile_id)

        should_delete = (
            bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
            and bool(getattr(_cfg, "ROXY_DELETE_PROFILE_AFTER_RUN", True))
            and bool(opened.created_by_run)
        )
        if should_delete:
            # 删除前尽量确保已关闭；若 keep_open=True 则不删除，便于调试保留现场。
            if keep_open:
                logger.info("[Roxy] ROXY_KEEP_BROWSER_OPEN=True，跳过删除环境：%s", opened.profile_id)
                return
            self.delete_profile(opened.profile_id)
        _cleanup_static_cache_dir(opened.static_cache_dir)

    @staticmethod
    def _extract_debugger_address(payload: dict) -> str | None:
        value = _first(payload, [
            ("debuggerAddress",), ("debugger_address",), ("debugAddress",),
            ("debuggingPortUrl",), ("debugging_port_url",),
            ("remoteDebuggingAddress",), ("remote_debugging_address",),
            ("http",), ("debugHttp",), ("debug_http",),
            ("data", "debuggerAddress"), ("data", "debugger_address"), ("data", "debugAddress"),
            ("data", "debuggingPortUrl"), ("data", "debugging_port_url"),
            ("data", "remoteDebuggingAddress"), ("data", "remote_debugging_address"),
            ("data", "http"), ("data", "debugHttp"), ("data", "debug_http"),
        ])
        if value:
            value = value.strip()
            # 兼容 http://127.0.0.1:xxxx / 127.0.0.1:xxxx / :xxxx / 9222
            value = value.replace("http://", "").replace("https://", "").strip("/")
            if value.startswith(":") and value[1:].isdigit():
                return f"127.0.0.1{value}"
            if value.isdigit():
                return f"127.0.0.1:{value}"
            if ":" in value and not value.startswith(":"):
                return value
        port = _first(payload, [
            ("debuggingPort",), ("debugging_port",), ("debug_port",), ("port",),
            ("data", "debuggingPort"), ("data", "debugging_port"), ("data", "debug_port"), ("data", "port"),
        ])
        if port:
            port = str(port).strip()
            if port.startswith(":"):
                port = port[1:]
            if port.isdigit():
                return f"127.0.0.1:{port}"
        return None
