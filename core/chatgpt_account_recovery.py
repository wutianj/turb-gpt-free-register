#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
from datetime import datetime
import inspect
import json
import random
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

try:
    from curl_cffi import requests
except ImportError:  # pragma: no cover - production installs curl_cffi
    import requests  # type: ignore[no-redef]


CHATGPT_BASE_URL = "https://chatgpt.com"
AUTH_BASE_URL = "https://auth.openai.com"
AUTH_AUTHORIZE_CONTINUE_URL = f"{AUTH_BASE_URL}/api/accounts/authorize/continue"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)


class AccountRecoveryError(RuntimeError):
    pass


class PasswordAlreadyExistsError(AccountRecoveryError):
    pass


_AUTH_FLOW_HEADER_NAMES = (
    "x-access-flow-invocation-id",
    "x-openai-document-navigation-id",
)


@dataclass(frozen=True)
class AccountRecoveryResult:
    ok: bool
    password: str
    access_token: str = ""
    cookie: str = ""
    action: str = "add"
    status: str = ""


@dataclass(frozen=True)
class PasswordFlowStart:
    ok: bool
    action: str
    authorize_url: str
    landed_url: str
    cookies: list[dict[str, Any]]
    status: str = ""


def _landed_status(url: str) -> str:
    parsed = urlparse(str(url or ""))
    path = (parsed.path or "").lower()
    if "email-verification" in path:
        return "email_otp_requested"
    if "reset-password" in path or "new-password" in path:
        return "password_form_ready"
    if "login" in path or "log-in" in path or "identifier" in path:
        return "login_page_landed"
    if parsed.netloc:
        return f"landed_{parsed.netloc}{path or '/'}"[:80]
    return "landing_unknown"


def dump_cookies(session: requests.Session) -> list[dict[str, Any]]:
    return [
        {
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": cookie.secure,
        }
        for cookie in _cookie_records(session)
        if cookie.name and cookie.value
    ]


def _new_browser_session() -> requests.Session:
    try:
        session = requests.Session(impersonate="chrome136")
    except TypeError:
        session = requests.Session()
    try:
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    except Exception:
        pass
    return session


def _cookie_records(session: requests.Session):
    cookies = session.cookies
    return getattr(cookies, "jar", cookies)


def session_from_cookies(cookies: list[dict[str, Any]] | None = None) -> requests.Session:
    session = _new_browser_session()
    for cookie in cookies or []:
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        if not name or not value:
            continue
        options: dict[str, Any] = {"path": str(cookie.get("path") or "/")}
        domain = str(cookie.get("domain") or "").strip()
        if domain:
            options["domain"] = domain
        try:
            session.cookies.set(name, value, **options)
        except TypeError:
            session.cookies.set(name, value)
        if name == "oai-did":
            setattr(session, "_reg2_device_id", value)
    return session


def _device_id(session: requests.Session) -> str:
    for cookie in _cookie_records(session):
        if str(getattr(cookie, "name", "") or "") == "oai-did" and getattr(cookie, "value", ""):
            value = str(cookie.value)
            setattr(session, "_reg2_device_id", value)
            return value
    value = str(getattr(session, "_reg2_device_id", "") or "").strip() or str(uuid.uuid4())
    setattr(session, "_reg2_device_id", value)
    return value


def _browser_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "user-agent": DEFAULT_USER_AGENT,
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "sec-ch-ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        "sec-ch-ua-full-version-list": '"Chromium";v="136.0.0.0", "Google Chrome";v="136.0.0.0", "Not.A/Brand";v="99.0.0.0"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-platform-version": '"15.0.0"',
        "sec-ch-viewport-width": '"1365"',
    }
    if extra:
        headers.update(extra)
    return headers


def _headers(
    origin: str = CHATGPT_BASE_URL,
    referer: str = f"{CHATGPT_BASE_URL}/",
    *,
    session: requests.Session | None = None,
) -> dict[str, str]:
    headers = _browser_headers({
        "accept": "application/json,text/plain,*/*",
        "content-type": "application/json",
        "origin": origin,
        "referer": referer,
    })
    if session is not None:
        headers["oai-device-id"] = _device_id(session)
    return headers


def _form_headers(session: requests.Session | None = None) -> dict[str, str]:
    headers = _headers(session=session)
    headers["content-type"] = "application/x-www-form-urlencoded"
    return headers


def _response_json(resp: requests.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except Exception as exc:
        raise AccountRecoveryError(f"response_not_json_http_{resp.status_code}") from exc
    if not isinstance(data, dict):
        raise AccountRecoveryError("response_not_object")
    return data


def _error_body_hint(resp: requests.Response, limit: int = 220) -> str:
    text = str(getattr(resp, "text", "") or "")
    text = text.replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if not text:
        return ""
    return text[:limit]


def _performance_now_ms() -> int:
    return time.perf_counter_ns() // 1_000_000


def _base64_json(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _sentinel_hash_hex(value: str) -> str:
    hash_value = 2166136261
    for char in value:
        hash_value ^= ord(char)
        hash_value = (hash_value * 16777619) & 0xFFFFFFFF
    hash_value ^= hash_value >> 16
    hash_value = (hash_value * 2246822507) & 0xFFFFFFFF
    hash_value ^= hash_value >> 13
    hash_value = (hash_value * 3266489909) & 0xFFFFFFFF
    hash_value ^= hash_value >> 16
    return f"{hash_value & 0xFFFFFFFF:08x}"


def _sentinel_fingerprint_data(sid: str) -> list[Any]:
    return [
        1366 + 768,
        datetime.now().astimezone().strftime("%a %b %d %Y %H:%M:%S GMT%z (%Z)"),
        4294967296,
        random.random(),
        DEFAULT_USER_AGENT,
        "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        "20260219f9f6",
        "zh-CN",
        "zh-CN,zh",
        random.random(),
        random.choice([
            f"userAgent−{DEFAULT_USER_AGENT}",
            "language−zh-CN",
            "hardwareConcurrency−8",
        ]),
        "location",
        random.choice(["window", "self", "document", "navigator", "location", "screen", "history"]),
        _performance_now_ms(),
        sid,
        "sv",
        8,
        int(time.time() * 1000),
        0,
        1,
        1,
        0,
        0,
        0,
        1,
    ]


def _generate_sentinel_answer(seed: str, difficulty: str) -> str:
    started = _performance_now_ms()
    data = _sentinel_fingerprint_data(str(uuid.uuid4()))
    for attempt in range(500000):
        data[3] = attempt
        data[9] = round(_performance_now_ms() - started)
        encoded = _base64_json(data)
        if _sentinel_hash_hex(seed + encoded)[:len(difficulty)] <= difficulty:
            return f"{encoded}~S"
    return "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + _base64_json("max attempts exceeded")


def _fetch_sentinel(session: requests.Session, device_id: str, flow: str) -> str:
    requirement_seed = str(random.random())
    req_token = f"gAAAAAC{_generate_sentinel_answer(requirement_seed, '0')}"
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        headers={"content-type": "application/json", "user-agent": DEFAULT_USER_AGENT},
        json={"p": req_token, "id": device_id, "flow": flow},
        timeout=30,
    )
    if resp.status_code >= 400:
        raise AccountRecoveryError(f"sentinel_http_{resp.status_code}")
    requirements = _response_json(resp)
    pow_data = requirements.get("proofofwork") if isinstance(requirements.get("proofofwork"), dict) else {}
    proof = None
    if pow_data.get("required") and pow_data.get("seed") and pow_data.get("difficulty"):
        proof = f"gAAAAAB{_generate_sentinel_answer(str(pow_data['seed']), str(pow_data['difficulty']))}"
    return json.dumps(
        {
            "p": proof,
            "t": None,
            "c": requirements.get("token"),
            "id": device_id,
            "flow": flow,
        },
        separators=(",", ":"),
    )


def _cookie_header(session: requests.Session) -> str:
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in _cookie_records(session) if cookie.value)


def _csrf_from_cookie(session: requests.Session) -> str:
    for cookie in _cookie_records(session):
        if cookie.name == "__Host-next-auth.csrf-token" and cookie.value:
            return str(cookie.value).split("|", 1)[0]
    return ""


def _get_csrf(session: requests.Session) -> str:
    resp = session.get(
        f"{CHATGPT_BASE_URL}/api/auth/csrf",
        headers=_browser_headers({
            "accept": "application/json",
            "oai-device-id": _device_id(session),
        }),
        timeout=30,
    )
    if resp.status_code >= 400:
        raise AccountRecoveryError(f"csrf_http_{resp.status_code}")
    token = str(_response_json(resp).get("csrfToken") or "")
    if not token:
        token = _csrf_from_cookie(session)
    if not token:
        raise AccountRecoveryError("csrf_missing")
    return token


def _signin_authorize_url(session: requests.Session, *, email: str, action: str, csrf_token: str) -> str:
    if action not in {"add", "reset"}:
        raise AccountRecoveryError("invalid_password_action")
    mode_key = "post_login_add_password" if action == "add" else "post_login_password_reset"
    query = urlencode({
        "connection": "password",
        "login_hint": email,
        "reauth": "password",
        mode_key: "true",
        "max_age": "0",
        "ext-oai-did": _device_id(session),
    })
    body = urlencode({
        "callbackUrl": "https://chatgpt.com/",
        "csrfToken": csrf_token,
        "json": "true",
    })
    resp = session.post(
        f"{CHATGPT_BASE_URL}/api/auth/signin/openai?{query}",
        headers=_form_headers(session),
        data=body,
        timeout=30,
    )
    data = _response_json(resp)
    authorize_url = str(data.get("url") or "")
    if not authorize_url and str(data.get("csrf") or "").lower() == "true":
        retry_csrf = _csrf_from_cookie(session) or csrf_token
        body = urlencode({"callbackUrl": "https://chatgpt.com/", "csrfToken": retry_csrf, "json": "true"})
        resp = session.post(
            f"{CHATGPT_BASE_URL}/api/auth/signin/openai?{query}",
            headers=_form_headers(session),
            data=body,
            timeout=30,
        )
        data = _response_json(resp)
        authorize_url = str(data.get("url") or "")
    if not authorize_url:
        raise AccountRecoveryError(f"authorize_url_missing_http_{resp.status_code}")
    return authorize_url


def _signin_login_authorize_url(session: requests.Session, *, email: str, csrf_token: str) -> str:
    query = urlencode({
        "prompt": "login",
        "auth_session_logging_id": str(uuid.uuid4()),
        "screen_hint": "login_or_signup",
        "login_hint": email,
        "ext-oai-did": _device_id(session),
    })
    body = urlencode({
        "callbackUrl": "https://chatgpt.com/",
        "csrfToken": csrf_token,
        "json": "true",
    })
    resp = session.post(
        f"{CHATGPT_BASE_URL}/api/auth/signin/openai?{query}",
        headers=_form_headers(session),
        data=body,
        timeout=30,
    )
    data = _response_json(resp)
    authorize_url = str(data.get("url") or "")
    if not authorize_url and str(data.get("csrf") or "").lower() == "true":
        retry_csrf = _csrf_from_cookie(session) or csrf_token
        body = urlencode({"callbackUrl": "https://chatgpt.com/", "csrfToken": retry_csrf, "json": "true"})
        resp = session.post(
            f"{CHATGPT_BASE_URL}/api/auth/signin/openai?{query}",
            headers=_form_headers(session),
            data=body,
            timeout=30,
        )
        data = _response_json(resp)
        authorize_url = str(data.get("url") or "")
    if not authorize_url:
        raise AccountRecoveryError(f"login_authorize_url_missing_http_{resp.status_code}")
    return authorize_url


def _open_authorize(session: requests.Session, authorize_url: str) -> str:
    target = str(authorize_url or "").strip()
    if not target:
        raise AccountRecoveryError("authorize_url_missing")
    if not target.startswith("http"):
        target = urljoin(AUTH_BASE_URL, target)
    referer = f"{CHATGPT_BASE_URL}/"
    visited: set[str] = set()
    response = None
    for redirect_count in range(13):
        if target in visited:
            raise AccountRecoveryError("authorize_redirect_loop")
        visited.add(target)
        target_origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        referer_origin = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"
        response = session.get(
            target,
            headers=_browser_headers({
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "oai-device-id": _device_id(session),
                "referer": referer,
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-origin" if target_origin == referer_origin else "cross-site",
                "sec-fetch-user": "?1",
                "upgrade-insecure-requests": "1",
            }),
            allow_redirects=False,
            timeout=60,
        )
        if response.status_code not in {301, 302, 303, 307, 308}:
            break
        location = str(
            getattr(response, "headers", {}).get("location")
            or getattr(response, "headers", {}).get("Location")
            or ""
        ).strip()
        if not location:
            raise AccountRecoveryError("authorize_redirect_location_missing")
        if redirect_count >= 12:
            raise AccountRecoveryError("authorize_redirect_limit")
        previous = str(getattr(response, "url", "") or target)
        referer = previous
        target = urljoin(previous, location)
    if response is None:
        raise AccountRecoveryError("authorize_response_missing")
    if response.status_code >= 400:
        raise AccountRecoveryError(f"authorize_http_{response.status_code}")
    return str(getattr(response, "url", "") or target)


def _continue_url(data: dict[str, Any]) -> str:
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    page_payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    for value in (
        data.get("continue_url"),
        data.get("redirect_url"),
        data.get("url"),
        data.get("location"),
        page_payload.get("url"),
    ):
        target = str(value or "").strip()
        if target:
            return target if target.startswith("http") else urljoin(AUTH_BASE_URL, target)
    return ""


def _follow_continue(session: requests.Session, data: dict[str, Any]) -> str:
    target = _continue_url(data)
    if not target:
        return ""
    return _open_authorize(session, target)


def _authorize_continue_email(session: requests.Session, email: str, current_url: str) -> str:
    current = str(current_url or "").strip()
    lowered = current.lower()
    if not current or "log-in" not in lowered or "password" in lowered or "email-verification" in lowered:
        return current
    device_id = _device_id(session)
    resp = session.post(
        AUTH_AUTHORIZE_CONTINUE_URL,
        headers=_headers(
            origin=AUTH_BASE_URL,
            referer=current,
            session=session,
        ) | {
            "openai-sentinel-token": _fetch_sentinel(session, device_id, "authorize_continue"),
            "x-access-flow-invocation-id": str(uuid.uuid4()),
        },
        json={"username": {"kind": "email", "value": email}},
        timeout=45,
    )
    if resp.status_code >= 400:
        hint = _error_body_hint(resp)
        raise AccountRecoveryError(
            f"authorize_continue_http_{resp.status_code}" + (f": {hint}" if hint else "")
        )
    target = _continue_url(_response_json(resp))
    if not target:
        raise AccountRecoveryError("authorize_continue_url_missing")
    return _open_authorize(session, target)


def _send_password_reset_otp(session: requests.Session, landed_url: str = "") -> None:
    referer = landed_url if str(landed_url or "").startswith(f"{AUTH_BASE_URL}/") else f"{AUTH_BASE_URL}/log-in"
    landed = _open_authorize(session, f"{AUTH_BASE_URL}/reset-password")
    if "reset-password" not in urlparse(landed).path:
        raise AccountRecoveryError("reset_password_page_missing")
    resp = session.post(
        f"{AUTH_BASE_URL}/api/accounts/password/send-otp",
        headers=_headers(
            origin=AUTH_BASE_URL,
            referer=f"{AUTH_BASE_URL}/reset-password",
            session=session,
        ) | {"x-access-flow-invocation-id": str(uuid.uuid4())},
        json={},
        timeout=30,
    )
    if resp.status_code >= 400:
        raise AccountRecoveryError(f"password_send_otp_http_{resp.status_code}")


def _fresh_login_session(source: requests.Session | None = None) -> requests.Session:
    login = _new_browser_session()
    if source is not None:
        proxies = getattr(source, "proxies", None)
        if isinstance(proxies, dict):
            login.proxies.update(proxies)
        setattr(login, "_reg2_device_id", _device_id(source))
    return login


def _invoke_otp_provider(otp_provider, session: requests.Session) -> str:
    try:
        parameters = inspect.signature(otp_provider).parameters.values()
        accepts_session = any(
            parameter.kind
            in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD, parameter.VAR_POSITIONAL)
            for parameter in parameters
        )
    except (TypeError, ValueError):
        accepts_session = False
    value = otp_provider(session) if accepts_session else otp_provider()
    return str(value or "").strip()


def _login_with_password_for_session(
    email: str,
    password: str,
    *,
    source_session: requests.Session | None = None,
    otp_provider=None,
) -> tuple[str, requests.Session]:
    login = _fresh_login_session(source_session)
    csrf = _get_csrf(login)
    authorize_url = _signin_login_authorize_url(login, email=email, csrf_token=csrf)
    current = _open_authorize(login, authorize_url)
    current = _authorize_continue_email(login, email, current)
    password_verified = False
    email_otp_verified = False
    for _ in range(8):
        lowered = str(current or "").lower()
        if ("email-verification" in lowered or "email-otp" in lowered) and not email_otp_verified:
            if not callable(otp_provider):
                raise AccountRecoveryError("password_login_email_otp_required")
            code = _invoke_otp_provider(otp_provider, login)
            if len(code) != 6 or not code.isdigit():
                raise AccountRecoveryError("password_login_email_otp_missing")
            payload = validate_email_otp(login, code)
            current = _follow_continue(login, payload)
            email_otp_verified = True
            continue
        if not password_verified and ("password" in lowered or email_otp_verified or not current):
            referer = current if current.startswith(AUTH_BASE_URL) else f"{AUTH_BASE_URL}/log-in/password"
            resp = _password_api_post(
                login,
                "/api/accounts/password/verify",
                {"password": password},
                flow="password_verify",
                referer=referer,
            )
            if resp.status_code >= 400:
                hint = _error_body_hint(resp)
                raise AccountRecoveryError(
                    f"password_verify_http_{resp.status_code}" + (f": {hint}" if hint else "")
                )
            current = _follow_continue(login, _response_json(resp))
            password_verified = True
            continue
        break
    if not password_verified:
        raise AccountRecoveryError(f"password_verify_step_missing:{urlparse(current).path or 'unknown'}")
    if current and current.startswith("http"):
        _open_authorize(login, current)
    access_token = _fetch_web_session(login)
    if not access_token:
        raise AccountRecoveryError("access_token_missing_after_login")
    return access_token, login


def login_with_password_for_session(*, email: str, password: str) -> AccountRecoveryResult:
    if not email or "@" not in email:
        raise AccountRecoveryError("invalid_email")
    if not password:
        raise AccountRecoveryError("missing_password")
    access_token, session = _login_with_password_for_session(email, password)
    if not access_token:
        raise AccountRecoveryError("access_token_missing_after_login")
    return AccountRecoveryResult(
        ok=True,
        password=password,
        access_token=access_token,
        cookie=_cookie_header(session),
        action="login",
        status="password_login_ok",
    )


def start_password_email_otp_flow(
    *,
    email: str,
    action: str = "add",
    session: requests.Session | None = None,
) -> PasswordFlowStart:
    if not email or "@" not in email:
        raise AccountRecoveryError("invalid_email")
    client = session or _new_browser_session()
    csrf = _get_csrf(client)
    authorize_url = _signin_authorize_url(client, email=email, action=action, csrf_token=csrf)
    landed_url = _open_authorize(client, authorize_url)
    landed_url = _authorize_continue_email(client, email, landed_url)
    status = _landed_status(landed_url)
    if action == "reset" and status == "login_page_landed":
        _send_password_reset_otp(client, landed_url)
        status = "email_otp_requested"
    return PasswordFlowStart(
        ok=True,
        action=action,
        authorize_url=authorize_url,
        landed_url=landed_url,
        cookies=dump_cookies(client),
        status=status,
    )


def validate_email_otp(session: requests.Session, code: str) -> dict[str, Any]:
    resp = _password_api_post(
        session,
        "/api/accounts/email-otp/validate",
        {"code": str(code or "").strip()},
        flow="email_otp_validate",
        referer=f"{AUTH_BASE_URL}/email-verification",
    )
    if resp.status_code >= 400:
        hint = _error_body_hint(resp)
        raise AccountRecoveryError(f"email_otp_validate_http_{resp.status_code}" + (f": {hint}" if hint else ""))
    return _response_json(resp)


def _password_submit_headers(
    session: requests.Session,
    *,
    action: str,
    flow_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    referer = f"{AUTH_BASE_URL}/add-password" if action == "add" else f"{AUTH_BASE_URL}/reset-password"
    headers = _headers(
        origin=AUTH_BASE_URL,
        referer=referer,
        session=session,
    )
    headers["x-access-flow-invocation-id"] = str(uuid.uuid4())
    headers["openai-sentinel-token"] = _fetch_sentinel(
        session,
        _device_id(session),
        "password_reset",
    )
    normalized = {
        str(key).lower(): str(value)
        for key, value in (flow_headers or {}).items()
        if str(value or "").strip()
    }
    for name in _AUTH_FLOW_HEADER_NAMES:
        if normalized.get(name):
            headers[name] = normalized[name]
    return headers


def _password_api_post(
    session: requests.Session,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    flow: str = "",
    referer: str = f"{AUTH_BASE_URL}/",
) -> requests.Response:
    device_id = _device_id(session)
    headers = _headers(
        origin=AUTH_BASE_URL,
        referer=referer,
        session=session,
    )
    headers["x-access-flow-invocation-id"] = str(uuid.uuid4())
    if flow:
        headers["openai-sentinel-token"] = _fetch_sentinel(session, device_id, flow)
    kwargs: dict[str, Any] = {
        "headers": headers,
        "timeout": 45,
    }
    if body is not None:
        kwargs["json"] = body
    return session.post(f"{AUTH_BASE_URL}{path}", **kwargs)


def resend_email_otp(session: requests.Session) -> None:
    response = _password_api_post(
        session,
        "/api/accounts/email-otp/resend",
        {},
        referer=f"{AUTH_BASE_URL}/email-verification",
    )
    if response.status_code >= 400:
        hint = _error_body_hint(response)
        raise AccountRecoveryError(
            f"email_otp_resend_http_{response.status_code}" + (f": {hint}" if hint else "")
        )


def submit_password(
    session: requests.Session,
    *,
    password: str,
    action: str,
    flow_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    endpoint = "add" if action == "add" else "reset"
    def post_password(target: str) -> requests.Response:
        return session.post(
            f"{AUTH_BASE_URL}/api/accounts/password/{target}",
            headers=_password_submit_headers(
                session,
                action=action,
                flow_headers=flow_headers,
            ),
            json={"password": password},
            timeout=30,
        )

    resp = post_password(endpoint)
    if action == "add" and resp.status_code >= 400:
        first_hint = _error_body_hint(resp)
        if "already have a password" in first_hint.lower() or "reset it instead" in first_hint.lower():
            raise PasswordAlreadyExistsError("password_add_existing_password")
    if resp.status_code not in {200, 204}:
        text = (resp.text or "")[:180]
        if endpoint == "reset" and "password must not be reused" in text.lower():
            return {}
        hint = _error_body_hint(resp)
        raise AccountRecoveryError(f"password_{endpoint}_http_{resp.status_code}" + (f": {hint}" if hint else ""))
    if resp.status_code == 204 or not str(resp.text or "").strip():
        return {}
    return _response_json(resp)


def complete_password_after_validated_otp(
    session: requests.Session,
    *,
    otp_result: dict[str, Any],
    password: str,
    action: str,
    flow_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Continue a browser-validated OTP flow without losing its auth step."""
    if not isinstance(otp_result, dict):
        raise AccountRecoveryError("email_otp_result_invalid")
    _follow_continue(session, otp_result)
    password_result = submit_password(
        session,
        password=password,
        action=action,
        flow_headers=flow_headers,
    )
    _follow_continue(session, password_result)
    return password_result


def submit_password_old_unused(session: requests.Session, *, password: str, action: str) -> None:
    endpoint = "add" if action == "add" else "reset"
    resp = session.post(
        f"https://auth.openai.com/api/accounts/password/{endpoint}",
        headers=_headers(
            origin="https://auth.openai.com",
            referer="https://auth.openai.com/reset-password/new-password",
        ),
        data=json.dumps({"password": password}),
        timeout=30,
    )
    if resp.status_code not in {200, 204}:
        text = (resp.text or "")[:180]
        if action == "reset" and "password must not be reused" in text.lower():
            return
        hint = _error_body_hint(resp)
        raise AccountRecoveryError(f"password_{endpoint}_http_{resp.status_code}" + (f": {hint}" if hint else ""))


def _fetch_web_session(session: requests.Session) -> str:
    for attempt in range(10):
        suffix = "?refresh=true" if attempt else ""
        resp = session.get(
            f"{CHATGPT_BASE_URL}/api/auth/session{suffix}",
            headers=_browser_headers({
                "accept": "application/json",
                "cache-control": "no-cache",
                "origin": CHATGPT_BASE_URL,
                "pragma": "no-cache",
                "referer": f"{CHATGPT_BASE_URL}/",
                "oai-device-id": _device_id(session),
            }),
            timeout=30,
        )
        if resp.status_code < 400:
            data = _response_json(resp)
            token = str(data.get("accessToken") or data.get("access_token") or "")
            if token:
                return token
        try:
            session.get(
                f"{CHATGPT_BASE_URL}/",
                headers=_browser_headers({
                    "accept": "text/html",
                    "oai-device-id": _device_id(session),
                }),
                timeout=30,
            )
        except Exception:
            pass
        if attempt < 9:
            time.sleep(1)
    return ""


def add_or_reset_password_with_email_otp(
    *,
    email: str,
    otp_code: str,
    password: str,
    action: str = "add",
    session: requests.Session | None = None,
    login_otp_provider=None,
) -> AccountRecoveryResult:
    if not email or "@" not in email:
        raise AccountRecoveryError("invalid_email")
    if not otp_code:
        raise AccountRecoveryError("missing_otp_code")
    if not password:
        raise AccountRecoveryError("missing_password")
    client = session or _new_browser_session()
    otp_result = validate_email_otp(client, otp_code)
    _follow_continue(client, otp_result)
    password_result = submit_password(client, password=password, action=action)
    _follow_continue(client, password_result)
    access_token = ""
    cookie = ""
    login_error: Exception | None = None
    if callable(login_otp_provider):
        try:
            access_token, login_session = _login_with_password_for_session(
                email,
                password,
                source_session=client,
                otp_provider=login_otp_provider,
            )
            cookie = _cookie_header(login_session)
        except Exception as exc:
            login_error = exc
    if not access_token:
        access_token = _fetch_web_session(client)
        cookie = _cookie_header(client)
    if not access_token:
        try:
            access_token, login_session = _login_with_password_for_session(
                email,
                password,
                source_session=client,
            )
            cookie = _cookie_header(login_session)
        except Exception as exc:
            login_error = login_error or exc
            return AccountRecoveryResult(
                ok=True,
                password=password,
                access_token="",
                cookie=cookie,
                action=action,
                status=f"password_{action}_ok_session_pending:{type(login_error).__name__}",
            )
    return AccountRecoveryResult(
        ok=True,
        password=password,
        access_token=access_token,
        cookie=cookie,
        action=action,
        status=f"password_{action}_ok",
    )
