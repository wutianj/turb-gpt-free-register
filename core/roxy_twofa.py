# -*- coding: utf-8 -*-
"""Use an official Roxy browser context for password setup and TOTP binding."""
from __future__ import annotations

import logging
import time
import uuid
from typing import Callable

import pyotp

from config import roxybrowser as _roxy_cfg
from config.openai_protocol import OAI_CLIENT_BUILD_NUMBER, OAI_CLIENT_VERSION
from core.browser_data_saver import BrowserDataSaver
from core.browser_traffic import SeleniumTrafficTracker
from core.roxy_registration import (
    _build_driver,
    _clear_otp_inputs,
    _click_continue,
    _click_passwordless_signup_if_present,
    _click_resend_email_otp,
    _center_browser_window,
    _fetch_chatgpt_session,
    _fill_password_page_if_present,
    _has_access_token,
    _human_click,
    _human_type_text,
    _is_email_verification_page,
    _is_login_password_page,
    _is_signup_password_page,
    _maybe_accept,
    _page_warmup,
    _safe_get,
    _submit_email_step,
    _type_email_address,
    _type_otp,
    _wait_after_email_otp_submit,
)
from core.roxybrowser_client import RoxyBrowserClient


logger = logging.getLogger(__name__)


class RoxyTwofaError(RuntimeError):
    pass


def _trigger_auth_url(driver, *, email: str, mode: str) -> str:
    """Create the auth URL inside the real browser so CSRF/CF cookies match."""
    if mode not in {"login", "add_password"}:
        raise ValueError(f"unsupported Roxy auth mode: {mode}")
    try:
        driver.set_script_timeout(35)
    except Exception:
        pass
    result = driver.execute_async_script(
        r"""
        const email = String(arguments[0] || '').trim();
        const mode = String(arguments[1] || 'login');
        const did = String(arguments[2] || '');
        const authLogId = String(arguments[3] || '');
        const done = arguments[arguments.length - 1];
        (async () => {
          try {
            const csrfResp = await fetch('/api/auth/csrf', {
              method: 'GET', credentials: 'include',
              headers: {accept: 'application/json', 'cache-control': 'no-cache', pragma: 'no-cache'}
            });
            const csrfText = await csrfResp.text();
            let csrfData = {};
            try { csrfData = JSON.parse(csrfText); } catch (_) {}
            const csrfToken = String(csrfData.csrfToken || '');
            if (!csrfResp.ok || !csrfToken) {
              done({ok: false, stage: 'csrf', status: csrfResp.status});
              return;
            }
            const query = mode === 'add_password'
              ? new URLSearchParams({
                  connection: 'password', login_hint: email, reauth: 'password',
                  post_login_add_password: 'true', max_age: '0', 'ext-oai-did': did
                })
              : new URLSearchParams({
                  prompt: 'login', auth_session_logging_id: authLogId,
                  screen_hint: 'login_or_signup', login_hint: email, 'ext-oai-did': did
                });
            const body = new URLSearchParams({
              callbackUrl: 'https://chatgpt.com/', csrfToken, json: 'true'
            });
            const resp = await fetch('/api/auth/signin/openai?' + query.toString(), {
              method: 'POST', credentials: 'include',
              headers: {
                accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded',
                'cache-control': 'no-cache', pragma: 'no-cache'
              },
              body: body.toString()
            });
            const text = await resp.text();
            let data = {};
            try { data = JSON.parse(text); } catch (_) {}
            const url = String(data.url || '');
            if (!resp.ok || !url) {
              done({ok: false, stage: 'signin', status: resp.status});
              return;
            }
            done({ok: true, stage: 'ready', url});
          } catch (error) {
            done({ok: false, stage: 'exception', error: String(error && (error.message || error)).slice(0, 180)});
          }
        })();
        """,
        email,
        mode,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
    ) or {}
    if not isinstance(result, dict) or not result.get("ok"):
        stage = str((result or {}).get("stage") or "unknown")
        status = int((result or {}).get("status") or 0)
        raise RoxyTwofaError(f"roxy_auth_{stage}_http_{status}")
    url = str(result.get("url") or "").strip()
    if not url.startswith("https://auth.openai.com/"):
        raise RoxyTwofaError("roxy_auth_url_invalid")
    return url


def _wait_for_password_form(driver, timeout: int = 60) -> None:
    end = time.time() + max(1, int(timeout))
    while time.time() < end:
        if _is_signup_password_page(driver) and not _is_login_password_page(driver):
            return
        if _has_access_token(driver):
            raise RoxyTwofaError("password_form_skipped_after_auth")
        time.sleep(0.5)
    raise RoxyTwofaError("password_form_timeout")


def _submit_login_password(driver, password: str, timeout: int = 25) -> None:
    result = driver.execute_script(
        r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="current-password"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_password_input'};
        const form = input.closest('form');
        const scope = form || document;
        const buttons = [...scope.querySelectorAll('button,input[type="submit"]')]
          .filter(el => visible(el) && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true')
          .map((el, index) => {
            const rect = el.getBoundingClientRect();
            const inputRect = input.getBoundingClientRect();
            return {el, index, below: rect.top >= inputRect.bottom - 10, distance: Math.max(0, rect.top - inputRect.bottom)};
          })
          .filter(item => item.below)
          .sort((a, b) => a.distance - b.distance || a.index - b.index);
        if (!buttons.length) return {ok:false, reason:'missing_password_submit'};
        return {ok:true, input, button:buttons[0].el};
        """
    ) or {}
    if not result.get("ok"):
        raise RoxyTwofaError(f"login_password_controls_missing:{result.get('reason') or 'unknown'}")
    _human_type_text(driver, result.get("input"), password, clear=True)
    _human_click(driver, result.get("button"), label="twofa_login_password")
    end = time.time() + max(1, int(timeout))
    while time.time() < end:
        if not _is_login_password_page(driver):
            return
        time.sleep(0.5)
    raise RoxyTwofaError("login_password_not_accepted")


def _submit_email_otp(
    driver,
    *,
    email: str,
    otp_provider: Callable,
    after_ts: float,
    max_attempts: int = 3,
) -> None:
    current_after_ts = float(after_ts or 0.0)
    used_codes: set[str] = set()
    for attempt in range(1, max(1, int(max_attempts)) + 1):
        code = str(otp_provider(email, after_ts=current_after_ts) or "").strip()
        if len(code) != 6 or not code.isdigit() or code in used_codes:
            raise RoxyTwofaError("email_otp_missing_or_reused")
        used_codes.add(code)
        _clear_otp_inputs(driver)
        _type_otp(driver, code)
        _click_continue(driver)
        outcome = _wait_after_email_otp_submit(driver, timeout=45)
        if outcome == "accepted" and not _is_email_verification_page(driver):
            return
        if attempt >= max_attempts:
            raise RoxyTwofaError("email_otp_rejected")
        current_after_ts = time.time()
        _click_resend_email_otp(driver, timeout=20)
    raise RoxyTwofaError("email_otp_retry_exhausted")


def _complete_browser_auth(
    driver,
    *,
    email: str,
    password: str,
    password_already_set: bool,
    otp_provider: Callable,
    auth_url: str,
    timeout: int = 150,
) -> None:
    otp_after_ts = time.time()
    _safe_get(
        driver,
        auth_url,
        timeout=min(60, int(_roxy_cfg.ROXY_SELENIUM_TIMEOUT)),
        attempts=2,
        accept_hosts=("auth.openai.com", "chatgpt.com"),
    )
    _maybe_accept(driver)
    end = time.time() + max(1, int(timeout))
    email_attempts = 0
    while time.time() < end:
        if _has_access_token(driver):
            return
        if not password_already_set and _is_signup_password_page(driver) and not _is_login_password_page(driver):
            return
        if _is_email_verification_page(driver):
            _submit_email_otp(
                driver,
                email=email,
                otp_provider=otp_provider,
                after_ts=otp_after_ts,
            )
            continue
        if _is_login_password_page(driver):
            if password_already_set:
                _submit_login_password(driver, password)
                continue
            passwordless = _click_passwordless_signup_if_present(driver)
            if not passwordless.get("ok"):
                raise RoxyTwofaError("passwordless_login_entry_missing")
            otp_after_ts = time.time()
            time.sleep(1)
            continue
        if email_attempts < 2:
            email_attempts += 1
            try:
                _type_email_address(driver, email, timeout=10)
                _submit_email_step(driver, email)
                otp_after_ts = time.time()
                time.sleep(1)
                continue
            except Exception:
                pass
        time.sleep(0.5)
    try:
        current_url = str(driver.current_url or "")
    except Exception:
        current_url = ""
    raise RoxyTwofaError(f"roxy_auth_flow_timeout:{current_url[:160]}")


def _browser_api_post(driver, *, path: str, payload: dict, access_token: str) -> dict:
    try:
        language = str(driver.execute_script("return navigator.language || 'en-US';") or "en-US")
    except Exception:
        language = "en-US"
    try:
        cookies = list(driver.get_cookies() or [])
    except Exception:
        cookies = []
    device_id = next(
        (str(item.get("value") or "") for item in cookies if str(item.get("name") or "") == "oai-did"),
        "",
    ) or str(uuid.uuid4())
    try:
        driver.set_script_timeout(35)
    except Exception:
        pass
    result = driver.execute_async_script(
        r"""
        const path = String(arguments[0] || '');
        const payload = arguments[1] || {};
        const accessToken = String(arguments[2] || '');
        const build = String(arguments[3] || '');
        const version = String(arguments[4] || '');
        const deviceId = String(arguments[5] || '');
        const language = String(arguments[6] || 'en-US');
        const sessionId = String(arguments[7] || '');
        const done = arguments[arguments.length - 1];
        (async () => {
          if (path.endsWith('/mfa/user/activate_enrollment')) {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', path, true);
            xhr.timeout = 30000;
            const headers = {
              accept: 'application/json', 'content-type': 'application/json',
              authorization: 'Bearer ' + accessToken,
              'oai-client-build-number': build, 'oai-client-version': version,
              'oai-device-id': deviceId, 'oai-language': language,
              'oai-session-id': sessionId, 'x-oai-is-client-observation': 'false',
              'x-oai-is-pending-updates': 'false', 'x-openai-target-path': path,
              'x-openai-target-route': path
            };
            for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value);
            xhr.onload = () => {
              let data = {};
              try { data = xhr.responseText ? JSON.parse(xhr.responseText) : {}; } catch (_) {}
              done({ok: xhr.status >= 200 && xhr.status < 300, status: xhr.status, data});
            };
            xhr.onerror = () => done({ok: false, status: xhr.status || 0, error: 'XHRNetworkError'});
            xhr.ontimeout = () => done({ok: false, status: xhr.status || 0, error: 'XHRTimeout'});
            xhr.send(JSON.stringify(payload));
            return;
          }
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 30000);
          try {
            const resp = await fetch(path, {
              method: 'POST', credentials: 'include',
              signal: controller.signal,
              headers: {
                accept: 'application/json', 'content-type': 'application/json',
                authorization: 'Bearer ' + accessToken,
                'oai-client-build-number': build, 'oai-client-version': version,
                'oai-device-id': deviceId, 'oai-language': language,
                'oai-session-id': sessionId, 'x-oai-is-client-observation': 'false',
                'x-oai-is-pending-updates': 'false', 'x-openai-target-path': path,
                'x-openai-target-route': path
              },
              body: JSON.stringify(payload)
            });
            const text = await resp.text();
            let data = {};
            try { data = text ? JSON.parse(text) : {}; } catch (_) {}
            done({ok: resp.ok, status: resp.status, data});
          } catch (error) {
            const name = String(error && error.name || 'Error');
            done({ok: false, status: 0, error: name + ':' + String(error && (error.message || error)).slice(0, 180)});
          } finally {
            clearTimeout(timer);
          }
        })();
        """,
        path,
        payload,
        access_token,
        OAI_CLIENT_BUILD_NUMBER,
        OAI_CLIENT_VERSION,
        device_id,
        language,
        str(uuid.uuid4()),
    ) or {}
    if not isinstance(result, dict) or not result.get("ok"):
        error = str((result or {}).get("error") or "").strip()[:180]
        suffix = f":{error}" if error else ""
        raise RoxyTwofaError(f"roxy_browser_api_http_{int((result or {}).get('status') or 0)}:{path}{suffix}")
    data = result.get("data") or {}
    if not isinstance(data, dict):
        raise RoxyTwofaError(f"roxy_browser_api_invalid_json:{path}")
    return data


def _bind_totp(driver, access_token: str) -> str:
    enroll = _browser_api_post(
        driver,
        path="/backend-api/accounts/mfa/enroll",
        payload={"factor_type": "totp"},
        access_token=access_token,
    )
    secret = str(enroll.get("secret") or "").replace(" ", "").upper()
    enroll_session_id = str(enroll.get("session_id") or "")
    if not secret or not enroll_session_id:
        raise RoxyTwofaError("roxy_enroll_missing_fields")
    if int(time.time()) % 30 >= 26:
        time.sleep(5)
    code = pyotp.TOTP(secret).now()
    activated = _browser_api_post(
        driver,
        path="/backend-api/accounts/mfa/user/activate_enrollment",
        payload={"code": code, "factor_type": "totp", "session_id": enroll_session_id},
        access_token=access_token,
    )
    if activated.get("success") is not True:
        raise RoxyTwofaError("roxy_activate_success_false")
    return secret


def setup_password_and_totp_via_roxy(
    *,
    email: str,
    password: str,
    password_already_set: bool,
    otp_provider: Callable,
    on_password_set: Callable[[str], None] | None = None,
    on_access_token: Callable[[str], None] | None = None,
    on_network_traffic: Callable[[dict], None] | None = None,
) -> dict:
    """Complete password login/setup and TOTP activation in one Roxy profile."""
    client = RoxyBrowserClient()
    opened = client.open_profile()
    driver = None
    traffic_tracker = None
    data_saver = None
    network_traffic = None
    try:
        driver = _build_driver(opened)
        traffic_tracker = SeleniumTrafficTracker(driver, label="Roxy 2FA")
        data_saver = BrowserDataSaver(label="Roxy 2FA")
        traffic_tracker.attach_data_saver(data_saver)
        data_saver.install_selenium(driver)
        _center_browser_window(driver)
        driver.set_page_load_timeout(int(_roxy_cfg.ROXY_SELENIUM_TIMEOUT))
        _safe_get(
            driver,
            "https://chatgpt.com/",
            timeout=min(45, int(_roxy_cfg.ROXY_SELENIUM_TIMEOUT)),
            attempts=2,
            accept_hosts=("chatgpt.com",),
        )
        _page_warmup(driver, reason="twofa_security_flow")
        _maybe_accept(driver)

        mode = "login" if password_already_set else "add_password"
        auth_url = _trigger_auth_url(driver, email=email, mode=mode)
        _complete_browser_auth(
            driver,
            email=email,
            password=password,
            password_already_set=password_already_set,
            otp_provider=otp_provider,
            auth_url=auth_url,
        )

        if not password_already_set:
            _wait_for_password_form(driver, timeout=60)
            applied = _fill_password_page_if_present(
                driver,
                email,
                timeout=35,
                password_value=password,
                allow_otp_switch=False,
                require_transition=True,
            )
            if applied != password:
                raise RoxyTwofaError("password_form_not_applied")
            if on_password_set is not None:
                on_password_set(password)

        session_info = _fetch_chatgpt_session(driver, timeout=120, auto_jump_wait=8)
        access_token = str(session_info.get("accessToken") or "").strip()
        if not access_token:
            raise RoxyTwofaError("roxy_session_access_token_missing")
        if on_access_token is not None:
            on_access_token(access_token)

        secret = _bind_totp(driver, access_token)
        network_traffic = traffic_tracker.stop()
        return {
            "password": password,
            "access_token": access_token,
            "totp_secret": secret,
            "network_traffic": network_traffic,
        }
    finally:
        if traffic_tracker is not None and network_traffic is None:
            try:
                network_traffic = traffic_tracker.stop()
            except Exception:
                logger.debug("[Roxy 2FA] 停止流量统计失败", exc_info=True)
        if network_traffic is not None and on_network_traffic is not None:
            try:
                on_network_traffic(network_traffic)
            except Exception:
                logger.debug("[Roxy 2FA] 保存流量统计失败", exc_info=True)
        if data_saver is not None:
            try:
                data_saver.stop()
            except Exception:
                logger.debug("[Roxy 2FA] 停止省流量拦截器失败", exc_info=True)
        if driver is not None and not bool(_roxy_cfg.ROXY_KEEP_BROWSER_OPEN):
            try:
                driver.quit()
            except Exception:
                pass
        if not bool(_roxy_cfg.ROXY_KEEP_BROWSER_OPEN):
            client.cleanup_profile(opened)
