# -*- coding: utf-8 -*-
"""Probe whether a ChatGPT checkout exposes a genuine trial and MoMo.

The probe deliberately stops after Stripe's public checkout initialization.  It
does not create a PaymentMethod, confirm a payment, or persist checkout IDs.
"""
from __future__ import annotations

import re
import time
import uuid
from datetime import datetime
from typing import Any

from config import proxy as proxy_cfg
from core.chatgpt_plan import normalize_token, resolve_plan_check_route, token_claims
from core.session import BrowserSession


CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
STRIPE_INIT_URL = "https://api.stripe.com/v1/payment_pages/init"
DEFAULT_STRIPE_PK = ""

DECISION_TEXT = {
    "ready": "支持真正试用，且当前结账页支持 MoMo",
    "account_trial_ineligible": "账号没有真正试用资格",
    "trial_not_applied": "试用未被结账后端采用",
    "momo_not_enabled": "试用已生效，但当前结账页未启用 MoMo",
    "already_paid": "账号已订阅，无法用新订阅流程检测",
    "credential_invalid": "凭据无效或已过期",
    "checkout_failed": "结账会话创建失败，结果不确定",
    "stripe_init_failed": "结账会话已创建，但 Stripe 初始化失败",
    "payment_methods_unknown": "Stripe 未返回明确的支付方式列表",
    "unexpected_mode": "Stripe Session 不是 subscription 模式",
}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _checkout_body() -> dict[str, Any]:
    return {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "price_interval": "month",
        "seat_quantity": 1,
        "billing_details": {"country": "VN", "currency": "VND"},
        "checkout_ui_mode": "custom",
        "subscription_data": {"trial_period_days": 30},
    }


def _has_trial(payload: dict[str, Any]) -> tuple[bool, Any, bool]:
    for item in (payload, payload.get("checkout_session"), payload.get("elements_options")):
        if not isinstance(item, dict):
            continue
        data = item.get("subscription_data") if isinstance(item.get("subscription_data"), dict) else item
        days = data.get("trial_period_days")
        end = data.get("trial_end")
        try:
            if int(days or 0) > 0:
                return True, days, bool(end)
        except (TypeError, ValueError):
            pass
        if end not in (None, "", 0, "0", False):
            return True, days, True
    return False, None, False


def _methods(payload: dict[str, Any]) -> list[str] | None:
    methods = payload.get("payment_method_types")
    if not isinstance(methods, list):
        elements = payload.get("elements_options")
        methods = elements.get("payment_method_types") if isinstance(elements, dict) else None
    if not isinstance(methods, list):
        return None
    return sorted({str(method).lower() for method in methods})


def _stripe_value(payload: dict[str, Any], key: str) -> Any:
    elements = payload.get("elements_options")
    return elements.get(key) if isinstance(elements, dict) and key in elements else payload.get(key)


def _checkout_error(response: Any) -> str:
    text = str(getattr(response, "text", "") or "").lower()
    if "already" in text and ("subscrib" in text or "paid" in text):
        return "already_paid"
    if int(getattr(response, "status_code", 0) or 0) == 401:
        return "credential_invalid"
    return "checkout_failed"


def _checkout_failure_message(response: Any) -> str:
    """Return an actionable, response-body-free reason for a failed checkout."""
    status = int(getattr(response, "status_code", 0) or 0)
    detail = _safe_error_detail(response)
    if status == 400:
        message = "结账请求被拒绝 (HTTP 400)，当前账号或结账参数不被后端接受"
        return f"{message}：{detail}" if detail else message
    if status == 401:
        return DECISION_TEXT["credential_invalid"]
    if status == 403:
        message = "结账请求被拒绝 (HTTP 403)，越南代理出口或会话可能触发风控"
        return f"{message}：{detail}" if detail else message
    if status == 429:
        return "结账请求过于频繁 (HTTP 429)，请稍后重试或降低并发"
    if status >= 500:
        return f"结账服务暂时异常 (HTTP {status})，可稍后重试"
    message = f"结账请求失败 (HTTP {status or '未知'})"
    return f"{message}：{detail}" if detail else message


def _safe_error_detail(response: Any) -> str:
    """Extract a short validation reason without retaining response bodies or IDs."""
    try:
        payload = response.json()
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    candidates: list[Any] = []
    if isinstance(error, dict):
        candidates.extend(error.get(key) for key in ("code", "type", "message", "detail"))
    candidates.extend(payload.get(key) for key in ("code", "type", "message", "detail"))
    for value in candidates:
        text = str(value or "").strip().replace("\r", " ").replace("\n", " ")
        if not text:
            continue
        # Never surface values that could be a credential or a checkout identifier.
        if any(marker in text.lower() for marker in ("bearer ", "access_token", "refresh_token", "cs_", "pk_", "sk_")):
            continue
        return text[:180]
    return ""


def _retryable_checkout_status(status: int) -> bool:
    return status in {403, 408, 409, 425, 429} or status >= 500


def _reset_circuit(env: BrowserSession) -> None:
    reset = getattr(env, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    else:
        env.blocked_until = 0.0
        env.blocked_reason = ""


def _warm_session(env: BrowserSession) -> None:
    """Establish edge cookies before the checkout XHR when the session supports it."""
    navigate_headers = getattr(env, "get_chatgpt_navigate_headers", None)
    request_get = getattr(env, "get", None)
    if not callable(navigate_headers) or not callable(request_get):
        return
    try:
        request_get(
            "https://chatgpt.com/",
            headers=navigate_headers(referer="https://chatgpt.com/", user_initiated=False),
            allow_redirects=True,
        )
    except Exception:
        pass
    finally:
        _reset_circuit(env)


def _retry_settings() -> tuple[int, float]:
    try:
        attempts = int(getattr(proxy_cfg, "PLAN_CHECK_MAX_ATTEMPTS", 2) or 2)
    except (TypeError, ValueError):
        attempts = 2
    try:
        delay = float(getattr(proxy_cfg, "PLAN_CHECK_RETRY_DELAY", 1.5) or 0.0)
    except (TypeError, ValueError):
        delay = 1.5
    return max(1, min(3, attempts)), max(0.0, min(15.0, delay))


def _decision(one_click_eligible: Any, actual_trial: bool, mode: Any, has_momo: bool | None) -> str:
    if not actual_trial and one_click_eligible is False:
        return "account_trial_ineligible"
    if not actual_trial:
        return "trial_not_applied"
    if str(mode or "") != "subscription":
        return "unexpected_mode"
    if has_momo is None:
        return "payment_methods_unknown"
    return "ready" if has_momo else "momo_not_enabled"


def probe_momo_eligibility(token: str, *, proxy: str | None = None, timeout: float = 20.0) -> dict:
    """Return a redacted checkout capability decision for one access token."""
    token = normalize_token(token)
    claims = token_claims(token)
    base = {"checked_at": _now(), **{k: v for k, v in claims.items() if k != "payload"}}
    if not token or claims.get("token_expired") is True:
        return {"ok": False, "decision": "credential_invalid", "error": DECISION_TEXT["credential_invalid"], **base}
    try:
        route = resolve_plan_check_route(proxy)
    except Exception as exc:
        return {"ok": False, "decision": "checkout_failed", "error": f"网络配置错误: {exc}", **base}

    route_meta = {key: value for key, value in route.items() if key != "proxy"}
    env: BrowserSession | None = None
    try:
        env = BrowserSession(proxy=route["proxy"], detect_exit_geo=True, fingerprint_seed=f"momo-check:{uuid.uuid4()}")
        _warm_session(env)
        headers = env.get_chatgpt_headers(referer="https://chatgpt.com/")
        headers.update({
            "authorization": f"Bearer {token}",
            "x-openai-target-path": "/backend-api/payments/checkout",
            "x-openai-target-route": "/backend-api/payments/checkout",
        })
        account_id = str(claims.get("account_id") or "").strip()
        if account_id:
            headers["chatgpt-account-id"] = account_id
        timeout_seconds = max(1.0, min(60.0, float(timeout)))
        attempts, retry_delay = _retry_settings()
        response = None
        last_exception: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = env.post(CHECKOUT_URL, json=_checkout_body(), headers=headers, timeout=timeout_seconds)
                status = int(response.status_code or 0)
                if 200 <= status < 300 or not _retryable_checkout_status(status) or attempt >= attempts:
                    break
                _reset_circuit(env)
                if retry_delay:
                    time.sleep(retry_delay * attempt)
            except Exception as exc:
                last_exception = exc
                if attempt >= attempts:
                    break
                _reset_circuit(env)
                if retry_delay:
                    time.sleep(retry_delay * attempt)
        if response is None:
            return {
                "ok": False, "decision": "checkout_failed",
                "error": f"结账网络请求失败: {type(last_exception).__name__ if last_exception else '未知错误'}",
                "attempt_count": attempts, **route_meta, **base,
            }
        if not 200 <= int(response.status_code) < 300:
            decision = _checkout_error(response)
            return {
                "ok": decision in {"already_paid", "credential_invalid"}, "decision": decision,
                "error": DECISION_TEXT[decision] if decision != "checkout_failed" else _checkout_failure_message(response),
                "http_status": response.status_code, "attempt_count": attempt,
                **route_meta, **base,
            }
        checkout = response.json() or {}
        checkout_id = str(checkout.get("checkout_session_id") or checkout.get("session_id") or checkout.get("id") or "")
        if not checkout_id.startswith("cs_"):
            return {"ok": False, "decision": "checkout_failed", "error": "结账响应未返回有效会话", **route_meta, **base}

        one_click_eligible = checkout.get("one_click_trial_eligible")
        checkout_trial, _, _ = _has_trial(checkout)
        if one_click_eligible is False and not checkout_trial:
            return {"ok": True, "decision": "account_trial_ineligible", "decision_text": DECISION_TEXT["account_trial_ineligible"], "actual_trial": False, "has_momo": False, "one_click_trial_eligible": False, **route_meta, **base}

        raw_key = " ".join(str(checkout.get(key) or "") for key in ("stripe_publishable_key", "publishable_key", "publishableKey", "stripePublishableKey", "key"))
        match = re.search(r"pk_live_[A-Za-z0-9]+", raw_key)
        stripe_key = match.group(0) if match else DEFAULT_STRIPE_PK
        if not stripe_key:
            return {"ok": False, "decision": "stripe_init_failed", "error": "结账响应未返回 Stripe publishable key", **route_meta, **base}
        # Stripe's checkout bootstrap is a public request.  The session ID is only
        # submitted in-memory and is never returned, logged, or stored.
        stripe_response = env.session.post(
            STRIPE_INIT_URL,
            data={"key": stripe_key, "payment_page_id": checkout_id, "locale": "auto"},
            headers={"Origin": "https://js.stripe.com", "Referer": "https://js.stripe.com/"},
            timeout=max(1.0, min(60.0, float(timeout))),
        )
        if not 200 <= int(stripe_response.status_code) < 300:
            return {"ok": False, "decision": "stripe_init_failed", "error": DECISION_TEXT["stripe_init_failed"], "http_status": stripe_response.status_code, **route_meta, **base}
        init = stripe_response.json() or {}
        methods = _methods(init)
        init_trial, trial_days, trial_end = _has_trial(init)
        actual_trial = bool(checkout_trial or init_trial)
        has_momo = None if methods is None else "momo" in methods
        decision = _decision(one_click_eligible, actual_trial, _stripe_value(init, "mode"), has_momo)
        return {
            "ok": decision not in {"stripe_init_failed", "checkout_failed"},
            "decision": decision,
            "decision_text": DECISION_TEXT[decision],
            "one_click_trial_eligible": one_click_eligible,
            "actual_trial": actual_trial,
            "trial_period_days": trial_days,
            "trial_end_present": trial_end,
            "stripe_mode": _stripe_value(init, "mode"),
            "methods": methods or [],
            "payment_methods_known": methods is not None,
            "has_momo": has_momo,
            **route_meta,
            **base,
        }
    except Exception as exc:
        return {"ok": False, "decision": "checkout_failed", "error": f"{type(exc).__name__}: {str(exc)[:240]}", **route_meta, **base}
    finally:
        if env is not None:
            try:
                env.session.close()
            except Exception:
                pass
