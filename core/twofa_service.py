# -*- coding: utf-8 -*-
"""账号 2FA/TOTP 后台设置队列。"""
from __future__ import annotations

import logging
import json
import secrets
import string
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from config import email as _email_cfg
from core import db
from core.account_export import setup_2fa
from core import chatgpt_account_recovery as account_recovery
from core.email_provider import wait_for_otp
from core.session import BrowserSession

logger = logging.getLogger(__name__)

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="twofa")
_QUEUE_SLOTS = threading.BoundedSemaphore(50)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"twofa-{safe}.log"


def _normalize_proxy(proxy: str | None) -> str | None:
    """
    2FA 入口只接受真实代理地址。

    注册流程里有些 `proxy_used` 字段保存的是环境标签，例如 `skyvern:jp`、
    `browser_use:jp`，这类不是 curl_cffi 可用代理，会导致 Unsupported proxy syntax。
    """
    text = str(proxy or "").strip()
    if not text:
        return None
    low = text.lower()
    if low.startswith(("http://", "https://", "socks5://", "socks5h://", "socks4://", "socks4a://")):
        return text
    return None


def is_running(acc_id: int) -> bool:
    with _LOCK:
        return int(acc_id) in _RUNNING


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _registration_password(account: dict) -> str:
    try:
        extra = json.loads(str(account.get("extra_json") or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        extra = {}
    return str((extra if isinstance(extra, dict) else {}).get("registration_password") or "").strip()


def _generate_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value) and any(c in "!@#$%" for c in value)):
            return value


def _use_roxy_security_flow() -> bool:
    try:
        from config import roxybrowser as roxy_cfg

        return str(getattr(roxy_cfg, "REGISTRATION_DRIVER", "") or "").strip().lower() == "roxy"
    except Exception:
        return False


def _ensure_password_for_twofa(*, account_id: int, email: str, proxy: str | None) -> tuple[str, str]:
    account = db.get_account(account_id) or {}
    existing = _registration_password(account)
    if existing:
        result = account_recovery.login_with_password_for_session(email=email, password=existing)
        db.update_account_security_material(
            account_id, access_token=result.access_token, stage="password-ready", error=None,
        )
        return existing, result.access_token

    db.update_account_security_material(account_id, stage="requesting-password-otp", error=None)
    client = account_recovery._new_browser_session()
    real_proxy = _normalize_proxy(proxy)
    if real_proxy:
        client.proxies.update({"http": real_proxy, "https": real_proxy})
    started_at = time.time()
    flow = account_recovery.start_password_email_otp_flow(email=email, action="add", session=client)
    db.update_account_security_material(account_id, stage="waiting-password-otp", error=None)
    otp = wait_for_otp(email, after_ts=started_at, email_source=account.get("email_source"))
    password = _generate_password()
    try:
        result = account_recovery.add_or_reset_password_with_email_otp(
            email=email, otp_code=otp, password=password, action="add", session=client,
        )
    except account_recovery.PasswordAlreadyExistsError:
        raise RuntimeError("账号已有 ChatGPT 密码，但本地未保存，需先补录密码")
    db.update_account_security_material(
        account_id,
        registration_password=password,
        access_token=result.access_token or None,
        stage="password-ready",
        error=None,
    )
    if not result.access_token:
        raise RuntimeError("ChatGPT 密码已设置，但未取得可用于绑定 2FA 的新 access_token")
    return password, result.access_token


def _run_twofa(
    *, account_id: int, email: str, access_token: str, proxy: str | None,
    trigger: str,
) -> dict:
    fh: logging.FileHandler | None = None
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    try:
        with _LOCK:
            _RUNNING.add(int(account_id))
        if not db.mark_account_totp_setup_running(account_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或 2FA 状态已被重置"}
        log_file = log_path(email)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("", encoding="utf-8")
        fh = logging.FileHandler(str(log_path(email)), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)
        logger.info("[2FA] 开始后台设置：email=%s trigger=%s", email, trigger)
        real_proxy = _normalize_proxy(proxy)
        if _use_roxy_security_flow():
            from core.roxy_twofa import setup_password_and_totp_via_roxy

            account = db.get_account(account_id) or {}
            existing_password = _registration_password(account)
            password = existing_password or _generate_password()
            db.update_account_security_material(account_id, stage="opening-roxy-security", error=None)
            _append_log(email, "[2FA] 使用官方 Roxy 浏览器执行密码设置与 TOTP 绑定")

            def _persist_password(value: str) -> None:
                db.update_account_security_material(
                    account_id,
                    registration_password=value,
                    stage="password-ready",
                    error=None,
                )
                _append_log(email, "[2FA] ChatGPT 密码已设置并保存")

            def _persist_access_token(value: str) -> None:
                db.update_account_security_material(
                    account_id,
                    access_token=value,
                    stage="binding-totp",
                    error=None,
                )
                _append_log(email, "[2FA] Roxy 登录会话已刷新，开始绑定 TOTP")

            def _persist_network_traffic(value: dict) -> None:
                db.update_account_security_material(
                    account_id,
                    twofa_network_traffic=value,
                )
                total = int(value.get("total_bytes") or 0)
                _append_log(email, f"[2FA] 浏览器代理流量：{total} bytes")

            def _otp_provider(target_email: str, *, after_ts: float = 0.0) -> str:
                return wait_for_otp(
                    target_email,
                    after_ts=after_ts,
                    email_source=account.get("email_source"),
                )

            result = setup_password_and_totp_via_roxy(
                email=email,
                password=password,
                password_already_set=bool(existing_password),
                otp_provider=_otp_provider,
                on_password_set=_persist_password,
                on_access_token=_persist_access_token,
                on_network_traffic=_persist_network_traffic,
            )
            secret = str(result.get("totp_secret") or "").strip()
            if not secret:
                raise RuntimeError("Roxy 2FA 流程未返回 TOTP secret")
        else:
            identity = email.strip().lower()
            session = BrowserSession(proxy=real_proxy, fingerprint_seed=f"account:{identity}")
            _append_log(email, f"[2FA] 会话创建完成：proxy={session.proxy or 'direct'} device_id={session.device_id}")
            _append_log(email, f"[2FA] 指纹摘要：{session.fingerprint_summary_text()}")
            _append_log(email, "[2FA] 阶段1：确保 ChatGPT 登录密码已设置")
            _, current_token = _ensure_password_for_twofa(
                account_id=account_id, email=email, proxy=real_proxy,
            )
            _append_log(email, "[2FA] ChatGPT 密码阶段完成，开始绑定 TOTP")
            db.update_account_security_material(account_id, stage="binding-totp", error=None)
            secret = setup_2fa(session, email, access_token=current_token or access_token)
        db.update_account_totp_secret(
            account_id,
            {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"},
        )
        db.update_account_security_material(account_id, stage="complete", error=None)
        _append_log(email, f"[2FA] 完成：secret={secret[:4]}...{secret[-4:]}")
        logger.info("[2FA] 完成：email=%s secret=%s...%s", email, secret[:4], secret[-4:])
        return {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"}
    except Exception as exc:
        result = {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
        try:
            db.update_account_security_material(account_id, stage="failed", error=result["error"])
            db.update_account_totp_secret(account_id, result)
        except Exception:
            logger.exception("[2FA] 写回失败状态失败: account_id=%s", account_id)
        try:
            _append_log(email, f"[2FA] 失败：{result['error']}")
        except Exception:
            pass
        logger.exception("[2FA] 后台异常: %s", email)
        return result
    finally:
        if fh is not None:
            try:
                root_logger.removeHandler(fh)
                fh.close()
            except Exception:
                pass
        with _LOCK:
            _RUNNING.discard(int(account_id))
        _QUEUE_SLOTS.release()


def enqueue_account_totp_setup(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str = "manual",
    proxy: str | None = None,
) -> dict:
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email 为空"}
    if not access_token:
        return {"accepted": False, "busy": False, "error": "缺少 access_token"}
    if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
        return {"accepted": False, "busy": False, "error": "启用 2FA 需要先开启 USE_EMAIL_SERVICE 自动收取邮箱验证码"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "2FA 队列已满，请稍后重试"}
    if not db.claim_account_totp_setup(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在设置 2FA"}

    _append_log(email, f"[2FA] 已入队 account_id={account_id} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(
            _run_twofa,
            account_id=account_id,
            email=email,
            access_token=access_token,
            proxy=proxy,
            trigger=str(trigger or "manual"),
        )
        return {"accepted": True, "busy": False, "future": future, "log_path": str(log_path(email))}
    except Exception as exc:
        _QUEUE_SLOTS.release()
        db.update_account_totp_secret(account_id, {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        return {"accepted": False, "busy": False, "error": f"{type(exc).__name__}: {exc}"}
