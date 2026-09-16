# -*- coding: utf-8 -*-
"""Background queue for per-account MoMo checkout capability checks."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from config import proxy as proxy_cfg
from core import db
from core.momo_check import probe_momo_eligibility

logger = logging.getLogger(__name__)
_WORKERS = max(1, min(16, int(getattr(proxy_cfg, "MOMO_CHECK_WORKERS", 2) or 2)))
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="momo-check")


def _run(*, account_id: int, token: str, proxy: str | None) -> None:
    if not db.mark_account_momo_check_running(account_id):
        return
    result = probe_momo_eligibility(token, proxy=proxy, timeout=float(getattr(proxy_cfg, "MOMO_CHECK_TIMEOUT", 20.0) or 20.0))
    db.update_account_momo_check(account_id, result)
    logger.info("[MoMo] 检测完成: account_id=%s decision=%s", account_id, result.get("decision"))


def enqueue(*, account_id: int, token: str, trigger: str, proxy: str | None = None) -> dict:
    if not str(token or "").strip():
        return {"accepted": False, "error": "该账号没有 access_token"}
    if not db.claim_account_momo_check(account_id, trigger=trigger):
        return {"accepted": False, "busy": True, "error": "该账号正在检测 MoMo"}
    try:
        _EXECUTOR.submit(_run, account_id=int(account_id), token=token, proxy=proxy)
    except Exception as exc:
        db.update_account_momo_check(account_id, {"ok": False, "decision": "checkout_failed", "error": f"入队失败: {type(exc).__name__}: {exc}"})
        return {"accepted": False, "error": "MoMo 检测入队失败"}
    return {"accepted": True, "status": "queued", "account_id": int(account_id)}


def queue_settings() -> dict:
    return {"workers": _WORKERS}
