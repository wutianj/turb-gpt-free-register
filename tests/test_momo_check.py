# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core import momo_check


class _Response:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = ""

    def json(self):
        return self._payload


class _Session:
    def __init__(self, stripe_response):
        self.stripe_response = stripe_response
        self.stripe_calls = []
        self.closed = False

    def post(self, *args, **kwargs):
        self.stripe_calls.append((args, kwargs))
        return self.stripe_response

    def close(self):
        self.closed = True


class _BrowserSession:
    checkout_response = None
    stripe_response = None
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.session = _Session(type(self).stripe_response)
        self.post_calls = []
        type(self).instances.append(self)

    def get_chatgpt_headers(self, **_kwargs):
        return {"accept": "application/json"}

    def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        return type(self).checkout_response


class MomoCheckTests(unittest.TestCase):
    def setUp(self):
        _BrowserSession.instances = []

    def _probe(self, checkout, stripe):
        _BrowserSession.checkout_response = checkout
        _BrowserSession.stripe_response = stripe
        claims = {"payload": {}, "account_id": "account-1", "token_expired": False}
        route = {"proxy": "", "proxy_mode": "direct", "network_route": "direct", "proxy_used": None, "proxy_fallback_reason": None}
        with patch.object(momo_check, "BrowserSession", _BrowserSession), patch.object(momo_check, "token_claims", return_value=claims), patch.object(momo_check, "resolve_plan_check_route", return_value=route):
            return momo_check.probe_momo_eligibility("token")

    def test_ready_requires_trial_subscription_and_momo(self):
        result = self._probe(
            _Response(200, {"checkout_session_id": "cs_live_test", "stripe_publishable_key": "pk_live_123", "one_click_trial_eligible": True, "subscription_data": {"trial_period_days": 30}}),
            _Response(200, {"mode": "subscription", "payment_method_types": ["card", "momo"], "subscription_data": {"trial_period_days": 30}}),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["decision"], "ready")
        self.assertTrue(result["has_momo"])
        self.assertNotIn("checkout_session_id", result)
        stripe_args, stripe_kwargs = _BrowserSession.instances[0].session.stripe_calls[0]
        self.assertEqual(stripe_args[0], momo_check.STRIPE_INIT_URL)
        self.assertEqual(stripe_kwargs["data"]["payment_page_id"], "cs_live_test")

    def test_ineligible_stops_before_stripe_initialization(self):
        result = self._probe(
            _Response(200, {"checkout_session_id": "cs_live_test", "stripe_publishable_key": "pk_live_123", "one_click_trial_eligible": False}),
            _Response(200, {}),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["decision"], "account_trial_ineligible")
        self.assertEqual(_BrowserSession.instances[0].session.stripe_calls, [])

    def test_checkout_403_reports_actionable_redacted_error(self):
        result = self._probe(_Response(403, {"error": {"code": "cf_blocked"}}), _Response(200, {}))
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 403)
        self.assertIn("HTTP 403", result["error"])
        self.assertIn("cf_blocked", result["error"])


if __name__ == "__main__":
    unittest.main()
