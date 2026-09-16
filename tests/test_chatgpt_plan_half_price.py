# -*- coding: utf-8 -*-
import unittest

from core.chatgpt_plan import parse_accounts_check


def _response(discount=50, periods=1, period="month"):
    return {
        "accounts": {
            "account-1": {
                "account": {"account_id": "account-1", "plan_type": "free"},
                "entitlement": {"subscription_plan": "chatgptfreeplan"},
                "eligible_promo_campaigns": {
                    "plus": {
                        "id": "plus-1-month-50-pct-off",
                        "metadata": {
                            "discount": {"percentage": discount},
                            "duration": {"num_periods": periods, "period": period},
                        },
                    },
                },
            },
        },
    }


class HalfPriceOfferTests(unittest.TestCase):
    def test_full_discount_is_classified_as_zero_price_trial(self):
        result = parse_accounts_check(_response(discount=100, periods=1))
        self.assertTrue(result["plus_trial_eligible"])
        self.assertTrue(result["plus_zero_price_eligible"])
        self.assertFalse(result["plus_half_price_eligible"])
        self.assertEqual(result["plus_trial_offer_type"], "zero_price")

    def test_fifty_percent_plus_offer_is_detected_for_any_positive_month_count(self):
        result = parse_accounts_check(_response())
        self.assertTrue(result["plus_trial_eligible"])
        self.assertTrue(result["plus_half_price_eligible"])
        self.assertFalse(result["plus_zero_price_eligible"])
        self.assertEqual(result["plus_trial_offer_type"], "half_price")

        two_month_result = parse_accounts_check(_response(periods=2))
        self.assertEqual(two_month_result["plus_trial_duration_num_periods"], 2)
        self.assertTrue(two_month_result["plus_half_price_eligible"])

        three_month_result = parse_accounts_check(_response(periods=3))
        self.assertEqual(three_month_result["plus_trial_duration_num_periods"], 3)
        self.assertTrue(three_month_result["plus_half_price_eligible"])

    def test_other_plus_offer_is_not_labeled_one_month_half_price(self):
        result = parse_accounts_check(_response(discount=25, periods=3))
        self.assertTrue(result["plus_trial_eligible"])
        self.assertFalse(result["plus_half_price_eligible"])


if __name__ == "__main__":
    unittest.main()
