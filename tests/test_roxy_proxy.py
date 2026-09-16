# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core.roxybrowser_client import _mask_proxy, _proxy_url_to_roxy_info
from config.proxy import normalize_proxy_url


class RoxyProxyFormatTests(unittest.TestCase):
    def test_converts_supplier_host_port_username_password_format(self):
        with patch("core.roxybrowser_client._cfg.ROXY_PROXY_CHECK_CHANNEL", ""), patch(
            "core.roxybrowser_client._cfg.ROXY_PROXY_DEFAULT_PROTOCOL", "http"
        ):
            info = _proxy_url_to_roxy_info("proxy.example.test:9000:user-name:secret:with:colon")

        self.assertEqual(info["protocol"], "HTTP")
        self.assertEqual(info["host"], "proxy.example.test")
        self.assertEqual(info["port"], "9000")
        self.assertEqual(info["proxyUserName"], "user-name")
        self.assertEqual(info["proxyPassword"], "secret:with:colon")

    def test_uses_configured_default_protocol_for_supplier_format(self):
        with patch("core.roxybrowser_client._cfg.ROXY_PROXY_CHECK_CHANNEL", ""), patch(
            "core.roxybrowser_client._cfg.ROXY_PROXY_DEFAULT_PROTOCOL", "socks5"
        ):
            info = _proxy_url_to_roxy_info("proxy.example.test:9000:user-name:secret")

        self.assertEqual(info["protocol"], "SOCKS5")

    def test_masks_supplier_format_credentials(self):
        self.assertEqual(
            _mask_proxy("proxy.example.test:9000:user-name:secret"),
            "http://***:***@proxy.example.test:9000",
        )

    def test_normalizes_supplier_format_for_curl_clients(self):
        self.assertEqual(
            normalize_proxy_url(
                "proxy.example.test:9000:user-name:secret:with:colon",
                default_protocol="socks5",
            ),
            "socks5://user-name:secret%3Awith%3Acolon@proxy.example.test:9000",
        )

    def test_keeps_remote_dns_proxy_protocol(self):
        self.assertEqual(
            normalize_proxy_url(
                "proxy.example.test:9000:user-name:secret",
                default_protocol="socks5h",
            ),
            "socks5h://user-name:secret@proxy.example.test:9000",
        )


if __name__ == "__main__":
    unittest.main()
