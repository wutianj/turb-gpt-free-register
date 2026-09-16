# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core.roxybrowser_client import RoxyBrowserClient


class RoxyProfileMetadataTests(unittest.TestCase):
    def test_create_profile_keeps_only_safe_comparison_metadata(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:1")
        with patch.object(client, "request", return_value={"data": {"dirId": "profile-1"}}), patch(
            "core.roxybrowser_client._random_roxy_os", return_value="Windows"
        ), patch("core.roxybrowser_client._random_roxy_profile_name", return_value="profile-name"):
            profile_id = client.create_profile()

        self.assertEqual(profile_id, "profile-1")
        self.assertEqual(client.last_create_metadata["os"], "Windows")
        self.assertNotIn("host", client.last_create_metadata)
        self.assertNotIn("proxyUserName", client.last_create_metadata)
        self.assertNotIn("proxyPassword", client.last_create_metadata)


if __name__ == "__main__":
    unittest.main()
