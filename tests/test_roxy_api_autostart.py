import unittest
from unittest.mock import patch

import requests

from core.roxybrowser_client import _is_connection_refused, _local_api_port


class RoxyApiAutostartTests(unittest.TestCase):
    def test_only_loopback_api_is_eligible(self):
        self.assertEqual(_local_api_port("http://127.0.0.1:50100"), 50100)
        self.assertEqual(_local_api_port("http://localhost:50100/base"), 50100)
        self.assertIsNone(_local_api_port("https://api.example.test:50100"))

    def test_connection_refusal_is_transport_error(self):
        self.assertTrue(_is_connection_refused(requests.exceptions.ConnectionError("connection refused")))
        self.assertFalse(_is_connection_refused(RuntimeError("Roxy API HTTP 400")))


if __name__ == "__main__":
    unittest.main()
