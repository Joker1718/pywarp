"""Tests for the protocol/mode guard matrix (SP3)."""

import unittest

from backend.guards import check_protocol_mode_guard


class GuardMatrixTests(unittest.TestCase):
    def test_warp_wireguard_allowed(self):
        self.assertIsNone(check_protocol_mode_guard("warp", "WireGuard", "auto"))

    def test_warp_plus_doh_wireguard_allowed(self):
        self.assertIsNone(check_protocol_mode_guard("warp+doh", "WireGuard", "auto"))

    def test_proxy_wireguard_blocked(self):
        message = check_protocol_mode_guard("proxy", "WireGuard", "auto")
        self.assertIsNotNone(message)
        self.assertIn("MASQUE", message)

    def test_proxy_masque_h2_only_blocked(self):
        message = check_protocol_mode_guard("proxy", "MASQUE", "h2-only")
        self.assertIsNotNone(message)
        self.assertIn("HTTP/2", message)

    def test_proxy_masque_default_allowed(self):
        self.assertIsNone(check_protocol_mode_guard("proxy", "MASQUE", "h3-with-h2-fallback"))

    def test_warp_masque_h2_only_allowed(self):
        self.assertIsNone(check_protocol_mode_guard("warp", "MASQUE", "h2-only"))


if __name__ == "__main__":
    unittest.main()
