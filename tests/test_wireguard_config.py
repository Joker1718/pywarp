"""Tests for the WARP-safe AmneziaWG config builder (SP1)."""

import unittest

from backend import wireguard_config as wgc


class BuildConfigTests(unittest.TestCase):
    def test_golden_config_warp_safe(self):
        conf = wgc.build_tunnel_config(
            private_key_b64="ABC=",
            address_v4="172.16.0.2/32",
            address_v6="2606:4700:110:8a62::1/128",
        )
        self.assertIn("[Interface]", conf)
        self.assertIn("PrivateKey = ABC=", conf)
        self.assertIn(
            "Address = 172.16.0.2/32, 2606:4700:110:8a62::1/128", conf
        )
        self.assertIn("DNS = 1.1.1.1", conf)
        self.assertIn("MTU = 1280", conf)
        # WARP-safe identity shared params (S1..S4 = 0, H1..H4 = 1..4).
        self.assertIn("S1 = 0", conf)
        self.assertIn("S2 = 0", conf)
        self.assertIn("S3 = 0", conf)
        self.assertIn("S4 = 0", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H2 = 2", conf)
        self.assertIn("H3 = 3", conf)
        self.assertIn("H4 = 4", conf)
        # Client-side junk packets present (DPI resistance, client-only).
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 40", conf)
        self.assertIn("Jmax = 70", conf)
        self.assertIn("[Peer]", conf)
        self.assertIn(
            f"PublicKey = {wgc.PEER_PUBLIC_KEY}", conf
        )
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", conf)
        self.assertIn(
            f"Endpoint = {wgc.DEFAULT_ENDPOINT}", conf
        )
        self.assertIn("PersistentKeepalive = 25", conf)

    def test_junk_disabled_omits_block(self):
        conf = wgc.build_tunnel_config(
            private_key_b64="ABC=",
            address_v4="172.16.0.2/32",
            address_v6="",
            junk=None,
            include_junk=False,
        )
        self.assertNotIn("Jc =", conf)
        self.assertNotIn("Jmin =", conf)
        self.assertNotIn("Jmax =", conf)
        self.assertIn("Address = 172.16.0.2/32", conf)
        self.assertNotIn(", \n", conf)  # no dangling v6 separator

    def test_custom_endpoint(self):
        conf = wgc.build_tunnel_config(
            private_key_b64="ABC=",
            address_v4="172.16.0.2/32",
            address_v6="",
            endpoint="162.159.192.1:943",
        )
        self.assertIn("Endpoint = 162.159.192.1:943", conf)

    def test_wireguard_profile_is_plain(self):
        # The stock WireGuard parser rejects unknown [Interface] keys, so the
        # wireguard profile must not emit AWG-only keys (review Blocking 2).
        conf = wgc.build_tunnel_config(
            private_key_b64="ABC=",
            address_v4="172.16.0.2/32",
            address_v6="",
            profile="wireguard",
        )
        self.assertIn("[Interface]", conf)
        self.assertIn("PrivateKey = ABC=", conf)
        self.assertIn("MTU = 1280", conf)
        self.assertIn("[Peer]", conf)
        for awg_key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
            self.assertNotIn(f"{awg_key} =", conf)


class ValidateJunkTests(unittest.TestCase):
    def test_defaults_valid(self):
        j = wgc.DEFAULT_JUNK
        wgc.validate_junk_params(j["Jc"], j["Jmin"], j["Jmax"])

    def test_jc_bounds(self):
        with self.assertRaises(ValueError):
            wgc.validate_junk_params(0, 10, 20)
        with self.assertRaises(ValueError):
            wgc.validate_junk_params(129, 10, 20)

    def test_range_bounds(self):
        with self.assertRaises(ValueError):
            wgc.validate_junk_params(4, 20, 10)  # jmin >= jmax
        with self.assertRaises(ValueError):
            wgc.validate_junk_params(4, 20, 1281)  # jmax > 1280
        with self.assertRaises(ValueError):
            wgc.validate_junk_params(4, -1, 20)

    def test_s1_plus_56_not_equal_s2_guard(self):
        # Shared-param sanity from the AWG constraints (init/resp size collision).
        with self.assertRaises(ValueError):
            wgc.validate_shared_params({"S1": 10, "S2": 66, "S3": 0, "S4": 0, "H1": 1, "H2": 2, "H3": 3, "H4": 4})

    def test_identity_params_accepted(self):
        wgc.validate_shared_params(wgc.IDENTITY_PARAMS)


if __name__ == "__main__":
    unittest.main()
