"""Tests for the WARP registration client (SP1)."""

import base64
import unittest
from unittest.mock import MagicMock

from backend import warp_registration as wr


# RFC 7748 section 6.1 test vectors.
VECTOR_1 = {
    "scalar": bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    ),
    "u": bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
    ),
    "out": bytes.fromhex(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    ),
}
VECTOR_2 = {
    "scalar": bytes.fromhex(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
    ),
    "u": bytes.fromhex(
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
    ),
    "out": bytes.fromhex(
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
    ),
}


class X25519Tests(unittest.TestCase):
    def test_public_key_rfc7748_vectors(self):
        for vector in (VECTOR_1, VECTOR_2):
            with self.subTest(vector=vector["scalar"].hex()[:8]):
                pub = wr.public_key(vector["scalar"], vector["u"])
                self.assertEqual(pub, vector["out"])

    def test_public_key_base64_roundtrip(self):
        priv = bytes(range(32))
        pub_b64 = wr.public_key_b64(priv)
        self.assertEqual(
            base64.b64decode(pub_b64), wr.public_key(priv)
        )

    def test_generate_private_key_shape(self):
        priv = wr.generate_private_key()
        self.assertEqual(len(priv), 32)
        self.assertNotEqual(priv, wr.generate_private_key())


class PayloadTests(unittest.TestCase):
    def test_headers_shape(self):
        headers = wr.registration_headers()
        self.assertEqual(
            headers["Content-Type"], "application/json; charset=UTF-8"
        )
        self.assertEqual(
            headers["User-Agent"], "1.1.1.1/6.38.9-5641 (Android 16.0.0)"
        )
        self.assertEqual(headers["CF-Client-Version"], "a-6.38.9-5641")

    def test_payload_shape(self):
        payload = wr.build_registration_payload("PUBKEY", "2026-01-01T00:00:00.000Z")
        self.assertEqual(payload["key"], "PUBKEY")
        self.assertEqual(payload["install_id"], "")
        self.assertEqual(payload["fcm_token"], "")
        self.assertEqual(payload["type"], "Android")
        self.assertEqual(payload["key_type"], "curve25519")
        self.assertEqual(payload["tos"], "2026-01-01T00:00:00.000Z")

    def test_registration_url(self):
        self.assertEqual(
            wr.registration_url(), "https://api.cloudflareclient.com/v0a5641/reg"
        )


class RegisterDeviceTests(unittest.TestCase):
    def _session(self, status, body):
        session = MagicMock()
        response = MagicMock()
        response.status_code = status
        response.json.return_value = body
        session.post.return_value = response
        return session

    def test_register_success(self):
        body = {
            "id": "dev-1",
            "token": "tok",
            "account": {"license": "lic-1"},
            "config": {
                "client_id": "abcd1234",
                "interface": {"addresses": {"v4": "172.16.0.2/32", "v6": "2606:4700:110:8a62::1/128"}},
                "peers": [{"endpoint": {"host": "engage.cloudflareclient.com", "v4": "162.159.192.1", "v6": "2606:4700:110:8a62:0000:0000:0000:0001", "port": 2408}}],
            },
        }
        device = wr.register_device(self._session(201, body), b"k" * 32, "2026-01-01T00:00:00.000Z")
        self.assertEqual(device["device_id"], "dev-1")
        self.assertEqual(device["token"], "tok")
        self.assertEqual(device["license"], "lic-1")
        self.assertEqual(device["client_id"], "abcd1234")
        self.assertEqual(device["address_v4"], "172.16.0.2/32")
        self.assertEqual(device["address_v6"], "2606:4700:110:8a62::1/128")
        # Endpoint host kept for the config builder.
        self.assertTrue(device["endpoint"])

    def test_register_429_maps_to_blocked(self):
        with self.assertRaises(wr.RegistrationBlocked):
            wr.register_device(self._session(429, {"errors": []}), b"k" * 32, "2026-01-01T00:00:00.000Z")

    def test_register_403_maps_to_blocked(self):
        with self.assertRaises(wr.RegistrationBlocked):
            wr.register_device(self._session(403, {"errors": []}), b"k" * 32, "2026-01-01T00:00:00.000Z")

    def test_register_500_maps_to_error(self):
        with self.assertRaises(wr.RegistrationError):
            wr.register_device(self._session(500, {}), b"k" * 32, "2026-01-01T00:00:00.000Z")

    def test_register_network_error_maps_to_error(self):
        session = MagicMock()
        session.post.side_effect = ConnectionError("boom")
        with self.assertRaises(wr.RegistrationError):
            wr.register_device(session, b"k" * 32, "2026-01-01T00:00:00.000Z")

    def test_blocked_message_mentions_import_fallback(self):
        try:
            wr.register_device(self._session(429, {}), b"k" * 32, "2026-01-01T00:00:00.000Z")
        except wr.RegistrationBlocked as exc:
            self.assertIn("import", str(exc).lower())


class ParseRegistrationResponseTests(unittest.TestCase):
    def test_minimal_response_defaults(self):
        device = wr.parse_registration_response({"id": "d", "token": "t"})
        self.assertEqual(device["device_id"], "d")
        self.assertEqual(device["token"], "t")
        self.assertEqual(device["address_v4"], "172.16.0.2/32")
        self.assertEqual(device["endpoint"], "engage.cloudflareclient.com:2408")
        self.assertEqual(device["client_id"], "")

    def test_malformed_response_does_not_raise(self):
        device = wr.parse_registration_response({"unexpected": [1, 2, 3]})
        self.assertEqual(device["device_id"], "")
        self.assertEqual(device["token"], "")


class DeleteDeviceTests(unittest.TestCase):
    def _session(self, status):
        session = MagicMock()
        response = MagicMock()
        response.status_code = status
        session.delete.return_value = response
        return session

    def test_delete_success(self):
        wr.delete_device(self._session(204), "tok", "dev-1")

    def test_delete_upstream_500_tolerated(self):
        # Cloudflare deactivate has returned 500 while still removing the device (wgcf #515).
        wr.delete_device(self._session(500), "tok", "dev-1")

    def test_delete_401_maps_to_error(self):
        with self.assertRaises(wr.RegistrationError):
            wr.delete_device(self._session(401), "tok", "dev-1")


class ParseWgConfigTests(unittest.TestCase):
    def test_parse_valid_config(self):
        conf = (
            "[Interface]\n"
            "PrivateKey = ABC=\n"
            "Address = 172.16.0.2/32, 2606:4700:110:8a62::1/128\n"
            "DNS = 1.1.1.1\n"
            "MTU = 1280\n"
            "Jc = 4\n"
            "Jmin = 40\n"
            "Jmax = 70\n"
            "\n"
            "[Peer]\n"
            "PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = engage.cloudflareclient.com:2408\n"
            "PersistentKeepalive = 25\n"
        )
        parsed = wr.parse_wg_config(conf)
        self.assertEqual(parsed["private_key"], "ABC=")
        self.assertEqual(parsed["address_v4"], "172.16.0.2/32")
        self.assertEqual(parsed["address_v6"], "2606:4700:110:8a62::1/128")
        self.assertEqual(parsed["endpoint"], "engage.cloudflareclient.com:2408")
        self.assertEqual(parsed["mtu"], 1280)
        self.assertEqual(parsed["junk"], {"Jc": 4, "Jmin": 40, "Jmax": 70})

    def test_parse_missing_private_key_raises(self):
        with self.assertRaises(wr.ConfigError):
            wr.parse_wg_config("[Peer]\nPublicKey = x\n")


if __name__ == "__main__":
    unittest.main()
