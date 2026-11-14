"""Tests for tunnel engine discovery and service control (SP2)."""

import unittest
from unittest.mock import MagicMock, patch

from backend import tunnel_engine as te


class FindEngineTests(unittest.TestCase):
    def test_prefers_amneziawg_over_wireguard(self):
        engine = te.find_engine_from_paths(
            amneziawg_path="C:/Program Files/AmneziaWG/amneziawg.exe",
            wireguard_path="C:/Program Files/WireGuard/wireguard.exe",
        )
        self.assertEqual(engine.name, "AmneziaWG")
        self.assertEqual(engine.service_prefix, "AmneziaWGTunnel$")

    def test_falls_back_to_wireguard(self):
        engine = te.find_engine_from_paths(
            amneziawg_path=None,
            wireguard_path="C:/Program Files/WireGuard/wireguard.exe",
        )
        self.assertEqual(engine.name, "WireGuard")
        self.assertEqual(engine.service_prefix, "WireGuardTunnel$")

    def test_none_when_missing(self):
        self.assertIsNone(te.find_engine_from_paths(amneziawg_path=None, wireguard_path=None))

    def test_service_name_derivation(self):
        engine = te.Engine("AmneziaWG", "amneziawg.exe", "AmneziaWGTunnel$")
        self.assertEqual(te.service_name(engine), "AmneziaWGTunnel$pywarp-warp")


class ServiceControlTests(unittest.TestCase):
    def setUp(self):
        self.engine = te.Engine("AmneziaWG", "C:/awg/amneziawg.exe", "AmneziaWGTunnel$")

    @patch("backend.tunnel_engine.subprocess.run")
    def test_install_command_shape(self, run_mock):
        run_mock.return_value = MagicMock(returncode=0)
        te.install_tunnel(self.engine, "C:/conf/pywarp-warp.conf")
        args = run_mock.call_args.args[0]
        self.assertEqual(
            args,
            ["C:/awg/amneziawg.exe", "/installtunnelservice", "C:/conf/pywarp-warp.conf"],
        )
        # CREATE_NO_WINDOW on Windows keeps the CLI invisible.
        self.assertEqual(
            run_mock.call_args.kwargs.get("creationflags"),
            te.subprocess.CREATE_NO_WINDOW if hasattr(te.subprocess, "CREATE_NO_WINDOW") else 0,
        )

    @patch("backend.tunnel_engine.subprocess.run")
    def test_uninstall_uses_tunnel_name_not_service_name(self, run_mock):
        # The CLI takes the TUNNEL name and derives the service name itself;
        # '$' is forbidden in tunnel names, so the service name must not be
        # passed (regression guard for review Blocking 1).
        run_mock.return_value = MagicMock(returncode=0, stdout="", stderr="")
        te.remove_tunnel(self.engine)
        args = run_mock.call_args.args[0]
        self.assertEqual(
            args,
            ["C:/awg/amneziawg.exe", "/uninstalltunnelservice", "pywarp-warp"],
        )
        self.assertNotIn("$", args[-1])

    @patch("backend.tunnel_engine.subprocess.run")
    def test_remove_tolerates_missing_tunnel(self, run_mock):
        run_mock.return_value = MagicMock(
            returncode=1, stderr="Tunnel 'pywarp-warp' does not exist", stdout=""
        )
        te.remove_tunnel(self.engine)  # must not raise

    @patch("backend.tunnel_engine.subprocess.run")
    def test_remove_raises_on_unknown_error(self, run_mock):
        run_mock.return_value = MagicMock(
            returncode=1, stderr="access denied", stdout=""
        )
        with self.assertRaises(te.EngineError):
            te.remove_tunnel(self.engine)

    @patch("backend.tunnel_engine.subprocess.run")
    def test_install_failure_raises(self, run_mock):
        run_mock.return_value = MagicMock(returncode=1, stderr="denied")
        with self.assertRaises(te.EngineError):
            te.install_tunnel(self.engine, "C:/conf/x.conf")

    @patch("backend.tunnel_engine.subprocess.run")
    def test_remove_idempotent_on_already_removed(self, run_mock):
        run_mock.return_value = MagicMock(returncode=1, stderr="service does not exist", stdout="")
        te.remove_tunnel(self.engine)  # must not raise

    @patch("backend.tunnel_engine.subprocess.run")
    def test_remove_real_failure_raises(self, run_mock):
        run_mock.return_value = MagicMock(returncode=1, stderr="access denied", stdout="")
        with self.assertRaises(te.EngineError):
            te.remove_tunnel(self.engine)

    @patch("backend.tunnel_engine.subprocess.run")
    def test_running_detection(self, run_mock):
        run_mock.return_value = MagicMock(
            returncode=0,
            stdout="SERVICE_NAME: AmneziaWGTunnel$pywarp-warp\nSTATE              : 4  RUNNING\n",
        )
        self.assertTrue(te.tunnel_service_running(self.engine))
        run_mock.return_value = MagicMock(
            returncode=0,
            stdout="STATE              : 1  STOPPED\n",
        )
        self.assertFalse(te.tunnel_service_running(self.engine))


if __name__ == "__main__":
    unittest.main()
