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
        # The install command is the FIRST issued call (a demand-start
        # `sc config` follows it — R2 hardening).
        args = run_mock.call_args_list[0].args[0]
        self.assertEqual(
            args,
            ["C:/awg/amneziawg.exe", "/installtunnelservice", "C:/conf/pywarp-warp.conf"],
        )
        # CREATE_NO_WINDOW on Windows keeps the CLI invisible.
        self.assertEqual(
            run_mock.call_args_list[0].kwargs.get("creationflags"),
            te.subprocess.CREATE_NO_WINDOW if hasattr(te.subprocess, "CREATE_NO_WINDOW") else 0,
        )

    @patch("backend.tunnel_engine.subprocess.run")
    def test_uninstall_uses_tunnel_name_not_service_name(self, run_mock):
        # The CLI takes the TUNNEL name and derives the service name itself;
        # '$' is forbidden in tunnel names, so the service name must not be
        # passed (regression guard for review Blocking 1).
        run_mock.return_value = MagicMock(returncode=0, stdout="", stderr="")
        te.remove_tunnel(self.engine)
        # The CLI uninstall is the FIRST issued call and keeps the TUNNEL
        # name; the follow-up terminal-state verify uses `sc query`.
        args = run_mock.call_args_list[0].args[0]
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

    @patch("backend.tunnel_engine.subprocess.run")
    def test_remove_stops_running_service(self, run_mock):
        # A not-stopped service survives the CLI uninstall; the SCM stop/
        # delete escalation must clear it (field log 2026-11-17, run R1/R3).
        escalated = {"done": False}

        def fake_run(args, **kwargs):
            joined = " ".join(args)
            if "query" in joined:
                if escalated["done"]:
                    return MagicMock(returncode=1, stdout="", stderr="")
                return MagicMock(
                    returncode=0,
                    stdout="STATE              : 4  RUNNING\n",
                )
            if "stop" in joined or "delete" in joined:
                escalated["done"] = True
            return MagicMock(returncode=0, stdout="", stderr="")

        run_mock.side_effect = fake_run
        with patch.object(te, "_SERVICE_STOP_TIMEOUT_S", 0.3), patch.object(
            te, "_SERVICE_POLL_INTERVAL_S", 0.02
        ):
            te.remove_tunnel(self.engine)  # must not raise
        calls = [" ".join(c.args[0]) for c in run_mock.call_args_list]
        self.assertTrue(
            any("sc stop AmneziaWGTunnel$pywarp-warp" in c for c in calls)
        )
        self.assertTrue(
            any("sc delete AmneziaWGTunnel$pywarp-warp" in c for c in calls)
        )

    @patch("backend.tunnel_engine.subprocess.run")
    def test_remove_tolerates_stop_pending_then_stopped(self, run_mock):
        # The CLI uninstall itself initiates an async stop, so the query can
        # legitimately report STOP_PENDING; the removal must poll to the
        # terminal state instead of treating RUNNING-only as the gate.
        responses = iter(
            [
                MagicMock(returncode=0, stdout="STATE              : 3  STOP_PENDING\n"),
                MagicMock(returncode=0, stdout="STATE              : 1  STOPPED\n"),
            ]
        )

        def fake_run(args, **kwargs):
            if "query" in " ".join(args):
                return next(responses)
            return MagicMock(returncode=0, stdout="", stderr="")

        run_mock.side_effect = fake_run
        with patch.object(te, "_SERVICE_STOP_TIMEOUT_S", 5), patch.object(
            te, "_SERVICE_POLL_INTERVAL_S", 0.01
        ):
            te.remove_tunnel(self.engine)  # must not raise
        calls = [" ".join(c.args[0]) for c in run_mock.call_args_list]
        self.assertFalse(any("sc stop" in c or "sc delete" in c for c in calls))

    @patch("backend.tunnel_engine.subprocess.run")
    def test_remove_raises_when_service_wont_stop(self, run_mock):
        def fake_run(args, **kwargs):
            if "query" in " ".join(args):
                return MagicMock(
                    returncode=0, stdout="STATE              : 4  RUNNING\n"
                )
            return MagicMock(returncode=0, stdout="", stderr="")

        run_mock.side_effect = fake_run
        with patch.object(te, "_SERVICE_STOP_TIMEOUT_S", 0.05), patch.object(
            te, "_SERVICE_POLL_INTERVAL_S", 0.005
        ):
            with self.assertRaises(te.EngineError) as ctx:
                te.remove_tunnel(self.engine)
        self.assertIn("did not stop", str(ctx.exception))

    @patch("backend.tunnel_engine.subprocess.run")
    def test_install_sets_demand_start(self, run_mock):
        # The engine creates tunnel services AUTOMATIC; demand-start prevents
        # boot-time resurrection after a crash or forced power-off (R2).
        run_mock.return_value = MagicMock(returncode=0, stdout="", stderr="")
        te.install_tunnel(self.engine, "C:/conf/pywarp-warp.conf")
        calls = [c.args[0] for c in run_mock.call_args_list]
        self.assertEqual(
            calls[0],
            [
                "C:/awg/amneziawg.exe",
                "/installtunnelservice",
                "C:/conf/pywarp-warp.conf",
            ],
        )
        self.assertEqual(
            calls[1],
            ["sc", "config", "AmneziaWGTunnel$pywarp-warp", "start=", "demand"],
        )

    @patch("backend.tunnel_engine.subprocess.run")
    def test_install_failure_skips_demand_start(self, run_mock):
        run_mock.return_value = MagicMock(returncode=1, stderr="denied", stdout="")
        with self.assertRaises(te.EngineError):
            te.install_tunnel(self.engine, "C:/conf/x.conf")
        self.assertEqual(len(run_mock.call_args_list), 1)
        self.assertEqual(
            run_mock.call_args_list[0].args[0][-2:],
            ["/installtunnelservice", "C:/conf/x.conf"],
        )


if __name__ == "__main__":
    unittest.main()
