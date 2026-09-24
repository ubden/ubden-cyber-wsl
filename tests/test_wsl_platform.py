"""Offline checks for the WSL bridge, tool attribution and bounded adapters."""
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import os

ROOT = Path(__file__).resolve().parents[1]

import sys
sys.path.insert(0, str(ROOT))
import host_bridge
import supplemental_scans
import tool_catalog
import wireless_assessment
import credential_assessment
import ad_assessment
import base64
import hashlib
if os.name == "nt":
    sys.modules.setdefault("pwd", types.SimpleNamespace(getpwuid=lambda uid: None))
import wizard

browser_spec = importlib.util.spec_from_file_location("windows_browser", ROOT / "windows-browser.py")
windows_browser = importlib.util.module_from_spec(browser_spec)
browser_spec.loader.exec_module(windows_browser)


class WslPlatformTests(unittest.TestCase):
    def test_catalog_distinguishes_installed_from_started_and_failed(self):
        with patch.object(tool_catalog.shutil, "which", return_value="/usr/bin/tool"), \
                patch.object(tool_catalog, "version", return_value="1.0"):
            data = tool_catalog.inventory([
                {"tool": "fping", "step": "fping_001", "status": "ok"},
                {"tool": "nmap", "step": "nmap_001", "status": "timeout"},
                {"tool": "hping3", "step": "hping3_001", "status": "missing_tool"},
            ])
        rows = {item["name"]: item for item in data["tools"]}
        self.assertEqual(data["catalog_count"], 83)
        self.assertEqual(len(data["tools"]), 88)
        self.assertEqual(rows["fping"]["successful_steps"], ["fping_001"])
        self.assertEqual(rows["nmap"]["steps"], ["nmap_001"])
        self.assertEqual(rows["nmap"]["successful_steps"], [])
        self.assertFalse(rows["hping3"]["executed"])
        self.assertFalse(rows["curl"]["executed"])

    def test_numeric_supplemental_probes_use_discovered_ports_only(self):
        calls = []
        def fake(name, argv, raw, events, timeout):
            calls.append((name, argv, timeout))
            row = {"step": name, "status": "ok"}
            events.append(row)
            return row
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "targets" / "one" / "raw"
            events = []
            supplemental_scans.run("192.0.2.0/24", ["192.0.2.5", "192.0.2.6"],
                                   {"192.0.2.5": [443, 445]}, raw, events, fake, "network")
        self.assertEqual([item[0] for item in calls],
                         ["fping_001", "nbtscan_001", "hping3_001", "fping_002"])
        self.assertEqual(calls[2][1], ["hping3", "-S", "-c", "1", "-p", "443", "192.0.2.5"])
        self.assertEqual([row["target"] for row in events],
                         ["192.0.2.5"] * 3 + ["192.0.2.6"])

    def test_cidr_web_only_probes_discovered_services_with_16_host_cap(self):
        calls = []
        def fake(name, argv, raw, events, timeout):
            calls.append(argv)
            row = {"step": name, "status": "ok"}
            events.append(row)
            return row
        addresses = [f"192.0.2.{n}" for n in range(1, 19)]
        ports = {ip: [80] for ip in addresses[:17]}
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "targets" / "one" / "raw"
            raw.mkdir(parents=True)
            events = []
            with patch.object(wizard, "command", side_effect=fake), \
                 patch.object(wizard.shutil, "which", return_value=None):
                wizard.scan_cidr_web("192.0.2.0/24", addresses, ports, raw,
                                     events, {"max_rate": 250})
        self.assertEqual(len(calls), 32)
        self.assertTrue(all(argv[0] == "curl" for argv in calls))
        self.assertFalse(any("192.0.2.17" in str(argv) or "192.0.2.18" in str(argv)
                             for argv in calls))
        self.assertEqual(next(row for row in events if row["step"] == "cidr_web_budget")["status"],
                         "skipped")

    def test_custom_nuclei_template_cannot_leave_scope_or_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outside.yaml"
            path.write_text("id: outside\ninfo: {name: outside}\nhttp:\n  - method: GET\n"
                            "    path: ['https://other.example/']\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                wizard.template_inventory(tmp)
            path.write_text("id: write\ninfo: {name: write}\nhttp:\n  - method: POST\n"
                            "    path: ['{{BaseURL}}/update']\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                wizard.template_inventory(tmp)

    def test_wireless_caps_and_monitor_precondition(self):
        spec = {"ssid": "lab", "bssid": "00:11:22:33:44:55",
                "test_station": "66:77:88:99:AA:BB", "test_station_ip": "192.0.2.9",
                "channel": 6, "interface": "wlan0mon", "busid": "1-2"}
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "targets" / "wifi" / "raw"
            events = []
            with patch.object(wireless_assessment, "monitor_ready", return_value=False):
                wireless_assessment.run(spec, raw, events, lambda *args: None)
            self.assertEqual(events[0]["status"], "skipped")
            calls = []
            def fake(name, argv, folder, event_list, timeout, **kwargs):
                calls.append((name, argv, timeout, kwargs))
                if name == "wireless_capture":
                    (folder / "authorized_ap-01.cap").write_bytes(b"pcap")
                row = {"step": name, "status": "ok"}
                event_list.append(row)
                return row
            events = []
            with patch.object(wireless_assessment, "monitor_ready", return_value=True), \
                 patch.object(wireless_assessment.shutil, "which", return_value="/usr/bin/tool"), \
                 patch.object(wireless_assessment.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)):
                wireless_assessment.run(spec, raw, events, fake)
        self.assertEqual(calls[0][2], 600)
        self.assertEqual(len([c for c in calls if c[0].startswith("wireless_deauth_")]), 3)
        wps = next(c for c in calls if c[0] == "wireless_wps")
        self.assertEqual(wps[1][wps[1].index("-g") + 1], "10")
        self.assertEqual(wps[2], 180)
        self.assertIn("locked", wps[3]["stop_on"])

    def test_browser_rejects_scope_drift_and_accepts_pinned_test_path(self):
        base = {"url": "https://example.test/account", "host": "example.test",
                "ip": "192.0.2.5", "path": "/account",
                "screenshot": r"\\wsl.localhost\kali-linux\opt\ubden-cyber\runs\x.png"}
        self.assertEqual(windows_browser.validate(base)[1], "192.0.2.5")
        with self.assertRaises(ValueError):
            windows_browser.validate({**base, "url": "https://other.test/account"})
        with self.assertRaises(ValueError):
            windows_browser.validate({**base, "path": "/other"})
        with self.assertRaises(ValueError):
            windows_browser.validate({**base, "url": "https://192.0.2.7/account",
                                      "host": "192.0.2.7"})

    def test_browser_uses_only_route_approved_dns_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "targets" / "example.test" / "raw"
            raw.mkdir(parents=True)
            (raw / "dns_resolution.json").write_text(
                '{"addresses":["192.0.2.5","192.0.2.6"]}', encoding="utf-8")
            (raw / "route_snapshot.json").write_text(
                '{"allowed":["192.0.2.6"]}', encoding="utf-8")
            calls = []
            def browser(action, request, timeout):
                calls.append(request)
                return {"status": "ok", "http_status": 200}
            meta = {"browser_enabled": True, "targets": ["example.test"],
                    "exclusions": [], "selected_interfaces": [29]}
            with patch.object(wizard, "resolve", return_value=["192.0.2.5", "192.0.2.6"]), \
                 patch.object(wizard, "windows_invoke", side_effect=browser), \
                 patch.object(wizard, "open_tcp_ports", return_value=[443]):
                wizard.run_browser_module(root, meta, [], [])
        self.assertEqual([row["ip"] for row in calls], ["192.0.2.6"])

    def test_bridge_has_closed_action_set(self):
        with self.assertRaises(ValueError):
            host_bridge.invoke("execute", {"command": "anything"})

    def test_route_guard_blocks_unselected_adapter_before_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "targets" / "network" / "raw"
            raw.mkdir(parents=True)
            result = {"status": "ok", "routes": [
                {"ip": "192.0.2.5", "status": "ok", "interface_index": 29},
                {"ip": "192.0.2.6", "status": "ok", "interface_index": 10},
            ]}
            events = []
            with patch.object(wizard, "windows_invoke", return_value=result):
                allowed = wizard.route_guard(["192.0.2.5", "192.0.2.6"], [29],
                                             raw, events, "192.0.2.0/24")
            self.assertEqual(allowed, ["192.0.2.5"])
            self.assertEqual(events[0]["status"], "blocked")
            self.assertTrue((raw / "route_snapshot.json").is_file())

    def test_frozen_exclusion_expands_to_ip(self):
        meta = {"targets": ["example.test"], "exclusions": ["excluded.test"]}
        def fake(host):
            return {"example.test": ["192.0.2.5"],
                    "excluded.test": ["192.0.2.5"]}[host]
        with patch.object(wizard, "resolve", side_effect=fake):
            wizard.freeze_scope(meta)
        self.assertIn("192.0.2.5", meta["exclusions"])
        self.assertEqual(meta["frozen_dns"]["example.test"], ["192.0.2.5"])

    def test_total_address_budget_rejects_multiple_full_cidrs(self):
        self.assertEqual(wizard.validate_task_address_budget(
            ["192.0.2.0/24", "192.0.2.5"])[4], 256)
        with self.assertRaises(ValueError):
            wizard.validate_task_address_budget(["192.0.2.0/24", "198.51.100.0/24"])
        with self.assertRaises(ValueError):
            wizard.validate_task_address_budget(["2001:db8::/120", "2001:db8::100"])
        with self.assertRaises(ValueError):
            wizard.validate_task_address_budget(
                ["192.0.2.0/24", "extra.example"],
                {"extra.example": ["198.51.100.1"]})

    def test_ssh_password_budget_and_no_secret_in_events(self):
        attempts = []
        class AuthenticationException(Exception):
            pass
        class Key:
            def asbytes(self): return b"pinned-test-key"
        class Socket:
            def __enter__(self): return self
            def __exit__(self, *args): return None
        class Transport:
            def __init__(self, connection): pass
            def start_client(self, timeout): pass
            def get_remote_server_key(self): return Key()
            def auth_password(self, username, password, fallback):
                attempts.append(password)
                raise AuthenticationException("authentication failed")
            def is_authenticated(self): return False
            def close(self): pass
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(b"pinned-test-key").digest()).decode().rstrip("=")
        fake_paramiko = types.SimpleNamespace(Transport=Transport,
                                              AuthenticationException=AuthenticationException)
        events = []
        with patch.dict(sys.modules, {"paramiko": fake_paramiko}), \
             patch.object(credential_assessment.socket, "create_connection", return_value=Socket()):
            credential_assessment.run_ssh(
                {"target_ip": "192.0.2.5", "username": "testuser",
                 "host_key_sha256": fingerprint}, ["wrong-one", "wrong-two"], events)
        self.assertEqual(attempts, ["wrong-one", "wrong-two"])
        self.assertEqual(len(events), 2)
        self.assertNotIn("wrong-one", str(events))
        self.assertNotIn("wrong-two", str(events))
        self.assertTrue(all(item["status"] == "auth_failed" for item in events))
        with self.assertRaises(ValueError):
            credential_assessment.run_ssh(
                {"target_ip": "192.0.2.5", "username": "testuser",
                 "host_key_sha256": fingerprint}, ["a", "b", "c"], [])

    def test_ssh_lock_message_stops_remaining_candidate(self):
        attempts = []
        class AuthenticationException(Exception): pass
        class Socket:
            def __enter__(self): return self
            def __exit__(self, *args): return None
        class Key:
            def asbytes(self): return b"key"
        class Transport:
            def __init__(self, connection): pass
            def start_client(self, timeout): pass
            def get_remote_server_key(self): return Key()
            def auth_password(self, username, password, fallback):
                attempts.append(password)
                raise AuthenticationException("account locked")
            def close(self): pass
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(b"key").digest()).decode().rstrip("=")
        events = []
        with patch.dict(sys.modules, {"paramiko": types.SimpleNamespace(
                Transport=Transport, AuthenticationException=AuthenticationException)}), \
             patch.object(credential_assessment.socket, "create_connection", return_value=Socket()):
            credential_assessment.run_ssh({"target_ip": "192.0.2.5", "username": "testuser",
                                           "host_key_sha256": fingerprint}, ["one", "two"], events)
        self.assertEqual(attempts, ["one"])
        self.assertEqual(events[0]["status"], "blocked")

    def test_ldaps_uses_pinned_ip_and_does_not_follow_referrals(self):
        calls = {}
        def tls(**kwargs):
            calls["tls"] = kwargs
            return kwargs
        def server(host, **kwargs):
            calls["server"] = (host, kwargs)
            return "server"
        class Connection:
            entries = []
            def __init__(self, target, **kwargs):
                calls["connection"] = kwargs
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def search(self, *args, **kwargs): return True
        fake_ldap3 = types.SimpleNamespace(BASE=0, NONE=0, Connection=Connection,
                                           Server=server, Tls=tls)
        with patch.dict(sys.modules, {"ldap3": fake_ldap3}):
            result = ad_assessment.inspect("dc.example.test", "example.test",
                                           "test@example.test", "secret", "192.0.2.5")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(calls["server"][0], "192.0.2.5")
        self.assertEqual(calls["tls"]["valid_names"], ["dc.example.test"])
        self.assertEqual(calls["tls"]["sni"], "dc.example.test")
        self.assertFalse(calls["connection"]["auto_referrals"])
        self.assertTrue(calls["connection"]["read_only"])


if __name__ == "__main__":
    unittest.main()
