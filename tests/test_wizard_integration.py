"""Kali gerektirmeyen entegrasyon testi: scan_target tarama-zamanı probe'ları çağırıyor mu?

wizard.py artık Windows'ta da içe aktarılabilir (pwd koşullu). Burada gerçek
araç/hedef/ağ olmadan, command ve ağır alt fonksiyonlar mock'lanarak scan_target
tek bir IP hedefiyle çalıştırılır ve yeni probe entegrasyonlarının (RootDSE,
network_extras, snmp_extras, web_extras) doğru koşullarda çağrıldığı doğrulanır.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import wizard


def _record_command(name, argv, folder, events, timeout=900, stop_on=()):
    record = {"step": name, "tool": argv[0], "status": "ok", "argv": argv}
    events.append(record)
    return record


class ScanTargetWiringTests(unittest.TestCase):
    def _run(self, profile):
        meta = {"profile": profile, "targets": ["203.0.113.5"], "exclusions": [],
                "max_rate": 250, "top_ports": 100, "selected_interfaces": [],
                "frozen_dns": {}, "exclusion_dns_names": [], "enabled_modules": [],
                "role_scenarios": [], "host_snapshot": {}}
        events = []
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            patches = {
                "command": _record_command,
                "open_tcp_ports": lambda xml: [22, 443, 445, 1433, 389],
                "open_tcp_ports_by_host": lambda xml, hosts: {"203.0.113.5": [8006]},
                "route_guard": lambda assets, sel, raw, ev, target: assets,
                "discover_sql_browser": MagicMock(),
                "probe_snmp": MagicMock(),
                "netbios_probe": MagicMock(),
                "discovery_probes": MagicMock(),
                "vmware_probe": MagicMock(),
                "appliance_probe": MagicMock(),
                "web_identify": MagicMock(),
                "run_supplemental": MagicMock(),
                "discover_rootdse": MagicMock(),
                "network_extras": MagicMock(),
                "snmp_extras": MagicMock(),
                "web_extras": MagicMock(),
                "recover_http_probe": MagicMock(),
                "UI": MagicMock(),
            }
            with patch.multiple(wizard, **patches), \
                 patch("wizard.shutil.which", return_value="/usr/bin/tool"):
                wizard.scan_target("203.0.113.5", meta, root, events)
                return events, patches

    def test_network_full_invokes_probes(self):
        for profile in ("network", "full"):
            events, mocks = self._run(profile)
            self.assertTrue(mocks["discover_rootdse"].called, f"{profile}: rootdse çağrılmadı")
            self.assertTrue(mocks["network_extras"].called, f"{profile}: network_extras çağrılmadı")
            self.assertTrue(mocks["snmp_extras"].called, f"{profile}: snmp_extras çağrılmadı")
            # rootdse doğru argümanlarla (assets + keşfedilen portlar) çağrılmalı.
            args = mocks["discover_rootdse"].call_args.args
            self.assertIn("203.0.113.5", args[0])
            self.assertIn(389, args[1]["203.0.113.5"])
            # Platform portu tarama adımı kaydedildi.
            self.assertTrue(any(e["step"] == "nmap_platform" for e in events))

    def test_web_extras_called_for_web_endpoint(self):
        events, mocks = self._run("full")
        self.assertTrue(mocks["web_extras"].called)

    def test_external_profile_skips_network_probes(self):
        events, mocks = self._run("external")
        self.assertFalse(mocks["discover_rootdse"].called)
        self.assertFalse(mocks["network_extras"].called)


class DomainReconWiringTests(unittest.TestCase):
    def test_domain_target_invokes_domain_recon(self):
        meta = {"profile": "external", "targets": ["ornek.com"], "exclusions": [],
                "max_rate": 250, "top_ports": 100, "selected_interfaces": [],
                "frozen_dns": {"ornek.com": ["203.0.113.9"]}, "exclusion_dns_names": [],
                "enabled_modules": [], "role_scenarios": [], "host_snapshot": {}}
        events = []
        domain_recon = MagicMock()
        with tempfile.TemporaryDirectory() as folder:
            with patch.multiple(wizard, command=_record_command,
                                open_tcp_ports=lambda xml: [80, 443],
                                route_guard=lambda a, s, r, e, t: a,
                                recover_http_probe=MagicMock(),
                                web_extras=MagicMock(),
                                domain_recon=domain_recon,
                                UI=MagicMock()), \
                 patch("wizard.shutil.which", return_value="/usr/bin/tool"), \
                 patch("wizard.resolve", return_value=["203.0.113.9"]):
                wizard.scan_target("ornek.com", meta, Path(folder), events)
                # external profil + alan adı hedefi → domain_recon çağrılır.
                self.assertTrue(domain_recon.called)
                self.assertEqual(domain_recon.call_args.args[0], "ornek.com")


if __name__ == "__main__":
    unittest.main()
