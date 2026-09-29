"""Offline enrichment must preserve evidence status and keep supplied hashes private."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from environment_doctor import inspect
from report_insights import cvss31, write


class ReportInsightsTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Kali IPv4 rota kontrolü yalnız POSIX'te çalışır")
    def test_preflight_blocks_missing_selected_interface_without_target_traffic(self):
        with tempfile.TemporaryDirectory() as folder:
            meta = {'targets': ['192.0.2.5'], 'authorization_reference': 'AUTH-1',
                    'selected_interfaces': [2], 'host_snapshot': {'status': 'ok', 'adapters': [
                        {'index': 35, 'status': 'Up', 'addresses': [{'address': '192.0.2.10'}]}]}}
            with patch('environment_doctor.shutil.which', return_value='/usr/bin/nmap'), \
                 patch('environment_doctor.subprocess.run') as command:
                command.return_value.returncode = 0
                command.return_value.stdout = 'default via 192.0.2.1 dev eth0\n'
                result = inspect(meta, Path(folder))
            self.assertEqual(result['status'], 'blocked')
            self.assertEqual(next(row for row in result['checks'] if row['name'] == 'Windows adaptör seçimi')['status'], 'blocked')
            command.assert_called_once_with(['ip', '-4', 'route', 'show', 'default'],
                                            capture_output=True, text=True, encoding="utf-8",
                                            errors="replace", timeout=3, check=False)

    def test_evidence_based_roadmap_and_private_offline_classification(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            samples = root / 'offline_samples'
            samples.mkdir()
            secret = '$krb5tgs$23$*test$REALM$service*$a1b2c3d4'
            (samples / 'supplied.hash').write_text(secret + '\n' + 'a' * 32 + '\n', encoding='utf-8')
            findings = [
                {'id': 'F-1', 'type': 'kerberoast', 'title': 'Test finding', 'status': 'doğrulandı',
                 'severity': 'high', 'asset': 'dc.example.test', 'recommendation': 'Rotate service secret'},
                {'id': 'F-2', 'type': 'asrep_roast', 'title': 'Candidate', 'status': 'taslak',
                 'severity': 'critical', 'asset': 'other.example.test', 'recommendation': 'Disable feature'},
            ]
            result = write(root, {'id': 'QA'}, [{'step': 'port_discovery', 'status': 'ok'}], findings, {'cases': []})
            self.assertEqual(result['remediation'][0]['findings'], ['F-1'])
            self.assertEqual(len(result['remediation']), 1)
            self.assertEqual(result['draft_count'], 1)
            self.assertEqual(result['cvss_suggestions'][0]['status'], 'analist incelemesi gerekli')
            self.assertIn('T1046', {item['techniqueID'] for item in result['attck']})
            counts = result['hash_samples']['files'][0]['counts']
            self.assertEqual(counts['TGS etype 23 / hashcat 13100'], 1)
            self.assertEqual(counts['32 hex karakter / algoritma doğrulanmadı'], 1)
            self.assertNotIn(secret, (root / 'UBDEN_INSIGHTS.json').read_text(encoding='utf-8'))
            self.assertNotIn('Disable feature', (root / 'REMEDIATION_ROADMAP.md').read_text(encoding='utf-8'))
            layer = json.loads((root / 'ATTACK_LAYER.json').read_text(encoding='utf-8'))
            self.assertEqual(layer['domain'], 'enterprise-attack')

    def test_preflight_requires_profile_tools_and_ad_context(self):
        with tempfile.TemporaryDirectory() as folder:
            meta = {'targets': ['192.0.2.5'], 'authorization_reference': 'AUTH-2',
                    'profile': 'external', 'ad': {'mode': 'supplied', 'domain': 'example.test'},
                    'host_snapshot': {'status': 'unavailable'}}
            with patch('environment_doctor.shutil.which', side_effect=lambda name: None if name in ('sslscan', 'whois') else '/usr/bin/' + name), \
                 patch('environment_doctor.subprocess.run') as command:
                command.return_value.returncode = 0
                command.return_value.stdout = 'default via 192.0.2.1 dev eth0\n'
                result = inspect(meta, Path(folder))
            failed = {row['name'] for row in result['checks'] if row['status'] == 'blocked'}
            self.assertEqual(result['status'], 'blocked')
            self.assertTrue({'Araç: sslscan', 'Araç: whois', 'AD test bağlamı'} <= failed)

    def test_known_cvss_base_vectors(self):
        self.assertEqual(cvss31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8)
        self.assertEqual(cvss31('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 7.8)


if __name__ == '__main__':
    unittest.main()
