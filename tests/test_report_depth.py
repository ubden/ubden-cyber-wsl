"""Report depth comes from recorded evidence, never inferred tool availability."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyst_review import initial, verified_finding, assess, LEGACY_CASES
from assessment_coverage import build_coverage
import report_v2


class ReportDepthTests(unittest.TestCase):
    def test_coverage_requires_execution_and_matching_manual_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / 'proof.txt'
            proof.write_text('synthetic authorized evidence', encoding='utf-8')
            digest = hashlib.sha256(proof.read_bytes()).hexdigest()
            review = initial()
            review['cases'][0].update(state='test edildi', note='Synthetic manual result',
                                      evidence='proof.txt', sha256=digest)
            steps = [{'step': 'port_discovery', 'status': 'ok', 'output': 'ports.xml'},
                     {'step': 'tls_target', 'status': 'timeout', 'detail': 'service unreachable'},
                     {'step': 'ad_assessment', 'status': 'skipped', 'detail': 'no authorized account'}]
            rows = {row['id']: row for row in build_coverage(root, {}, steps, review)['controls']}
            self.assertEqual(rows['NET-PORT']['status'], 'çalıştı')
            self.assertEqual(rows['WEB-TLS']['status'], 'tamamlanamadı')
            self.assertEqual(rows['AD-READ']['status'], 'atlandı')
            self.assertEqual(rows['WEB-HTTP']['status'], 'kayıt yok')
            self.assertEqual(rows['MAN-AUTH']['status'], 'çalıştı')
            proof.write_text('changed', encoding='utf-8')
            self.assertEqual({row['id']: row for row in build_coverage(root, {}, steps, review)['controls']}
                             ['MAN-AUTH']['status'], 'tamamlanamadı')

    def test_old_review_cases_still_valid_and_extra_evidence_is_integrity_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / 'proof.txt'
            extra = root / 'screen.png'
            proof.write_text('evidence', encoding='utf-8')
            extra.write_bytes(b'example image bytes')
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            item = {'status': 'doğrulandı', 'title': 'Synthetic example', 'asset': '192.0.2.5',
                    'description': 'Observed', 'impact': 'Conditional effect',
                    'recommendation': 'Review control', 'reproduction': 'Recorded manual steps',
                    'reviewed_by': 'Analyst', 'evidence': 'proof.txt',
                    'evidence_sha256': digest(proof),
                    'evidence_items': [{'path': 'screen.png', 'caption': 'Synthetic', 'sha256': digest(extra)}]}
            self.assertTrue(verified_finding(root, item))
            extra.write_bytes(b'changed')
            self.assertFalse(verified_finding(root, item))
            old = {'schema': 2, 'analyst_summary': 'Legacy review', 'reviewer': 'Analyst',
                   'approved_at': '2026-09-24T00:00:00Z',
                   'cases': [{'id': code, 'title': title, 'state': 'uygulanamaz',
                              'note': 'Legacy scope', 'evidence': '', 'sha256': ''}
                             for code, title in LEGACY_CASES], 'findings': []}
            self.assertTrue(assess(root, old)['complete'])

    def test_report_renders_finding_profile_inventory_and_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'engagement.json').write_text(json.dumps({
                'id': 'DEMO-TEST', 'client': 'Synthetic Org', 'project': 'Report QA',
                'tester': 'Analyst', 'targets': ['192.0.2.0/24'], 'exclusions': [],
                'profile': 'network', 'status': 'completed'}), encoding='utf-8')
            raw = root / 'targets' / '192.0.2.0_24' / 'raw'
            raw.mkdir(parents=True)
            xml = raw / 'nmap_scope.xml'
            xml.write_text('<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/>'
                           '<hostnames><hostname name="qa.example.test"/></hostnames>'
                           '<os><osmatch name="Linux" accuracy="90"/></os>'
                           '<ports><port portid="23" protocol="tcp"><state state="open"/>'
                           '<service name="telnet"/></port></ports></host></nmaprun>',
                           encoding='utf-8')
            proof = raw / 'proof.txt'
            proof.write_text('Synthetic review evidence', encoding='utf-8')
            relative = str(proof.relative_to(root))
            review = initial()
            review['analyst_summary'] = 'Synthetic executive summary.'
            review['findings'] = [{'id': 'QA-001', 'title': 'Synthetic verified profile',
                'severity': 'medium', 'status': 'doğrulandı', 'asset': '192.0.2.5',
                'category': 'Configuration', 'access_point': 'Local network / TCP 23',
                'user_profile': 'Operator', 'root_cause': 'Demo configuration',
                'description': 'Detailed evidence-led description',
                'reproduction': 'Synthetic manual steps', 'impact': 'Synthetic impact',
                'recommendation': 'Disable test service', 'remediation_priority': 'Owner first',
                'retest_status': 'Pending', 'reviewed_by': 'Analyst',
                'evidence': relative, 'evidence_sha256': hashlib.sha256(proof.read_bytes()).hexdigest()}]
            (root / 'review.json').write_text(json.dumps(review), encoding='utf-8')
            (root / 'steps.json').write_text(json.dumps([{
                'step': 'port_discovery', 'status': 'ok', 'output': str(xml.relative_to(root))}]), encoding='utf-8')
            with patch.object(sys, 'argv', ['report_v2.py', str(root)]):
                report_v2.main()
            html = (root / 'REPORT.html').read_text(encoding='utf-8')
            inventory = json.loads((root / 'DEVICE_INVENTORY.json').read_text(encoding='utf-8'))
            coverage = json.loads((root / 'ASSESSMENT_COVERAGE.json').read_text(encoding='utf-8'))
            self.assertIn('Kök neden', html)
            self.assertIn('Synthetic verified profile', html)
            self.assertIn('Test kapsamı ve yürütme matrisi', html)
            self.assertIn('qa.example.test', html)
            self.assertEqual(inventory['devices'][0]['os_matches'][0]['name'], 'Linux')
            self.assertEqual(next(row for row in coverage['controls'] if row['id'] == 'NET-PORT')['status'], 'çalıştı')
            analyst = json.loads((root / 'ANALIST_GOREV_RAPORU.json').read_text(encoding='utf-8'))
            self.assertIn('ANALIST_GOREV_RAPORU.md', html)
            self.assertTrue(any(task['case'] == 'PROTOCOL' for task in analyst['tasks']))
            self.assertGreater((root / 'ANALIST_GOREV_RAPORU.pdf').stat().st_size, 5_000)
            self.assertGreater((root / 'TEKNIK_RAPOR.pdf').stat().st_size, 5_000)
            self.assertGreater((root / 'YONETICI_OZETI.pdf').stat().st_size, 5_000)


if __name__ == '__main__':
    unittest.main()
