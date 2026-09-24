"""Manual review cannot silently turn unverified entries into confirmed findings."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyst_review import assess, evidence, initial, verified_finding
from report_v2 import read_data


class ReviewTests(unittest.TestCase):
    def test_evidence_is_inside_run_and_not_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'proof.txt').write_text('test', encoding='utf-8')
            (root / 'link').symlink_to(root / 'proof.txt')
            self.assertEqual(len(evidence(root, 'proof.txt')), 64)
            for name in ('../outside', '/tmp/example', 'link', 'missing'):
                with self.assertRaises(ValueError):
                    evidence(root, name)

    def test_confirmed_finding_requires_complete_matching_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / 'proof.txt'
            proof.write_text('verified observation', encoding='utf-8')
            item = dict(status='doğrulandı', title='Example', asset='example.test',
                        description='Observed', impact='Effect', recommendation='Fix',
                        reproduction='Recorded manual steps', reviewed_by='Analyst',
                        evidence='proof.txt', evidence_sha256=evidence(root, 'proof.txt'))
            self.assertTrue(verified_finding(root, item))
            proof.write_text('changed', encoding='utf-8')
            self.assertFalse(verified_finding(root, item))

    def test_report_downgrades_unsupported_confirmed_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'engagement.json').write_text(json.dumps({'targets': [], 'tester': 'Example'}))
            (root / 'review.json').write_text(json.dumps({'findings': [
                {'status': 'doğrulandı', 'title': 'Unsupported', 'asset': 'example.test'}]}))
            *_, findings, _ = read_data(root)
            self.assertEqual(findings[0]['status'], 'taslak')

    def test_completion_requires_cases_and_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = initial()
            self.assertFalse(assess(root, data)['complete'])
            proof = root / 'proof.txt'
            proof.write_text('manual test evidence', encoding='utf-8')
            for case in data['cases']:
                case.update(state='test edildi', note='Performed in authorized test account',
                            evidence='proof.txt', sha256=evidence(root, 'proof.txt'))
            data.update(analyst_summary='Manual review of scoped application.',
                        reviewer='Reviewer', approved_at='2026-09-23T00:00:00Z')
            self.assertTrue(assess(root, data)['complete'])
            proof.write_text('mutated evidence', encoding='utf-8')
            self.assertFalse(assess(root, data)['complete'])


if __name__ == '__main__':
    unittest.main()
