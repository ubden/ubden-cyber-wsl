"""A header observation must not crash technical PDF or prevent linked HTML."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import report_v2


class ReportDeliveryTests(unittest.TestCase):
    def fixture(self,root):
        (root/'engagement.json').write_text(json.dumps({
            'client':'Example','project':'Report QA','tester':'Analyst',
            'targets':['example.test'],'profile':'web','status':'completed_with_errors'}))
        raw=root/'targets'/'example.test'/'raw'
        raw.mkdir(parents=True)
        evidence=raw/'headers_192.0.2.5_https_443.txt'
        evidence.write_text('HTTP/1.1 200 OK\nContent-Type: text/html\n',encoding='utf-8')
        relative=str(evidence.relative_to(root))
        (root/'steps.json').write_text(json.dumps([{
            'step':'headers_192.0.2.5_https_443','status':'ok','output':relative,'seconds':0.2}]))
        return relative

    def test_automatic_findings_generate_both_pdfs_and_linked_html(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            relative=self.fixture(root)
            with patch.object(sys,'argv',['report_v2.py',str(root)]):
                report_v2.main()
            self.assertGreater((root/'TEKNIK_RAPOR.pdf').stat().st_size,1000)
            self.assertGreater((root/'YONETICI_OZETI.pdf').stat().st_size,1000)
            document=(root/'REPORT.html').read_text()
            self.assertIn('href="'+relative+'"',document)
            self.assertIn('id="bulgu-1"',document)
            self.assertIn('href="#bulgu-1"',document)
            self.assertIn('href="TEKNIK_RAPOR.pdf"',document)

    def test_links_reject_traversal_and_script_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'proof.txt').write_text('evidence')
            (root/'link.txt').symlink_to(root/'proof.txt')
            self.assertIn('href="proof.txt"',report_v2.evidence_link(root,'proof.txt'))
            for name in ('../secret.txt','/etc/passwd','link.txt','<img src=x onerror=alert(1)>'):
                self.assertNotIn('href=',report_v2.evidence_link(root,name))
            self.assertIn('&lt;img',report_v2.evidence_link(root,'<img src=x onerror=alert(1)>'))

    def test_html_survives_a_pdf_failure_and_explains_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.fixture(root)
            real_pdf=report_v2.pdf
            def fail_technical(*args,**kwargs):
                if args[1].startswith('.TEKNIK_RAPOR'):
                    raise RuntimeError('simulated PDF failure')
                return real_pdf(*args,**kwargs)
            with patch.object(report_v2,'pdf',side_effect=fail_technical), \
                    patch.object(sys,'argv',['report_v2.py',str(root)]):
                with self.assertRaises(SystemExit):
                    report_v2.main()
            document=(root/'REPORT.html').read_text()
            self.assertIn('PDF üretim hatası',document)
            self.assertNotIn('href="TEKNIK_RAPOR.pdf"',document)
            self.assertIn('href="YONETICI_OZETI.pdf"',document)


if __name__=='__main__': unittest.main()
