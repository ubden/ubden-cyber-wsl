"""Default template scope and command generation regression checks."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import wizard


class NucleiBaselineTests(unittest.TestCase):
    def test_default_templates_are_read_only_and_scope_bound(self):
        files=wizard.template_inventory(wizard.BASELINE)
        self.assertEqual(len(files),12)
        self.assertEqual(len({row['sha256'] for row in files}),12)
        try:
            import yaml
        except ImportError:
            self.skipTest('PyYAML missing; Kali installer validates templates with Nuclei')
        for entry in files:
            item=yaml.safe_load((wizard.BASELINE/entry['name']).read_text())
            self.assertEqual(set(item),{'id','info','http'})
            self.assertEqual(len(item['http']),1)
            request=item['http'][0]
            self.assertIn(request['method'],('GET','HEAD'))
            self.assertEqual(len(request['path']),1)
            self.assertTrue(request['path'][0].startswith('{{BaseURL}}/'))
            self.assertNotIn('://',request['path'][0])
            self.assertNotIn('interactsh',str(item).lower())
            self.assertNotIn('redirects',str(item).lower())
            self.assertEqual(request['matchers-condition'],'and')
            if entry['name'].startswith('https/'):
                self.assertEqual(request['method'],'HEAD')

    def test_dns_is_not_used_as_nuclei_destination(self):
        folder=Path('/tmp/ubden-example/raw')
        name,argv=wizard.nuclei_args('example.test','192.0.2.45','https',wizard.BASELINE,'baseline',20,folder)
        self.assertEqual(argv[argv.index('-u')+1],'https://192.0.2.45/')
        self.assertEqual(argv[argv.index('-H')+1],'Host: example.test')
        self.assertEqual(argv[argv.index('-sni')+1],'example.test')
        self.assertEqual(argv[argv.index('-rl')+1],'5')
        self.assertIn('-dr',argv)
        self.assertIn('-duc',argv)
        self.assertIn('-ni',argv)
        self.assertIn('-or',argv)
        self.assertTrue(name.endswith('_https'))
        _,http_args=wizard.nuclei_args('example.test','192.0.2.45','http',wizard.BASELINE,'baseline',20,folder)
        self.assertEqual(http_args[http_args.index('-t')+1],str(wizard.BASELINE/'web'))
        self.assertNotIn('-sni',http_args)


if __name__ == '__main__': unittest.main()
