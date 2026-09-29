"""Invalid wizard answers are corrected in place, including the reported AD path."""
from pathlib import Path
from types import SimpleNamespace
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wizard


class WizardRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.original_umask = os.umask(0o077)
        os.umask(self.original_umask)

    def tearDown(self):
        os.umask(self.original_umask)

    def test_scope_accepts_cidr_ip_and_domain_before_profile(self):
        answers=iter(['192.168.0.0/24,195.87.199.26','sanifoam.com.tr','',''])
        with patch.object(wizard.UI,'prompt',side_effect=lambda *args: next(answers)), \
             patch.object(wizard.UI,'say'), \
             patch.object(wizard,'resolve',return_value=['203.0.113.5']):
            targets,exclusions,frozen,budget=wizard.collect_scope()
        self.assertEqual(targets,['192.168.0.0/24','195.87.199.26','sanifoam.com.tr'])
        self.assertEqual(exclusions,[])
        self.assertEqual(frozen['sanifoam.com.tr'],['203.0.113.5'])
        self.assertEqual(budget[4],256)

    def test_scope_budget_retry_keeps_previous_fields(self):
        over=wizard.MAX_SCOPED_ADDRESSES//254+2   # exceed the scope cap to force the retry
        large=','.join(f'10.{index//256}.{index%256}.0/24' for index in range(over))
        answers=iter([large,'','','','10.0.0.0/24','','',''])
        defaults=[]
        def answer(label,default=''):
            defaults.append(default)
            return next(answers) or default
        with patch.object(wizard.UI,'prompt',side_effect=answer), \
             patch.object(wizard.UI,'say'):
            targets,exclusions,_,budget=wizard.collect_scope()
        self.assertEqual(targets,['10.0.0.0/24'])
        self.assertEqual(exclusions,[])
        self.assertEqual(budget[4],254)
        self.assertEqual(defaults[4].replace(' ',''),large)

    def test_non_domain_windows_does_not_offer_joined_ad_and_retries_fields(self):
        answers = iter(['192.0.2.4', 'corp.example', '192.0.2.0/24',
                        'dc.corp.example', 'CORP\\tester'])
        def select(title, options, default):
            self.assertEqual(title, 'AD / Domain kontrolü')
            self.assertEqual([key for key, _ in options], ['0', '2'])
            return '2'
        with patch.object(wizard.UI, 'menu', side_effect=select), \
             patch.object(wizard.UI, 'prompt', side_effect=lambda *args: next(answers)), \
             patch.object(wizard.UI, 'say'), \
             patch.object(wizard, 'private_value', return_value='test-secret'):
            spec, secret = wizard.collect_ad({'part_of_domain': False})
        self.assertEqual(spec, {'mode': 'supplied', 'domain': 'corp.example',
                                'dc': 'dc.corp.example', 'account': 'CORP\\tester'})
        self.assertEqual(secret['password'], 'test-secret')

    def test_https_explanation_names_target_request_and_cookie_purpose(self):
        menu_answers = iter(['1', '1', '0'])
        fields = iter(['bad role', 'tester', '70000', '443', 'https://other.example/',
                       '/account', 'bad:name', 'test-user'])
        spoken = []
        with patch.object(wizard.UI, 'menu', side_effect=lambda *args: next(menu_answers)), \
             patch.object(wizard.UI, 'prompt', side_effect=lambda *args: next(fields)), \
             patch.object(wizard.UI, 'say', side_effect=lambda value, *args: spoken.append(value)), \
             patch.object(wizard, 'private_value', return_value='test-secret'):
            public, secrets = wizard.collect_credentials(['app.example.test'], [])
        self.assertEqual(public, [{'target': 'app.example.test', 'role': 'tester',
                                   'method': 'basic', 'port': 443, 'path': '/account'}])
        self.assertEqual(secrets[0]['username'], 'test-user')
        self.assertTrue(any('anonim ve bir kimlikli HEAD' in line for line in spoken))
        self.assertTrue(any('geçici Cookie' in line for line in spoken))

    def test_ssh_bad_ip_and_fingerprint_do_not_end_wizard(self):
        fields = iter(['wrong', '192.0.2.5', 'bad user', 'tester', 'bad-fingerprint',
                       'SHA256:' + 'A' * 43, ''])
        with patch.object(wizard.UI, 'prompt', side_effect=lambda *args: next(fields)), \
             patch.object(wizard.UI, 'menu', return_value='1'), \
             patch.object(wizard.UI, 'say'), \
             patch.object(wizard, 'private_value', return_value='test-secret'):
            public, secrets = wizard.collect_ssh_passwords(['192.0.2.5'], [])
        self.assertEqual(len(public), 1)
        self.assertEqual(public[0]['username'], 'tester')
        self.assertEqual(secrets[0]['passwords'], ['test-secret'])

    def test_role_comparison_requires_compatible_accounts(self):
        credentials = [({'target': 'app.example.test', 'port': 443, 'role': 'user'}, {}),
                       ({'target': 'app.example.test', 'port': 8443, 'role': 'admin'}, {})]
        with patch.object(wizard.UI, 'menu') as menu, patch.object(wizard.UI, 'say'):
            self.assertEqual(wizard.collect_role_scenarios(credentials), [])
        menu.assert_not_called()

    def test_wireless_invalid_channel_can_be_corrected_without_restart(self):
        fields = iter(['TestWifi', 'AA:BB:CC:DD:EE:01', '999', '11', 'wlan0mon', '',
                       'AA:BB:CC:DD:EE:02', '192.0.2.30', ''])
        with patch.object(wizard.UI, 'menu', return_value='1'), \
             patch.object(wizard.UI, 'prompt', side_effect=lambda *args: next(fields)), \
             patch.object(wizard.UI, 'say'), \
             patch.object(wizard, 'windows_invoke', return_value={'status': 'ok', 'lines': []}):
            spec = wizard.collect_wireless()
        self.assertTrue(spec['enabled'])
        self.assertEqual(spec['channel'], 11)

    def test_empty_secret_is_reasked_without_exposing_value(self):
        with patch.object(sys.stdin, 'isatty', return_value=True), \
             patch.object(wizard.getpass, 'getpass', side_effect=['', 'test-secret']), \
             patch.object(wizard.UI, 'say') as message:
            self.assertEqual(wizard.private_value('Test parolası'), 'test-secret')
        self.assertNotIn('test-secret', str(message.call_args_list))

    def test_preflight_retry_and_failed_target_keep_later_modules_running(self):
        with tempfile.TemporaryDirectory() as folder:
            meta = {'id': 'qa-run-1', 'client': 'Synthetic', 'targets': ['192.0.2.5', '192.0.2.6'],
                    'exclusions': [], 'host_snapshot': {}, 'nuclei_templates': '',
                    'selected_interfaces': [], 'ad': {'mode': 'disabled'},
                    'browser_enabled': False, 'wireless': {'enabled': False},
                    'enabled_modules': [], 'allowed_techniques': [], 'auth_probes': [],
                    'role_scenarios': [], 'password_probes': []}
            outcomes = [{'status': status, 'note': 'Local checks',
                         'checks': [{'name': 'Tool', 'status': status, 'detail': 'Local'}]}
                        for status in ('blocked', 'ok')]
            with patch.object(wizard, 'collect_meta', return_value=(meta, [], None, None, [])) as collected, \
                 patch.object(wizard, 'freeze_scope', side_effect=[ValueError('synthetic'),None]), \
                 patch.object(wizard, 'collect_scope', return_value=(meta['targets'],[],{}, {4:2,6:0})), \
                 patch.object(wizard, 'choose_run_base', return_value=(Path(folder), None)), \
                 patch.object(wizard, 'register_run'), \
                 patch.object(wizard, 'tool_inventory', return_value={}), \
                 patch.object(wizard, 'catalog_inventory', return_value={}), \
                 patch.object(wizard, 'build_inventory', return_value={
                     'host_count': 0, 'mac_count': 0, 'unknown_count': 0}), \
                 patch.object(wizard, 'inspect_environment', side_effect=outcomes), \
                 patch.object(wizard, 'scan_target', side_effect=[RuntimeError('synthetic'), None]) as scan, \
                 patch.object(wizard, 'record_exploit_gate'), \
                 patch.object(wizard, 'run_ad_module', side_effect=RuntimeError('synthetic')), \
                 patch.object(wizard, 'run_browser_module') as browser, \
                 patch.object(wizard, 'handoff_run'), \
                 patch.object(wizard.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                 patch.object(wizard.UI, 'menu', return_value='1'), \
                 patch.object(wizard.UI, 'prompt', return_value='YETKILIYIM'), \
                 patch.object(wizard.UI, 'say'), \
                 patch.object(wizard.UI, 'target_done'), \
                 patch.object(wizard.UI, 'done'):
                wizard.run(SimpleNamespace(runs=None))
            collected.assert_called_once()
            root = next(Path(folder).iterdir())
            steps = wizard.json.loads((root / 'steps.json').read_text(encoding='utf-8'))
            self.assertEqual(scan.call_count, 2)
            browser.assert_called_once()
            self.assertEqual(sum(s['step'] == 'environment_preflight' for s in steps), 2)
            self.assertEqual(next(s for s in steps if s['step'] == 'environment_preflight')['status'], 'recovered')
            self.assertTrue(any(s['step'] == 'target_error' for s in steps))
            self.assertTrue(any(s['step'] == 'ad_assessment' and s['status'] == 'error' for s in steps))
            self.assertEqual(meta['status'], 'completed_with_errors')

    def test_blocked_preflight_can_stop_with_report_without_scanning(self):
        with tempfile.TemporaryDirectory() as folder:
            meta = {'id': 'qa-run-2', 'client': 'Synthetic', 'targets': ['192.0.2.5'],
                    'exclusions': [], 'host_snapshot': {}, 'nuclei_templates': '',
                    'selected_interfaces': [], 'ad': {'mode': 'disabled'},
                    'browser_enabled': False, 'wireless': {'enabled': False}}
            blocked = {'status': 'blocked', 'note': 'Local checks',
                       'checks': [{'name': 'Tool', 'status': 'blocked', 'detail': 'Missing'}]}
            with patch.object(wizard, 'collect_meta', return_value=(meta, [], None, None, [])), \
                 patch.object(wizard, 'freeze_scope'), \
                 patch.object(wizard, 'choose_run_base', return_value=(Path(folder), None)), \
                 patch.object(wizard, 'register_run'), \
                 patch.object(wizard, 'tool_inventory', return_value={}), \
                 patch.object(wizard, 'catalog_inventory', return_value={}), \
                 patch.object(wizard, 'build_inventory', return_value={
                     'host_count': 0, 'mac_count': 0, 'unknown_count': 0}), \
                 patch.object(wizard, 'inspect_environment', return_value=blocked), \
                 patch.object(wizard, 'scan_target') as scan, \
                 patch.object(wizard.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                 patch.object(wizard, 'handoff_run'), \
                 patch.object(wizard.UI, 'menu', return_value='0'), \
                 patch.object(wizard.UI, 'say'), \
                 patch.object(wizard.UI, 'done'):
                wizard.run(SimpleNamespace(runs=None))
            scan.assert_not_called()
            self.assertEqual(meta['status'], 'preflight_blocked')
            root = next(Path(folder).iterdir())
            self.assertTrue((root / 'PREFLIGHT.json').is_file())
            self.assertTrue((root / 'steps.json').is_file())


if __name__ == '__main__':
    unittest.main()
