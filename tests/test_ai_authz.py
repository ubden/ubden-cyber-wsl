"""Safety and failure behavior for bounded role checks and optional Claude calls."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ai_analyst import ai_input, analyze_run
import wizard


class FakeResponse:
    status=200
    def __init__(self,body): self.body=body
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,n): return self.body[:n]


def claude_response(checks):
    return FakeResponse(json.dumps({'model':'fake-claude','content':[{'type':'text','text':json.dumps({
        'commentary':'İnsan doğrulaması bekleniyor.', 'proposed_checks':checks})}]}).encode())


class AIAndRoleTests(unittest.TestCase):
    def test_query_idor_path_is_scoped_and_excludes_secrets(self):
        self.assertEqual(wizard.scenario_path('/api/invoices?id=test123'),'/api/invoices?id=test123')
        for value in ('//other.test/api', '/a/%2e%2e/b', '/api?id=x#frag',
                      '/api?token=SECRET', '/api?session_id=abc', 'https://other.test/'):
            with self.assertRaises(ValueError): wizard.scenario_path(value)

    def test_credentials_only_stdin_and_get_never_redirect(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            scenario={'id':'AC-01','kind':'idor','target':'example.test','port':443,
                      'path':'/api/test-record/123','owner':'user_a','challenger':'user_b'}
            creds=[({'target':'example.test','port':443,'role':name},
                    {'method':'bearer','value':'SECRET_TOKEN_123456'}) for name in ('user_a','user_b')]
            calls=[]
            def fake_run(argv,**kwargs):
                calls.append((argv,kwargs['input']))
                return type('Result',(),{'returncode':0,'stdout':'200\n1024'})()
            events=[]
            with patch.object(wizard.subprocess,'run',side_effect=fake_run):
                result=wizard.role_probe(root,scenario,'192.0.2.1',creds,events)
            self.assertEqual(result['assessment'],'review')
            self.assertEqual(len(calls),2)
            self.assertTrue(all('--request' in argv and 'GET' in argv for argv,_ in calls))
            self.assertTrue(all('--max-redirs' in argv and '--resolve' in argv for argv,_ in calls))
            self.assertNotIn('SECRET_TOKEN_123456',json.dumps([events,result,calls[0][0]]))
            self.assertIn('SECRET_TOKEN_123456',calls[0][1])

    def test_model_can_only_repeat_two_existing_scenarios_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            meta={'profile':'full','role_scenarios':[{'id':'AC-01','kind':'idor'},
                                                     {'id':'AC-02','kind':'role'}]}
            config={'key':'SECRET_KEY_123','model':'claude-sonnet-4-6','raw':False}
            replay=[];calls=[]
            def fake_api(request):
                calls.append(request)
                return claude_response([{'scenario_id':'AC-01'},{'scenario_id':'AC-02'},
                                        {'scenario_id':'OUTSIDE'}])
            result=analyze_run(root,meta,[],config,lambda case: replay.append(case['id']),fake_api)
            self.assertEqual(replay,['AC-01','AC-02'])
            self.assertEqual(result['calls'],2)
            self.assertNotIn('SECRET_KEY_123',(root/'AI_DURUM.json').read_text())
            self.assertNotIn('SECRET_KEY_123',(root/'AI_ANALIST_YORUMU.md').read_text())

    def test_api_failure_keeps_report_path_available(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def fail(request): raise urllib.error.URLError('network unavailable')
            result=analyze_run(root,{'profile':'full','role_scenarios':[]},[],
                               {'key':'secret','model':'claude-sonnet-4-6','raw':False},request_fn=fail)
            self.assertEqual(result['status'],'failed')
            self.assertTrue((root/'AI_ANALIST_YORUMU.md').exists())
            self.assertNotIn('secret',(root/'AI_DURUM.json').read_text())

    def test_opt_in_raw_evidence_is_capped_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);raw=root/'targets'/'example.test'/'raw';raw.mkdir(parents=True)
            (raw/'headers_a.txt').write_text('Authorization: Bearer SECRET_TOKEN_12345\n'+('a'*3000))
            (raw/'auth_secret.json').write_text('NEVER_INCLUDE')
            aggregate=ai_input(root,{'profile':'full'},[],False)
            self.assertNotIn('raw_evidence',aggregate)
            detailed=ai_input(root,{'profile':'full'},[],True)
            self.assertNotIn('SECRET_TOKEN_12345',json.dumps(detailed))
            self.assertNotIn('NEVER_INCLUDE',json.dumps(detailed))


if __name__=='__main__': unittest.main()
