"""Security regression checks for the optional authenticated access probe."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import wizard


class AuthProbeTests(unittest.TestCase):
    def test_path_rejects_other_hosts_and_traversal(self):
        for value in ("https://other.test/x", "//other.test/x", "/x/../y", "/x\ny"):
            with self.assertRaises(ValueError): wizard.auth_path(value)
        self.assertEqual(wizard.auth_path("/private/account"), "/private/account")

    def test_secrets_go_only_to_subprocess_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw=Path(tmp)/"targets"/"example.test"/"raw"
            events=[]
            spec={"target":"example.test","role":"user","method":"bearer","port":443,"path":"/private"}
            secret={"method":"bearer","value":"SENSITIVE_TOKEN_123"}
            calls=[]

            def fake_run(argv, **kwargs):
                calls.append((argv,kwargs.get('input')))
                return type('Result', (), {"returncode":0,"stdout":"401" if len(calls)==1 else "200"})()

            with patch.object(wizard.subprocess,"run",side_effect=fake_run):
                wizard.access_probe("example.test","192.0.2.1",spec,secret,raw,events)
            self.assertEqual(len(calls),2)
            self.assertIsNone(calls[0][1])
            self.assertIn('SENSITIVE_TOKEN_123',calls[1][1])
            self.assertNotIn('SENSITIVE_TOKEN_123',json.dumps([calls[1][0],events, json.loads((raw/'auth_192.0.2.1_user.json').read_text())]))
            self.assertEqual(events[0]['status'],'ok')
            self.assertEqual(json.loads((raw/'auth_192.0.2.1_user.json').read_text())['authenticated']['http_status'],200)


if __name__ == '__main__': unittest.main()
