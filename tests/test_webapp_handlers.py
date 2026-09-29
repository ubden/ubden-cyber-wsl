"""The local web UI must bind loopback, require the one-time token on every
route, and never serve files outside a job's run directory. No network needed.
"""
import sys
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import webapp


class WebappHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = webapp.QuietThreadingHTTPServer(("127.0.0.1", 0), webapp.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.host = cls.httpd.server_address[0]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _get(self, path):
        url = f"http://127.0.0.1:{self.port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def _post(self, path, data=b""):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_binds_loopback_only(self):
        self.assertEqual(self.host, "127.0.0.1")

    def test_root_requires_token(self):
        self.assertEqual(self._get("/")[0], 403)

    def test_root_with_token_serves_page(self):
        code, body = self._get(f"/?t={webapp.TOKEN}")
        self.assertEqual(code, 200)
        self.assertTrue(body.startswith(b"<!doctype html>"))
        self.assertNotIn(b"__TOKEN__", body)

    def test_api_requires_token(self):
        self.assertEqual(self._get("/api/adapters")[0], 403)
        self.assertEqual(self._get(f"/api/adapters?t={webapp.TOKEN}")[0], 200)

    def test_wrong_token_rejected(self):
        self.assertEqual(self._get("/?t=wrong")[0], 403)

    def test_report_without_job_is_not_found(self):
        code, _ = self._get(f"/r/REPORT.html?t={webapp.TOKEN}&job=none")
        self.assertEqual(code, 404)

    def test_api_runs_requires_token_and_returns_list(self):
        self.assertEqual(self._get("/api/runs")[0], 403)
        import json
        code, body = self._get(f"/api/runs?t={webapp.TOKEN}")
        self.assertEqual(code, 200)
        self.assertIn("runs", json.loads(body))

    def test_attack_with_traversal_run_name_rejected(self):
        import json
        code, body = self._post(f"/api/attack?t={webapp.TOKEN}",
                                 json.dumps({"run": "..\\evil", "user": "u", "password": "p"}).encode())
        self.assertEqual(code, 400)  # no thread spawned; _resolve_run_name blocks traversal


class QuietServerTests(unittest.TestCase):
    def test_benign_client_disconnect_is_swallowed(self):
        # A browser dropping the socket (ConnectionReset/Abort/BrokenPipe) must NOT
        # raise or print a stack trace from the server's error handler.
        srv = object.__new__(webapp.QuietThreadingHTTPServer)  # no socket bind needed
        for exc in (ConnectionResetError(10054, "reset"), ConnectionAbortedError(), BrokenPipeError()):
            try:
                raise exc
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                self.assertIsNone(srv.handle_error(None, ("127.0.0.1", 0)))

    def test_real_error_is_not_swallowed(self):
        # A genuine handler bug still reaches the base handler (which logs it).
        srv = object.__new__(webapp.QuietThreadingHTTPServer)
        seen = []
        with unittest.mock.patch("socketserver.BaseServer.handle_error",
                                 lambda self, req, addr: seen.append(addr)):
            try:
                raise ValueError("real bug")
            except ValueError:
                srv.handle_error(None, ("127.0.0.1", 1))
        self.assertEqual(seen, [("127.0.0.1", 1)])


class RunHelperTests(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile
        self._prev = os.environ.get("LOCALAPPDATA")
        self._tmp = tempfile.mkdtemp()
        os.environ["LOCALAPPDATA"] = self._tmp

    def tearDown(self):
        import os
        if self._prev is not None:
            os.environ["LOCALAPPDATA"] = self._prev

    def test_list_and_resolve_and_block_traversal(self):
        import json
        base = Path(self._tmp) / "UBDEN-Cyber" / "Reports" / "PENTEST_demo"
        base.mkdir(parents=True)
        (base / "engagement.json").write_text(json.dumps(
            {"client": "C", "project": "P", "targets": ["10.0.0.0/24"]}), encoding="utf-8")
        names = [r["name"] for r in webapp._list_runs()]
        self.assertIn("PENTEST_demo", names)
        self.assertIsNotNone(webapp._resolve_run_name("PENTEST_demo"))
        for bad in ("../x", "..\\x", "a/b", "sub\\dir", "nonexistent"):
            self.assertIsNone(webapp._resolve_run_name(bad))


if __name__ == "__main__":
    unittest.main()
