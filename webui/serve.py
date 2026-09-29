"""Loopback-only server for a portable, offline UBDEN report workspace."""

from __future__ import annotations

import json
import mimetypes
import os
import secrets
import sys
import tempfile
import threading
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from publisher import publish, recover_incomplete
from report_data import (FINDING_STATUSES, TASK_STATUSES, is_report, load_report,
                         load_reviews, safe_report_path, sha256)


WEBUI = Path(__file__).resolve().parent
MAX_BODY = 80_000


def select_native_folder() -> str:
    try:
        import tkinter
        from tkinter import filedialog
        window = tkinter.Tk()
        window.withdraw()
        window.attributes("-topmost", True)
        choice = filedialog.askdirectory(title="Pentest Raporu klasörünü seçin")
        window.destroy()
        return choice
    except Exception:
        return ""


def save_json_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix="review-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address):
        super().__init__(address, Handler)
        parent = WEBUI.parent.resolve()
        self.report_root: Path | None = parent if is_report(parent) else None
        if self.report_root:
            recover_incomplete(self.report_root)
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()


class Handler(BaseHTTPRequestHandler):
    server: AppServer

    def handle_one_request(self) -> None:
        # Browser tab close / reload drops the socket mid-request; BaseHTTPRequestHandler
        # otherwise dumps a ConnectionResetError traceback even though nothing failed.
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            self.close_connection = True

    def log_message(self, format: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")

    def _send(self, status: int, data: bytes, content_type: str, *, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _root(self) -> Path:
        root = self.server.report_root
        if root is None or not is_report(root):
            raise ValueError("Lütfen Pentest Raporu seçin")
        return root

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_BODY:
            raise ValueError("İstek boyutu sınırı aşıldı")
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON nesnesi gerekli")
        return value

    def _authorized(self) -> bool:
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        if origin and origin != f"http://{host}":
            return False
        return secrets.compare_digest(self.headers.get("X-Review-Token", ""), self.server.token)

    def _local_host(self) -> bool:
        return self.headers.get("Host", "") in (f"127.0.0.1:{self.server.server_port}",
                                                f"localhost:{self.server.server_port}")

    def do_GET(self) -> None:
        if not self._local_host():
            self._error(421, "Yalnız yerel erişim kabul edilir")
            return
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/session":
                root = self.server.report_root
                self._json(200, {"has_report": bool(root and is_report(root)),
                                 "report_name": root.name if root and is_report(root) else "",
                                 "report_path": str(root) if root and is_report(root) else ""})
            elif parsed.path == "/api/report":
                with self.server.lock:
                    self._json(200, load_report(self._root()))
            elif parsed.path == "/api/file":
                root = self._root()
                relative = parse_qs(parsed.query).get("path", [""])[0]
                target = safe_report_path(root, relative)
                if target.stat().st_size > 5_000_000:
                    raise ValueError("Önizleme için dosya çok büyük")
                content_type = "application/pdf" if target.suffix.lower() == ".pdf" else "text/plain; charset=utf-8"
                self._send(200, target.read_bytes(), content_type,
                           extra={"Content-Disposition": f'inline; filename="{target.name.encode("ascii", "ignore").decode() or "evidence"}"'})
            else:
                self._static(parsed.path)
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception as exc:
            self._error(500, f"Sunucu hatası: {exc}")

    def _static(self, request_path: str) -> None:
        relative = "index.html" if request_path in ("/", "/index.html") else request_path.lstrip("/")
        if not relative.startswith(("css/", "js/", "assets/")) and relative != "index.html":
            self._error(404, "Dosya bulunamadı")
            return
        path = (WEBUI / relative).resolve()
        try:
            path.relative_to(WEBUI)
        except ValueError:
            self._error(404, "Dosya bulunamadı")
            return
        if not path.is_file():
            self._error(404, "Dosya bulunamadı")
            return
        if relative == "index.html":
            page = path.read_text(encoding="utf-8").replace("__CSRF_TOKEN__", self.server.token)
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8", extra={
                "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'"})
            return
        # Pin the content type ourselves. With X-Content-Type-Options: nosniff, a wrong
        # MIME from a client machine's Windows registry (e.g. .js -> text/plain) would make
        # the browser refuse the script/stylesheet and silently break the whole panel; and
        # a missing charset lets some browsers mis-decode Turkish glyphs in js/css.
        forced = {".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
                  ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml; charset=utf-8",
                  ".json": "application/json; charset=utf-8", ".png": "image/png",
                  ".ico": "image/x-icon", ".webp": "image/webp",
                  ".woff2": "font/woff2", ".woff": "font/woff"}
        kind = forced.get(path.suffix.lower()) or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self._send(200, path.read_bytes(), kind)

    def do_POST(self) -> None:
        if not self._local_host():
            self._error(421, "Yalnız yerel erişim kabul edilir")
            return
        if not self._authorized():
            self._error(403, "Oturum doğrulaması başarısız")
            return
        parsed = urlparse(self.path)
        try:
            payload = self._body()
            if parsed.path == "/api/select-report":
                selected = payload.get("path") or select_native_folder()
                if not selected:
                    self._json(200, {"selected": False})
                    return
                candidate = Path(selected).expanduser().resolve()
                if not is_report(candidate):
                    raise ValueError("Seçilen klasör geçerli bir Pentest Raporu değil")
                with self.server.lock:
                    recover_incomplete(candidate)
                    self.server.report_root = candidate
                self._json(200, {"selected": True, "name": candidate.name})
            elif parsed.path == "/api/review":
                with self.server.lock:
                    self._json(200, self._save_review(self._root(), payload))
            elif parsed.path == "/api/publish":
                with self.server.lock:
                    signature = payload.get("signature", "")
                    if not signature or not isinstance(signature, str):
                        raise ValueError("Rapor imzası gerekli")
                    self._json(200, publish(self._root(), signature))
            else:
                self._error(404, "İşlem bulunamadı")
        except (ValueError, json.JSONDecodeError) as exc:
            self._error(400, str(exc))
        except Exception as exc:
            self._error(500, f"İşlem başarısız: {exc}")

    def _save_review(self, root: Path, payload: dict) -> dict:
        kind = payload.get("kind")
        if kind not in ("findings", "tasks"):
            raise ValueError("Geçersiz inceleme türü")
        item_id = payload.get("id")
        if not isinstance(item_id, str):
            raise ValueError("Kayıt kimliği gerekli")
        model = load_report(root)
        valid_ids = ({item["id"] for item in model["findings"]} if kind == "findings" else
                     {item.get("id") for item in (model["datasets"].get("ANALIST_GOREV_RAPORU") or {}).get("tasks", [])})
        if item_id not in valid_ids:
            raise ValueError("Kayıt raporda bulunamadı")
        status = payload.get("status", "")
        allowed = FINDING_STATUSES if kind == "findings" else TASK_STATUSES
        if status not in allowed:
            raise ValueError("Geçersiz durum")
        reviewer = str(payload.get("reviewer", "")).strip()[:120]
        note = str(payload.get("note", "")).strip()[:5000]
        evidence = payload.get("evidence", [])
        retest = payload.get("retest_evidence", [])
        if not isinstance(evidence, list) or not isinstance(retest, list) or len(evidence) > 30 or len(retest) > 30:
            raise ValueError("Kanıt listesi geçersiz")
        for relative in evidence + retest:
            safe_report_path(root, relative)
        if kind == "findings" and status in ("doğrulandı", "giderildi") and not (reviewer and note and evidence):
            raise ValueError("Doğrulama için analist, inceleme notu ve en az bir kanıt gerekli")
        if kind == "findings" and status == "giderildi" and not retest:
            raise ValueError("Giderildi durumu için yeniden test kanıtı gerekli")
        if kind == "findings" and status == "yanlış pozitif" and not (reviewer and note):
            raise ValueError("Yanlış pozitif kararı için analist ve gerekçe gerekli")
        if kind == "tasks" and status == "tamamlandı" and not (reviewer and note):
            raise ValueError("Tamamlanan görev için analist ve sonuç notu gerekli")
        reviews = load_reviews(root)
        engagement_id = (model["datasets"].get("engagement") or {}).get("id", "")
        if reviews.get("engagement_id") not in ("", engagement_id):
            raise ValueError("İnceleme kaydı farklı rapora ait")
        reviews["engagement_id"] = engagement_id
        old = reviews.setdefault(kind, {}).get(item_id)
        updated_at = datetime.now(timezone.utc).isoformat()
        new = {"status": status, "reviewer": reviewer, "note": note,
               "evidence": list(dict.fromkeys(evidence)),
               "retest_evidence": list(dict.fromkeys(retest)), "updated_at": updated_at}
        reviews[kind][item_id] = new
        reviews.setdefault("history", []).append({"at": updated_at, "kind": kind, "id": item_id,
                                                    "previous": old, "current": new})
        save_json_atomic(root / ".webui" / "review.json", reviews)
        return {"saved": True, "review": new, "history_count": len(reviews["history"])}


def main() -> None:
    server = AppServer(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"UBDEN WebUI: {url}", flush=True)
    if server.report_root:
        print(f"Rapor: {server.report_root}", flush=True)
    else:
        print("Lütfen Pentest Raporu seçin.", flush=True)
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWebUI kapatılıyor.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
