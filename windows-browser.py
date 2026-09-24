"""A disposable, same-origin Windows browser probe for UBDEN.

JSON is read from stdin.  The caller supplies a pinned IP and a screenshot
destination inside its own assessment directory.  No personal browser profile
is opened or copied.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from urllib.parse import urlsplit


def validate(request: dict) -> tuple[str, str, Path]:
    url = str(request.get("url", ""))
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("HTTP(S) hedefi bekleniyor")
    allowed_path = str(request.get("path", "/"))
    if not allowed_path.startswith("/") or allowed_path.startswith("//") or "\\" in allowed_path or \
            ".." in allowed_path.split("/") or len(allowed_path) > 256:
        raise ValueError("Gecersiz yetkili tarayici yolu")
    if (parsed.path or "/") != allowed_path or parsed.query or parsed.fragment:
        raise ValueError("Tarayici yolu gorev yoluyla ayni olmali")
    host = parsed.hostname.lower().rstrip(".")
    if host != str(request.get("host", "")).lower().rstrip("."):
        raise ValueError("Tarayici hostu gorev hostuyla ayni olmali")
    pinned = str(ipaddress.ip_address(str(request.get("ip", ""))))
    try:
        numeric_host = str(ipaddress.ip_address(host))
    except ValueError:
        numeric_host = None
    if numeric_host and numeric_host != pinned:
        raise ValueError("Sayisal host sabit IP ile ayni olmali")
    output = Path(str(request.get("screenshot", "")))
    if not output.name.endswith(".png") or ".." in output.parts:
        raise ValueError("Gecersiz ekran goruntusu yolu")
    if not str(output).lower().startswith("\\\\wsl.localhost\\kali-linux\\"):
        raise ValueError("Ekran goruntusu yalniz Kali gorev klasorune yazilabilir")
    return host, pinned, output


def probe(request: dict) -> dict:
    host, pinned, output = validate(request)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"status": "missing_tool", "reason": "Windows Playwright kurulu degil"}
    base = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "UBDEN" / "browser"
    base.mkdir(parents=True, exist_ok=True)
    try:
        ipaddress.ip_address(host)
        numeric_host = True
    except ValueError:
        numeric_host = False
    args = ["--no-proxy-server", "--disable-quic"]
    if not numeric_host:
        args.append(f"--host-resolver-rules=MAP {host} {pinned}, EXCLUDE localhost")
    auth = request.get("auth") or {}
    if auth and auth.get("method") not in ("basic", "bearer", "cookie"):
        raise ValueError("Desteklenmeyen tarayici kimlik yontemi")
    with tempfile.TemporaryDirectory(prefix="session-", dir=base) as profile:
        with sync_playwright() as playwright:
            context = None
            last_error = None
            for channel in ("msedge", "chrome"):
                try:
                    settings = dict(
                        user_data_dir=profile, channel=channel, headless=True, args=args,
                        accept_downloads=False, service_workers="block", ignore_https_errors=False,
                        timeout=10000,
                    )
                    if auth.get("method") == "basic":
                        settings["http_credentials"] = {"username": auth["username"], "password": auth["value"]}
                    context = playwright.chromium.launch_persistent_context(**settings)
                    break
                except Exception as exc:
                    last_error = type(exc).__name__
            if context is None:
                return {"status": "error", "reason": f"Browser baslatilamadi: {last_error}"}
            try:
                origin = urlsplit(request["url"])
                def effective_port(parts):
                    return parts.port or (443 if parts.scheme == "https" else 80)
                if auth.get("method") == "bearer":
                    context.set_extra_http_headers({"Authorization": "Bearer " + auth["value"]})
                elif auth.get("method") == "cookie":
                    context.set_extra_http_headers({"Cookie": auth["value"]})
                blocked = []
                budget = {"count": 0, "next_at": time.monotonic()}
                def scope_route(route):
                    candidate = urlsplit(route.request.url)
                    navigation_outside = (route.request.is_navigation_request() and
                                          (candidate.path or "/") != (origin.path or "/"))
                    if candidate.scheme != origin.scheme or candidate.hostname != host or effective_port(candidate) != effective_port(origin) or navigation_outside:
                        blocked.append(route.request.url)
                        route.abort()
                    else:
                        if budget["count"] >= 50:
                            blocked.append("browser request budget")
                            route.abort()
                            return
                        pause = budget["next_at"] - time.monotonic()
                        if pause > 0:
                            time.sleep(pause)
                        budget["count"] += 1
                        budget["next_at"] = time.monotonic() + 0.2
                        route.continue_()
                context.route("**/*", scope_route)
                page = context.new_page()
                try:
                    response = page.goto(request["url"], wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    if blocked:
                        return {"status": "blocked", "reason": "Kapsam disi istek veya yonlendirme engellendi"}
                    raise
                final = urlsplit(page.url)
                if final.hostname != host or final.scheme != origin.scheme or effective_port(final) != effective_port(origin) or (final.path or "/") != (origin.path or "/"):
                    return {"status": "blocked", "reason": "Kapsam disi yonlendirme"}
                output.parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(output), full_page=False, timeout=10000)
                return {"status": "ok", "http_status": response.status if response else None,
                        "title": page.title()[:160], "final_url": page.url,
                        "screenshot": str(output), "requests": budget["count"],
                        "blocked_requests": len(blocked)}
            finally:
                context.close()


def main() -> None:
    try:
        request = json.load(sys.stdin)
        result = probe(request)
    except Exception as exc:
        result = {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
