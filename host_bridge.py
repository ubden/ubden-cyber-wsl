"""Narrow Windows bridge used only by an interactive Kali WSL engagement."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess


def available() -> bool:
    return bool(os.environ.get("UBDEN_WINDOWS_BRIDGE") and
                (shutil.which("pwsh.exe") or shutil.which("powershell.exe")))


def invoke(action: str, payload: dict | None = None, timeout: int = 30) -> dict:
    if action not in ("inventory", "route", "domain", "browser", "usb_list", "usb_attach"):
        raise ValueError("Windows koprusu islemi desteklenmiyor")
    bridge = os.environ.get("UBDEN_WINDOWS_BRIDGE")
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if not bridge or not shell:
        return {"status": "skipped", "reason": "Windows koprusu WSL oturumunda yok"}
    if not bridge.lower().endswith("windows-bridge.ps1"):
        return {"status": "error", "reason": "Windows koprusu yolu gecersiz"}
    try:
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", bridge, "-Action", action],
            input=json.dumps(payload or {}, ensure_ascii=False), text=True,
            capture_output=True, errors="replace", timeout=timeout, check=False,
        )
        data = json.loads(result.stdout.strip())
        if not isinstance(data, dict):
            raise ValueError("JSON object bekleniyor")
        if result.returncode and data.get("status") != "error":
            data = {"status": "error", "reason": f"Bridge exit {result.returncode}"}
        return data
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError) as exc:
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}


def screenshot_path(run: Path, target: str) -> str:
    # A Windows UNC path to a Linux-side run directory; the browser helper
    # accepts only the Kali namespace and a PNG destination.
    run = Path(run).resolve()
    if not run.is_absolute() or ".." in run.parts:
        raise ValueError("Gorev dizini gecersiz")
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in target)[:90]
    return "\\\\wsl.localhost\\kali-linux" + str(run / f"browser_{safe}.png").replace("/", "\\")
