"""Build synthetic report PDFs without contacting a network target."""

import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import report_v2  # noqa: E402


def main():
    with TemporaryDirectory(prefix="ubden-report-example-") as directory:
        root = Path(directory)
        metadata = {
            "id": "ornek-v481",
            "client": "Örnek Kurum",
            "project": "Temsili ağ keşfi (canlı tarama değildir)",
            "tester": "Örnek Test Ekibi",
            "authorization_reference": "ÖRNEK",
            "targets": ["192.0.2.0/24"],
            "exclusions": [],
            "profile": "network",
            "max_rate": 250,
            "top_ports": 1000,
            "tool_version": "UBDEN 4.8.1",
            "status": "completed",
            "started_at": "2026-09-24T09:00:00+00:00",
            "finished_at": "2026-09-24T09:30:00+00:00",
        }
        (root / "engagement.json").write_text(
            json.dumps(metadata, ensure_ascii=False), encoding="utf-8"
        )
        (root / "steps.json").write_text(
            json.dumps([{
                "step": "synthetic_fixture", "status": "ok",
                "detail": "Yalnızca rapor görünümü örneği; ağ testi yapılmadı",
                "seconds": 0,
            }], ensure_ascii=False), encoding="utf-8"
        )
        raw = root / "targets" / "192.0.2.0_24" / "raw"
        raw.mkdir(parents=True)
        (raw / "nmap_cidr.xml").write_text(
            "<nmaprun>"
            '<host><address addr="192.0.2.5" addrtype="ipv4"/>'
            '<address addr="00:0C:29:AA:BB:CC" addrtype="mac"/>'
            '<ports><port portid="22" protocol="tcp"><state state="open"/>'
            '<service name="ssh" product="OpenSSH"/></port></ports></host>'
            '<host><address addr="192.0.2.37" addrtype="ipv4"/>'
            '<ports><port portid="80" protocol="tcp"><state state="open"/>'
            '<service name="http"/></port></ports></host>'
            '<host><address addr="192.0.2.60" addrtype="ipv4"/><ports/></host>'
            "</nmaprun>", encoding="utf-8"
        )
        original_argv = sys.argv
        try:
            sys.argv = [str(PROJECT / "report_v2.py"), str(root)]
            report_v2.main()
        finally:
            sys.argv = original_argv
        for name in ("YONETICI_OZETI.pdf", "TEKNIK_RAPOR.pdf"):
            shutil.copy2(root / name, Path(__file__).resolve().parent / f"ORNEK_UBDEN_{name}")


if __name__ == "__main__":
    main()
