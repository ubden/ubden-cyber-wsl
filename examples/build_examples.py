"""Build synthetic report PDFs without contacting a network target."""

import hashlib
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
from PIL import Image, ImageDraw, ImageFont


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import report_v2  # noqa: E402
from analyst_review import initial  # noqa: E402


def main():
    with TemporaryDirectory(prefix="ubden-report-example-") as directory:
        root = Path(directory)
        metadata = {
            "schema": 8,
            "id": "DEMO-2026-001",
            "client": "Örnek Kurum",
            "project": "SENTETİK RAPOR DEMOSU — gerçek test değildir",
            "tester": "Örnek Test Ekibi",
            "authorization_reference": "DEMO-ONLY",
            "targets": ["192.0.2.0/24"],
            "exclusions": ["192.0.2.200/32"],
            "selected_interfaces": [12],
            "host_snapshot": {"status": "example_only", "part_of_domain": False,
                "adapters": [{"name": "Örnek LAN", "index": 12, "status": "Up",
                              "addresses": [{"address": "192.0.2.10", "prefix": 24}],
                              "dns": ["192.0.2.1"], "is_vpn": False}],
                "default_routes": [{"interface_index": 12, "gateway": "192.0.2.1"}]},
            "profile": "network",
            "max_rate": 250,
            "top_ports": 1000,
            "tool_version": "UBDEN 4.8.2",
            "status": "example_only",
            "started_at": "2026-09-24T09:00:00+00:00",
            "finished_at": "2026-09-24T09:30:00+00:00",
        }
        (root / "engagement.json").write_text(
            json.dumps(metadata, ensure_ascii=False), encoding="utf-8"
        )
        raw = root / "targets" / "192.0.2.0_24" / "raw"
        raw.mkdir(parents=True)
        xml = raw / "nmap_cidr.xml"
        xml.write_text(
            "<nmaprun>"
            '<host><address addr="192.0.2.5" addrtype="ipv4"/>'
            '<address addr="00:0C:29:AA:BB:CC" addrtype="mac"/>'
            '<hostnames><hostname name="example-dc.example.test"/></hostnames>'
            '<os><osmatch name="Linux (temsili tahmin)" accuracy="87"/></os>'
            '<ports><port portid="22" protocol="tcp"><state state="open"/>'
            '<service name="ssh" product="OpenSSH"/></port>'
            '<port portid="23" protocol="tcp"><state state="open"/>'
            '<service name="telnet"/></port></ports></host>'
            '<host><address addr="192.0.2.37" addrtype="ipv4"/>'
            '<hostnames><hostname name="example-files.example.test"/></hostnames>'
            '<ports><port portid="445" protocol="tcp"><state state="open"/>'
            '<service name="microsoft-ds"/></port>'
            '<port portid="3389" protocol="tcp"><state state="open"/>'
            '<service name="ms-wbt-server"/></port></ports></host>'
            '<host><address addr="192.0.2.60" addrtype="ipv4"/>'
            '<ports><port portid="80" protocol="tcp"><state state="open"/>'
            '<service name="http"/></port>'
            '<port portid="9100" protocol="tcp"><state state="open"/>'
            '<service name="jetdirect"/></port></ports></host>'
            "</nmaprun>", encoding="utf-8"
        )
        proof = raw / "proof-example.txt"
        proof.write_text("SENTETİK KANIT — canlı sistemden elde edilmedi.\n"
                         "Hedef: 192.0.2.5\nSenaryo: eski yönetim servisi.\n", encoding="utf-8")
        screenshot = raw / "proof-example.png"
        picture = Image.new("RGB", (1060, 300), "#101b32")
        canvas = ImageDraw.Draw(picture)
        font = ImageFont.truetype(str(PROJECT / "assets" / "DejaVuSans.ttf"), 28)
        canvas.text((34, 38), "SENTETİK KANIT / CANLI TEST DEĞİL", font=font, fill="#ffffff")
        canvas.text((34, 143), "192.0.2.5 : TCP/23 - örnek değerlendirme kaydı", font=font, fill="#a8e1df")
        picture.save(screenshot)
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        review = initial()
        review["analyst_summary"] = ("Bu belge yalnız rapor düzenini göstermek için üretilmiş sentetik bir örnektir. "
            "Canlı ağ taraması ve müşteri sistemi üzerinde doğrulama yapılmadı. Gerçek görevlerde bulgular "
            "kanıt, kapsam ve analist incelemesi ile oluşturulur.")
        review["findings"] = [{"id": "DEMO-001", "title": "Yönetim servisinde korumasız protokol kullanımı (örnek)",
            "severity": "high", "status": "doğrulandı", "asset": "192.0.2.5",
            "category": "Güvensiz yönetim protokolü", "access_point": "Yerel ağ / TCP 23",
            "user_profile": "Yönetim hesabı", "root_cause": "Eski yönetim servisinin açık bırakılması",
            "description": "Sentetik laboratuvar senaryosunda yönetim servisinin erişilebilir olduğu ve güvenli alternatifin kullanıma alınmadığı varsayılmıştır.",
            "reproduction": "Örnek kanıt kaydındaki kapsam içi adres ve servis gözlemiyle eşleştirildi. Canlı test adımı içermez.",
            "impact": "Gerçek ortamda kullanılıyorsa yönetim trafiğinin gizliliği etkilenebilir.",
            "recommendation": "Servisi kaldırın; yetkili yönetim segmentinde şifreli bir protokol kullanın ve erişimi sınırlandırın.",
            "remediation_priority": "Önce servis sahibiyle kullanım ihtiyacını doğrulayın; ardından geçiş planı hazırlayın.",
            "retest_status": "Yapılmadı — örnek veri", "reference": "Kurumsal güvenli yapılandırma politikası",
            "reviewed_by": "Örnek Analist", "evidence": str(proof.relative_to(root)),
            "evidence_sha256": digest(proof),
            "evidence_items": [{"path": str(screenshot.relative_to(root)),
                                "caption": "Sentetik ekran örneği", "sha256": digest(screenshot)}]}]
        (root / "review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2), encoding="utf-8")
        (root / "steps.json").write_text(json.dumps([
            {"step": "port_discovery", "tool": "nmap", "status": "ok", "target": "192.0.2.0/24",
             "output": str(xml.relative_to(root)), "sha256": digest(xml), "seconds": 0,
             "detail": "Sentetik XML; canlı tarama yapılmadı"},
            {"step": "ad_assessment", "status": "skipped", "detail": "Örnek görevde etki alanı seçilmedi"},
        ], ensure_ascii=False, indent=2), encoding="utf-8")
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
