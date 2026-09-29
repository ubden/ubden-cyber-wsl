"""Build reviewed report outputs and replace them only after successful staging."""

from __future__ import annotations

import base64
import copy
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from report_data import PDF_NAMES, load_report, report_signature, sha256


OUTPUTS = (
    "REPORT.html", "YONETICI_OZETI.pdf", "TEKNIK_RAPOR.pdf", "ANALIST_GOREV_RAPORU.pdf",
    "ANALIST_GOREV_RAPORU.json", "ANALIST_GOREV_RAPORU.md", "REMEDIATION_ROADMAP.md",
    "WEBUI_PUBLISHED_REVIEW.json", "SHA256SUMS.txt",
)
JOURNAL = "publish-journal.json"


def e(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def badge(label: str, kind: str = "") -> str:
    return f'<span class="badge {e(kind)}">{e(label)}</span>'


def table(headers: list[str], rows: list[list]) -> str:
    head = "".join(f"<th>{e(v)}</th>" for v in headers)
    body = "".join("<tr>" + "".join(f"<td>{v}</td>" for v in row) + "</tr>" for row in rows)
    return f"<div class=table-wrap><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def evidence_links(paths: list[str]) -> str:
    links = []
    for entry in paths:
        for path in str(entry).split(";"):
            path = path.strip()
            if not path or path.startswith(("http:", "https:")):
                continue
            normalized = path.replace("\\", "/")
            if (normalized.startswith("/") or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", normalized)
                    or ".." in Path(normalized).parts):
                continue
            href = "/".join(quote(part) for part in normalized.split("/"))
            links.append(f'<a href="{href}">{e(normalized)}</a>')
    return ", ".join(links) if links else "—"


def _reviewed(item: dict, reviews: dict, kind: str) -> dict:
    return reviews.get(kind, {}).get(item.get("id", ""), {})


def _css() -> str:
    return """
    @page{size:A4;margin:16mm 14mm}*{box-sizing:border-box}body{margin:0;color:#16243b;background:#edf3f8;font:14px/1.55 Arial,sans-serif}
    main{max-width:1180px;margin:26px auto;background:#fff;box-shadow:0 12px 40px #07152b18;padding:35px}
    header{background:#0a1930;color:#fff;padding:28px 34px;margin:-35px -35px 30px;border-bottom:5px solid #18c5c7}
    header img{width:175px;max-height:68px;object-fit:contain;vertical-align:middle;margin-right:20px}
    header strong{font-size:24px;letter-spacing:.02em}header small{display:block;color:#b6d1df;margin-top:6px}
    h1{font-size:28px;margin:0 0 8px}h2{font-size:19px;margin:28px 0 12px;padding:0 0 7px;border-bottom:2px solid #1cc4c6;color:#0b2443}
    h3{font-size:15px;color:#0c2d4b}p{margin:7px 0 12px}.muted{color:#52677d}.notice{background:#e9f7f6;border-left:4px solid #0aa6a8;padding:11px 14px;margin:12px 0}
    .warn{background:#fff6e4;border-left-color:#dc9d37}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.metric{border:1px solid #dae6ee;border-radius:9px;padding:14px}
    .metric b{display:block;font-size:24px;color:#087e88}.metric span{font-size:12px;color:#4d6075}.badge{display:inline-block;border-radius:99px;padding:2px 9px;background:#e5f2f3;color:#0b646c;font-size:11px;font-weight:bold}
    .badge.high{background:#ffedf0;color:#a72540}.badge.medium{background:#fff1dc;color:#94610a}.badge.verified{background:#e3f7eb;color:#126439}
    .finding,.card{border:1px solid #dce6ee;border-left:4px solid #19b9c1;border-radius:6px;padding:12px 15px;margin:12px 0;break-inside:avoid}
    .finding p{margin:5px 0}.finding h3,.card h3{margin:0 0 9px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:11px}th,td{border-bottom:1px solid #dfe7ed;text-align:left;vertical-align:top;padding:7px;overflow-wrap:anywhere}th{background:#e8f4f5;color:#0a3045}
    a{color:#087b83;text-decoration:underline;overflow-wrap:anywhere}ul,ol{padding-left:21px}li{margin:3px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:10px/1.35 Consolas,monospace;background:#f1f5f8;padding:10px}
    footer{margin-top:36px;border-top:1px solid #dae6ec;padding-top:8px;color:#607286;font-size:11px}
    @media print{body{background:white}main{margin:0;max-width:none;box-shadow:none;padding:0}header{margin:0 0 20px;padding:18px;print-color-adjust:exact}.metric,.finding,.card,.badge,th,.notice{print-color-adjust:exact}a{color:#087b83}}
    @media(max-width:700px){main{padding:18px;margin:0}.grid{grid-template-columns:repeat(2,1fr)}header{margin:-18px -18px 20px}}
    """


def _header(model: dict, title: str, root: Path) -> str:
    engagement = model["datasets"].get("engagement") or {}
    logo = Path(__file__).resolve().parent / "assets" / "ubden-logo.png"
    img = (f'<img alt="Ubden" src="data:image/png;base64,{base64.b64encode(logo.read_bytes()).decode()}">' if logo.is_file() else "")
    return (f"<header>{img}<strong>UBDEN® Cyber Security Systems</strong>"
            f"<small>{e(title)} · {e(engagement.get('client', ''))} · {e(engagement.get('project', ''))}"
            f" · {e(engagement.get('id', ''))}</small></header>")


def _summary(model: dict) -> str:
    d = model["datasets"]
    overview = model["overview"]
    engagement = d.get("engagement") or {}
    metrics = [("Cihaz", overview["hosts"]), ("Taslak / inceleme adayı", overview["findings"]),
               ("Doğrulanmış", overview["confirmed"]), ("Bekleyen görev", overview["tasks"])]
    cards = "".join(f'<div class=metric><b>{e(value)}</b><span>{e(label)}</span></div>' for label, value in metrics)
    warnings = "".join(f'<div class="notice warn">{e(w)}</div>' for w in model["warnings"])
    return ("<section><h1>Güvenlik değerlendirmesi</h1>"
            '<div class="notice">Otomatik gözlemler analist onayı olmadan kesinleşmiş güvenlik açığı değildir. '
            'CVE ve saldırı zincirleri doğrulama adayıdır.</div>'
            f'<div class=grid>{cards}</div><h2>Görev ve kapsam</h2>'
            f'<p><b>Müşteri:</b> {e(engagement.get("client"))} · <b>Proje:</b> {e(engagement.get("project"))}'
            f' · <b>Profil:</b> {e(engagement.get("profile"))} · <b>Durum:</b> {e(engagement.get("status"))}</p>'
            f'<p><b>Hedefler:</b> {e(", ".join(engagement.get("targets", [])))}</p>'
            f'<p><b>Başlangıç:</b> {e(engagement.get("started_at"))} · <b>Bitiş:</b> {e(engagement.get("finished_at"))}</p>'
            f'<p><b>Test sorumlusu:</b> {e(engagement.get("tester"))} · '
            f'<b>Yetki referansı:</b> {e(engagement.get("authorization_reference"))}</p>'
            f'<h2>Veri kalitesi</h2>{warnings or "<p>Ek uyarı yok.</p>"}</section>')


def _findings(model: dict, *, executive: bool = False) -> str:
    reviews = model["reviews"]
    items = model["findings"]
    if executive:
        items = [x for x in items if _reviewed(x, reviews, "findings").get("status") == "doğrulandı"]
    body = [f"<section><h2>{'Doğrulanmış bulgular' if executive else 'Gözlemler ve analist incelemeleri'}</h2>"]
    if not items:
        body.append("<p>Analistçe doğrulanmış bulgu bulunmuyor.</p>")
    for item in items:
        review = _reviewed(item, reviews, "findings")
        status = review.get("status", item.get("status", "taslak"))
        klass = "verified" if status == "doğrulandı" else "high" if item.get("severity") == "Yüksek" else "medium"
        body.append(f'<section class="finding" id="{e(item["id"])}"><h3>{e(item["id"])} · {e(item["title"])}</h3>'
                    f'<p><b>Şiddet:</b> {e(item["severity"])} · <b>Doğrulama:</b> {e(status)}</p>{badge(status, klass)}'
                    f'<p><b>Kaynak:</b> {e(item["source"])} · <b>Varlık:</b> {e(item["asset"])}'
                    f' · <b>CWE sınıfı:</b> {e(item["cwe"])}</p>'
                    f'<p><b>Açıklama:</b> {e(item["description"])}</p>'
                    f'<p><b>İş etkisi:</b> {e(item["impact"])}</p>'
                    f'<p><b>Düzeltme önerisi:</b> {e(item["remediation"])}</p>'
                    f'<p><b>Kanıt:</b> {evidence_links(item["evidence"])}</p>')
        if review:
            body.append(f'<p><b>Analist:</b> {e(review.get("reviewer"))} · '
                        f'<b>İnceleme:</b> {e(review.get("updated_at"))}</p>'
                        f'<p><b>İnceleme notu:</b> {e(review.get("note"))}</p>'
            f'<p class="review-evidence"><b>Seçilen kanıt:</b> {evidence_links(review.get("evidence", []))}</p>')
            if review.get("retest_evidence"):
                body.append(f'<p class="retest-evidence"><b>Yeniden test:</b> {evidence_links(review["retest_evidence"])}</p>')
        body.append("</section>")
    return "".join(body) + "</section>"


def _coverage(model: dict) -> str:
    d = model["datasets"].get("ASSESSMENT_COVERAGE") or {}
    rows = [[e(c.get("group")), e(c.get("id")), e(c.get("title")), e(c.get("status")),
             e(f'{c.get("executed", 0)}/{c.get("attempted", 0)}'),
             evidence_links(c.get("evidence", []))] for c in d.get("controls", [])]
    return ("<section><h2>Test kapsamı ve yürütme</h2>"
            f'<p class=muted>{e(d.get("meaning", ""))}</p>'
            + table(["Grup", "Kontrol", "Başlık", "Durum", "Adım", "Kanıt"], rows) + "</section>")


def _assets(model: dict) -> str:
    inventory = model["datasets"].get("DEVICE_INVENTORY") or {}
    body = ["<section><h2>Cihaz ve servis envanteri</h2>",
            f'<p class=muted>{e(inventory.get("limits", ""))}</p>']
    for device in inventory.get("devices", []):
        ports = device.get("ports", [])
        rows = [[e(p.get("port")), e(p.get("protocol")), e(p.get("service")),
                 e(p.get("product")), e(p.get("version"))] for p in ports]
        body.append(f'<div class=card><h3>{e(device.get("ip"))} · {e(device.get("category"))}</h3>'
                    f'<p><b>Ad:</b> {e(device.get("display_name"))} · <b>MAC:</b> {e(device.get("mac"))}'
                    f' · <b>Üretici:</b> {e(device.get("vendor"))} · '
                    f'<b>Sınıflandırma güveni:</b> {e(device.get("confidence_pct"))}%</p>'
                    f'<p><b>Rol adayları:</b> {e(", ".join(r.get("role", "") for r in device.get("role_candidates", [])))}</p>'
                    f'<p><b>Kaynak kanıt:</b> {evidence_links([x.strip() for x in str(device.get("evidence", "")).split(";") if x.strip()])}</p>'
                    + table(["Port", "Protokol", "Servis", "Ürün", "Sürüm"], rows) + "</div>")
    return "".join(body) + "</section>"


def _tasks(model: dict) -> str:
    tasks = (model["datasets"].get("ANALIST_GOREV_RAPORU") or {}).get("tasks", [])
    reviews = model["reviews"]
    body = ["<section><h2>Analist görevleri</h2>"]
    for task in tasks:
        review = _reviewed(task, reviews, "tasks")
        status = review.get("status", task.get("status", "bekliyor"))
        body.append(f'<div class=card id="{e(task.get("id"))}"><h3>{e(task.get("id"))} · {e(task.get("title"))}</h3>'
                    f'<p>{badge(task.get("priority", ""))} {badge(status)} · '
                    f'<b>Varlıklar:</b> {e(", ".join(task.get("targets", [])))}</p>'
                    f'<p><b>Gerekçe:</b> {e(task.get("trigger"))}</p>'
                    f'<p><b>Müşteriden gereken:</b> {e(task.get("customer_input"))}</p>'
                    '<b>Adımlar</b><ol>' + "".join(f"<li>{e(v)}</li>" for v in task.get("steps", [])) + "</ol>"
                    '<b>Gerekli kanıt</b><ul>' + "".join(f"<li>{e(v)}</li>" for v in task.get("evidence_required", [])) + "</ul>"
                    f'<p><b>Mevcut kanıt:</b> {evidence_links(task.get("source_evidence", []))}</p>'
                    f'<p><b>İnceleme:</b> {e(review.get("reviewer", ""))} · {e(review.get("note", ""))}</p></div>')
    return "".join(body) + "</section>"


def _other(model: dict) -> str:
    d = model["datasets"]
    body = ["<section><h2>Ek teknik kayıtlar</h2>"]
    for name in ("AD_ASSESSMENT", "UBDEN_TECH_PROFILE", "UBDEN_CVE", "UBDEN_CORRELATION",
                 "WIFI_SCAN", "UBDEN_OSINT", "UBDEN_INSIGHTS", "UBDEN_EXECUTION", "ATTACK_LAYER"):
        value = d.get(name)
        if value is not None:
            body.append(f'<h3>{e(name)}</h3><pre>{e(json.dumps(value, ensure_ascii=False, indent=2))}</pre>')
    body.append("</section>")
    return "".join(body)


def _steps(model: dict) -> str:
    steps = model["datasets"].get("steps") or []
    rows = []
    for index, step in enumerate(steps, 1):
        output = step.get("output", "")
        rows.append([e(index), e(step.get("step")), e(step.get("tool")), e(step.get("status")),
                     e(step.get("started_at")), evidence_links([output] if output else []),
                     e(step.get("sha256", ""))])
    return "<section><h2>Adım günlüğü ve kanıt zinciri</h2>" + table(
        ["#", "Adım", "Araç", "Durum", "Başlangıç", "Çıktı", "SHA-256"], rows) + "</section>"


def _file_index(model: dict) -> str:
    rows = [[e(f["path"]), e(f["type"]), e(f["size"]), e(f["sha_status"])]
            for f in model["manifest"]["files"] if f["path"] not in OUTPUTS]
    return "<section><h2>Kaynak dosya ve kanıt dizini</h2><p>Bu tablo yayın sırasında yenilenen çıktı dosyalarını içermez.</p>" + table(
        ["Rapor köküne göre yol", "Tür", "Bayt", "SHA-256"], rows) + "</section>"


def render_html(model: dict, root: Path, mode: str = "technical", *, for_pdf: bool = False) -> str:
    title = {"technical": "Teknik Güvenlik Değerlendirme Raporu",
             "executive": "Yönetici Özeti", "analyst": "Analist Çalışma Raporu"}[mode]
    sections = [_summary(model)]
    if mode == "executive":
        sections += [_findings(model, executive=True), _coverage(model)]
        correlations = (model["datasets"].get("UBDEN_CORRELATION") or {}).get("combined_actions", [])
        sections.append("<section><h2>Önerilen aksiyonlar</h2><ol>" + "".join(
            f'<li><b>{e(a.get("priority"))}:</b> {e(a.get("action"))} — {e(a.get("rationale"))}</li>'
            for a in correlations) + "</ol></section>")
    elif mode == "analyst":
        sections += [_tasks(model), _findings(model)]
    else:
        sections += [_coverage(model), _findings(model), _assets(model), _tasks(model), _other(model), _steps(model), _file_index(model)]
    engagement = model["datasets"].get("engagement") or {}
    footer = (f'<footer>UBDEN® Cyber Security Systems · {e(engagement.get("client", ""))} · '
              f'{e(engagement.get("id", ""))} · Yalnız yetkili alıcılar · '
              '<a href="https://www.ubden.com">www.ubden.com</a> · '
              '<a href="mailto:security@ubden.com">security@ubden.com</a></footer>')
    base = f'<base href="{e(root.as_uri())}/">' if for_pdf else ""
    return ('<!doctype html><html lang="tr"><head><meta charset="utf-8">' + base +
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>'
            f'<style>{_css()}</style></head><body><main>{_header(model, title, root)}'
            + "".join(sections) + footer + "</main></body></html>")


def analyst_json(model: dict) -> dict:
    result = copy.deepcopy(model["datasets"].get("ANALIST_GOREV_RAPORU") or {})
    for task in result.get("tasks", []):
        review = model["reviews"].get("tasks", {}).get(task.get("id"), {})
        if review:
            task["status"] = review.get("status", task.get("status"))
            task["review_note"] = review.get("note", "")
            task["reviewer"] = review.get("reviewer", "")
            task["reviewed_at"] = review.get("updated_at", "")
            task["review_evidence"] = review.get("evidence", [])
    result["pending_count"] = sum(t.get("status") != "tamamlandı" for t in result.get("tasks", []))
    return result


def analyst_markdown(tasks_data: dict) -> str:
    lines = ["# UBDEN® | Analist çalışma raporu", "",
             f'**Müşteri:** {tasks_data.get("client", "")}  ',
             f'**Görev:** {tasks_data.get("project", "")}  ',
             f'**Kayıt:** {tasks_data.get("engagement_id", "")}  ',
             f'**Bekleyen görev:** {tasks_data.get("pending_count", 0)}', "",
             "Görev durumu ve onaylayan kişi yerel WebUI inceleme kaydından alınır.", ""]
    for task in tasks_data.get("tasks", []):
        lines += [f'## {task.get("id")} · {task.get("title")}', "",
                  f'**Öncelik:** {task.get("priority")} · **Durum:** {task.get("status")}', "",
                  f'**Varlıklar:** {", ".join(task.get("targets", []))}', "",
                  f'**Gerekçe:** {task.get("trigger", "")}', "",
                  f'**Müşteriden gereken:** {task.get("customer_input", "")}', "",
                  "### Adımlar", ""]
        lines += [f'{i}. {step}' for i, step in enumerate(task.get("steps", []), 1)]
        lines += ["", "### Gerekli kanıt", ""] + [f'- {v}' for v in task.get("evidence_required", [])]
        lines += ["", f'**Kaynak kanıt:** {", ".join(task.get("source_evidence", [])) or "—"}', ""]
        if task.get("commands"):
            lines += ["### Örnek komutlar", "", "```text"]
            lines += [str(v) for v in task["commands"]]
            lines += ["```", ""]
        lines += [f'**İnceleyen:** {task.get("reviewer", "") or "—"} · {task.get("reviewed_at", "")}', "",
                  f'**İnceleme notu:** {task.get("review_note", "") or "—"}', ""]
    return "\n".join(lines) + "\n"


def roadmap(model: dict) -> str:
    lines = ["# UBDEN® Düzeltme Yol Haritası", "", "Yalnız analist tarafından doğrulanmış ve açık bulgular listelenir.", "",
             "| Öncelik | Bulgu | Varlık | Düzeltme |", "|---|---|---|---|"]
    count = 0
    for item in model["findings"]:
        review = model["reviews"].get("findings", {}).get(item["id"], {})
        if review.get("status") != "doğrulandı":
            continue
        values = [item["severity"], f'{item["id"]} {item["title"]}', item["asset"], item["remediation"]]
        lines.append("| " + " | ".join(v.replace("|", "\\|").replace("\n", " ") for v in values) + " |")
        count += 1
    if not count:
        lines.append("| — | — | — | Henüz analistçe doğrulanmış bulgu yok. |")
    pending = sum(model["reviews"].get("findings", {}).get(item["id"], {}).get("status", item.get("status"))
                  in ("taslak", "inceleniyor") for item in model["findings"])
    lines += ["", f"İnceleme bekleyen gözlem: {pending}.", ""]
    return "\n".join(lines)


def browser_binary() -> Path | None:
    candidates = [
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    ]
    for path in candidates:
        if path.is_file():
            return path
    for name in ("msedge", "chrome", "chromium"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def render_pdf(browser: Path, source: Path, output: Path, profile: Path | None = None) -> None:
    temporary_profile = None
    if profile is None:
        temporary_profile = Path(tempfile.mkdtemp(prefix="ubden-edge-profile-"))
        profile = temporary_profile
    args = [str(browser), "--headless=new", "--disable-gpu", "--no-first-run",
            "--no-default-browser-check", "--disable-extensions", "--no-pdf-header-footer",
            "--disable-background-mode", "--disable-background-networking",
            f"--user-data-dir={profile}", f"--print-to-pdf={output}", source.as_uri()]
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        process = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=180, creationflags=flags)
        if process.returncode != 0 or not output.is_file() or output.stat().st_size < 1000:
            raise RuntimeError(f"PDF oluşturulamadı: {process.stderr[-700:]}")
        with output.open("rb") as pdf:
            if pdf.read(4) != b"%PDF":
                raise RuntimeError("Oluşturulan PDF geçersiz")
    finally:
        if temporary_profile is not None:
            resolved = temporary_profile.resolve()
            if resolved.is_relative_to(Path(tempfile.gettempdir()).resolve()) and resolved.name.startswith("ubden-edge-profile-"):
                shutil.rmtree(resolved, ignore_errors=True)


def _manifest_content(root: Path, staged: Path, output_names: set[str]) -> str:
    names = set()
    for path in root.rglob("*"):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if (relative.startswith(("webui/", ".webui/", ".playwright-cli/"))
                    or relative.split("/", 1)[0].startswith("ubden-pdf-path-")
                    or relative == "SHA256SUMS.txt"):
                continue
            names.add(relative)
    names.update(output_names - {"SHA256SUMS.txt"})
    lines = []
    for relative in sorted(names):
        path = staged / relative if relative in output_names else root / relative
        if not path.is_file():
            continue
        lines.append(f"{sha256(path)}  {relative.replace('/', chr(92))}")
    return "\n".join(lines) + "\n"


def recover_incomplete(root: Path) -> bool:
    """Restore the prior outputs if the application stopped during replacement."""
    state = root / ".webui"
    journal = state / JOURNAL
    if not journal.is_file():
        return False
    record = json.loads(journal.read_text(encoding="utf-8"))
    backup = (root / record.get("backup", "")).resolve()
    backup_root = (state / "backups").resolve()
    names = record.get("outputs", [])
    original_names = set(record.get("original_names", []))
    if not backup.is_relative_to(backup_root) or not backup.is_dir() or set(names) != set(OUTPUTS) or not original_names.issubset(set(OUTPUTS)):
        raise RuntimeError("Yayınlama kurtarma kaydı geçersiz; rapor dosyaları değiştirilmedi")
    for name in OUTPUTS:
        target = root / name
        if name in original_names:
            source = backup / name
            if not source.is_file():
                raise RuntimeError(f"Yedek dosya eksik: {name}")
            shutil.copy2(source, target)
        else:
            target.unlink(missing_ok=True)
    journal.unlink()
    return True


def publish(root: Path, expected_signature: str) -> dict:
    if report_signature(root) != expected_signature:
        raise ValueError("Rapor dosyaları bu oturumda değişti; paneli yenileyip tekrar deneyin")
    model = load_report(root)
    browser = browser_binary()
    if browser is None:
        raise RuntimeError("PDF yayını için Edge veya Chrome bulunamadı")
    state = root / ".webui"
    state.mkdir(exist_ok=True)
    backup = state / "backups" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    staging = Path(tempfile.mkdtemp(prefix="publish-", dir=state))
    published_at = datetime.now(timezone.utc).isoformat()
    try:
        (staging / "REPORT.html").write_text(render_html(model, root), encoding="utf-8")
        task_json = analyst_json(model)
        (staging / "ANALIST_GOREV_RAPORU.json").write_text(json.dumps(task_json, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (staging / "ANALIST_GOREV_RAPORU.md").write_text(analyst_markdown(task_json), encoding="utf-8")
        (staging / "REMEDIATION_ROADMAP.md").write_text(roadmap(model), encoding="utf-8")
        snapshot = copy.deepcopy(model["reviews"])
        snapshot["published_at"] = published_at
        snapshot["source_signature"] = expected_signature
        (staging / "WEBUI_PUBLISHED_REVIEW.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        for mode, filename in (("executive", PDF_NAMES[0]), ("technical", PDF_NAMES[1]), ("analyst", PDF_NAMES[2])):
            source = staging / f"print-{mode}.html"
            source.write_text(render_html(model, root, mode, for_pdf=True), encoding="utf-8")
            render_pdf(browser, source, staging / filename)
        if report_signature(root) != expected_signature:
            raise ValueError("Yayınlama sırasında kaynak rapor değişti; işlem durduruldu")
        (staging / "SHA256SUMS.txt").write_text(_manifest_content(root, staging, set(OUTPUTS)), encoding="utf-8")
        backup.mkdir(parents=True, exist_ok=False)
        original_names = []
        for name in OUTPUTS:
            source = root / name
            if source.is_file():
                shutil.copy2(source, backup / name)
                original_names.append(name)
        journal = state / JOURNAL
        temp_journal = state / f"{JOURNAL}.tmp"
        temp_journal.write_text(json.dumps({"backup": str(backup.relative_to(root)),
                                            "outputs": list(OUTPUTS), "original_names": original_names},
                                           ensure_ascii=False), encoding="utf-8")
        os.replace(temp_journal, journal)
        replaced = []
        try:
            for name in OUTPUTS:
                os.replace(staging / name, root / name)
                replaced.append(name)
        except Exception:
            for name in reversed(replaced):
                if name in original_names:
                    shutil.copy2(backup / name, root / name)
                else:
                    (root / name).unlink(missing_ok=True)
            journal.unlink(missing_ok=True)
            raise
        journal.unlink(missing_ok=True)
        return {"published_at": published_at, "backup": str(backup.relative_to(root)),
                "outputs": list(OUTPUTS), "signature": report_signature(root)}
    finally:
        resolved = staging.resolve()
        if resolved.is_relative_to(state.resolve()) and resolved.name.startswith("publish-"):
            shutil.rmtree(resolved, ignore_errors=True)
