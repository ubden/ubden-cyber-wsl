"""PARSDX A-to-Z pipeline: the one command to run after UBDEN (safety-hardened).

  attack (scoped, guarded, read-only-first)  ->  parse  ->  score (CVSS + chain)  ->  ATT&CK layer
  ->  kill-chain narrative  ->  coverage matrix  ->  emit into UBDEN's report.

All gating (scope allowlist, credential pre-flight, lockout kill-switch, write confirmation) lives in
attack.run_offensive — the single choke point both entrypoints hit. Offline-safe: --skip-attack parses
existing evidence; --dry-run runs nothing live; --no-report skips report regeneration.

    python3 pipeline.py --run-dir <run> --scope scope.txt --dc dc01 --domain corp.local \
                        --user svc_test --password '***' --ip 10.0.0.10
    python3 pipeline.py --run-dir <run> --skip-attack        # rebuild report layer only
    python3 pipeline.py --self-test
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attack, parse, score, attck, narrate, coverage, emit  # noqa: E402

STAGE_ORDER = {"unauth_smb": 0, "gpp_password": 1, "asrep_roast": 1, "kerberoast": 1,
               "default_creds": 2, "local_admin": 3, "coercion": 4, "adcs_esc": 4, "dcsync": 5}


def order_chain(findings):
    return sorted(findings, key=lambda f: STAGE_ORDER.get(f.get("type", ""), 9))


def infer_reached_da(run_dir: str) -> bool:
    """Claim Domain Admin ONLY from an EXECUTED DCSync that actually returned secrets.
    Mere existence of dcsync_dump.txt is not enough — run_plan creates the file before secretsdump
    writes, so a failed/empty dump must NOT read as 'Domain Admin achieved'. Require real hash lines
    (impacket ends each with ':::', and krbtgt is the tell-tale)."""
    p = os.path.join(run_dir, "parsdx", "dcsync_dump.txt")
    if not os.path.isfile(p):
        return False
    try:
        body = open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return False
    return (":::" in body) or ("krbtgt:" in body.lower())


def run(run_dir, creds, *, nets=None, hosts_allow=None, skip_attack=False, dry_run=False,
        enable_writes=False, allow_dcsync=False, assume_yes=False, no_report=False,
        reached_da=None, lang="tr") -> dict:
    pdir = os.path.join(run_dir, "parsdx")
    os.umask(0o077)
    os.makedirs(pdir, exist_ok=True)

    ctx = attack.load_context(run_dir)
    for k in ("domain", "dc", "dc_ip"):
        if creds.get(k):
            setattr(ctx, k, creds[k])

    if not skip_attack:
        attack.run_offensive(ctx, user=creds.get("user"), password=creds.get("password"),
                             hashes=creds.get("hashes"), nets=nets, hosts_allow=hosts_allow,
                             enable_writes=enable_writes, allow_dcsync=allow_dcsync,
                             dry_run=dry_run, assume_yes=assume_yes, out_dir=pdir)

    findings = parse.parse_run(run_dir)
    for f in findings:
        score.score_finding(f)
    attck.tag_findings(findings)
    layer_path = attck.write_layer(findings, os.path.join(pdir, "ATTACK_LAYER.json"))

    chain = order_chain(findings)
    da = infer_reached_da(run_dir) if reached_da is None else reached_da
    cs = score.chain_severity(chain, da)
    narr_path = narrate.write_narrative(chain, da, os.path.join(pdir, "KILL_CHAIN.md"), lang)
    cov_json, cov_md = coverage.write_matrix(run_dir)

    emit_res = emit.emit_findings(run_dir, findings)
    report_rc = None
    if not dry_run and not no_report:
        report_rc = emit.regenerate_report(run_dir)

    summary = {
        "findings": len(findings), "emit": emit_res, "chain": cs,
        "artifacts": {"attack_layer": os.path.relpath(layer_path, run_dir),
                      "kill_chain": os.path.relpath(narr_path, run_dir),
                      "coverage_json": os.path.relpath(cov_json, run_dir),
                      "coverage_md": os.path.relpath(cov_md, run_dir)},
        "report_regenerated": report_rc == 0 if report_rc is not None else False,
    }
    with open(os.path.join(pdir, "SUMMARY.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    try:
        os.chmod(os.path.join(pdir, "SUMMARY.json"), 0o600)
    except OSError:
        pass
    _write_summary_md(run_dir, summary, cs)
    return summary


def _write_summary_md(run_dir, summary, cs):
    lines = ["# PARSDX — Özet", "",
             f"- Bulgu sayısı: **{summary['findings']}** "
             f"(rapora eklenen: {summary['emit']['added']}, "
             f"doğrulanmış: {summary['emit']['verified']}, taslak: {summary['emit']['draft']})",
             f"- Zincir sonucu: **{cs['chain_severity']} (CVSS {cs['chain_score']})** — "
             f"{'Domain Admin FİİLEN elde edildi' if cs['reached_da'] else 'DA fiilen çalıştırılmadı (yol tespit edildiyse raporda belirtildi)'}, "
             f"{cs['links']} aşama",
             f"- Gerekçe: {cs['rationale']}", "",
             "## Üretilen dosyalar (parsdx/)",
             f"- Saldırı zinciri anlatısı: `{summary['artifacts']['kill_chain']}`",
             f"- ATT&CK Navigator katmanı: `{summary['artifacts']['attack_layer']}`",
             f"- Kapsam matrisi: `{summary['artifacts']['coverage_md']}`", "",
             "Bulgular UBDEN `review.json`'ına yazıldı; rapor `report_v2.py` ile yeniden üretildi."
             if summary["report_regenerated"] else
             "Bulgular UBDEN `review.json`'ına yazıldı (rapor yeniden üretimi atlandı)."]
    p = os.path.join(run_dir, "parsdx", "SUMMARY.md")
    open(p, "w", encoding="utf-8").write("\n".join(lines))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def _self_test() -> int:
    import tempfile
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    with tempfile.TemporaryDirectory() as d:
        json.dump({"ad": {"domain": "corp.local", "dc": "dc01.corp.local", "dc_ip": "10.0.0.10"}},
                  open(os.path.join(d, "engagement.json"), "w"))
        json.dump({"schema": 1, "devices": [{"ip": "10.0.0.10"}, {"ip": "10.0.0.20"}]},
                  open(os.path.join(d, "DEVICE_INVENTORY.json"), "w"))
        json.dump([{"step": "nmap_10.0.0.10", "status": "ok"}], open(os.path.join(d, "steps.json"), "w"))
        pdir = os.path.join(d, "parsdx"); os.makedirs(pdir)
        open(os.path.join(pdir, "kerberoast.txt"), "w").write("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc*$h")
        # per-host filename (matches real attack.py output; guards the parse regression)
        open(os.path.join(pdir, "auth_matrix_10.0.0.20.txt"), "w").write("SMB 10.0.0.20 445 FILE01 [+] corp.local\\svc:P (Pwn3d!)")
        open(os.path.join(pdir, "adcs_find.txt"), "w").write("    Template Name : UserAuth\n      ESC1 : enrollee supplies subject")

        s = run(d, {"user": "svc", "password": "P"}, skip_attack=True, no_report=True)
        check("parsed 3 findings", s["findings"] == 3)
        check("emitted 3 verified", s["emit"]["added"] == 3 and s["emit"]["verified"] == 3)
        # M1: no DCSync executed -> must NOT claim DA reached
        check("does NOT claim DA from inventory only", s["chain"]["reached_da"] is False)
        # but a Critical vuln (ESC1) still makes the chain Critical
        check("chain still Critical (ESC1 present)", s["chain"]["chain_severity"] == "Critical")
        check("kill-chain conclusion is honest (not achieved)",
              "ulaşmadı" in open(os.path.join(pdir, "KILL_CHAIN.md"), encoding="utf-8").read())
        check("artifacts written", all(os.path.exists(os.path.join(d, s["artifacts"][k]))
              for k in ("attack_layer", "kill_chain", "coverage_json")))

        # now simulate an executed DCSync -> DA truly reached
        open(os.path.join(pdir, "dcsync_dump.txt"), "w").write("krbtgt:502:aad3b...:31d6...")
        check("claims DA only after executed DCSync", infer_reached_da(d) is True)

        # evidence files locked down 0600
        mode = oct(os.stat(os.path.join(pdir, "SUMMARY.json")).st_mode)[-3:]
        check("SUMMARY.json is 0600", mode == "600")

    total = 8
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PARSDX post-UBDEN A-to-Z pipeline (hardened)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--run-dir")
    ap.add_argument("--scope", help="allowlist file (IP/CIDR/hostname per line) — required for live runs")
    ap.add_argument("--dc"); ap.add_argument("--domain")
    ap.add_argument("--user"); ap.add_argument("--password"); ap.add_argument("--hashes")
    ap.add_argument("--ip", dest="dc_ip")
    ap.add_argument("--skip-attack", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--enable-writes", action="store_true")
    ap.add_argument("--allow-dcsync", action="store_true")
    ap.add_argument("--assume-yes", action="store_true")
    ap.add_argument("--no-report", action="store_true")
    ap.add_argument("--reached-da", dest="da", action="store_true", default=None)
    ap.add_argument("--no-da", dest="da", action="store_false")
    ap.add_argument("--lang", default="tr")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.run_dir:
        ap.error("--run-dir required")
    nets, hosts = ([], set())
    if a.scope:
        nets, hosts = attack.load_scope(a.scope)
    creds = {"user": a.user, "password": a.password, "hashes": a.hashes,
             "domain": a.domain, "dc": a.dc, "dc_ip": a.dc_ip}
    try:
        s = run(a.run_dir, creds, nets=nets, hosts_allow=hosts, skip_attack=a.skip_attack,
                dry_run=a.dry_run, enable_writes=a.enable_writes, allow_dcsync=a.allow_dcsync,
                assume_yes=a.assume_yes, no_report=a.no_report, reached_da=a.da, lang=a.lang)
    except attack.SafetyAbort as e:
        print(f"[SAFETY ABORT] {e}", file=sys.stderr); return 2
    print(json.dumps(s, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
