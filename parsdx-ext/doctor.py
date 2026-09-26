"""Pre-engagement readiness check ("doctor") — run BEFORE any live action.

The most common way an engagement day goes wrong is discovering, half-way through, that a tool
isn't installed / the scope file is empty / the DC isn't reachable / no credential was given. This
checks all of that up front and prints a clear GO / NO-GO, so nothing surprises you mid-run.

It is READ-ONLY and sends NO authentication: the only network it does is a plain TCP connect to the
DC's LDAP/SMB ports to confirm a path exists (no login).

    python3 doctor.py --scope scope.txt --dc dc01.corp.local --domain corp.local \
                      --ip 10.0.0.10 --user svc --password '***' [--run-dir <UBDEN_run>]
    python3 doctor.py --self-test
"""
from __future__ import annotations

import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attack  # noqa: E402  (reuse TOOLS, tool_path, load_scope, load_context)

OK, WARN, FAIL = "OK", "WARN", "FAIL"

# Core tools the default chain cannot run without vs. optional ones.
CORE_TOOLS = ["nxc", "certipy", "bloodhound-python", "GetUserSPNs", "GetNPUsers", "coercer"]
OPTIONAL_TOOLS = ["secretsdump"]  # only needed for the gated DCSync-proof step


def check_tools() -> list[tuple]:
    res = []
    for key in CORE_TOOLS:
        p = attack.tool_path(key)
        res.append((f"tool: {key}", OK if p else FAIL,
                    p or f"NOT FOUND ({'/'.join(attack.TOOLS.get(key, [key]))}) — run setup-offensive.sh"))
    for key in OPTIONAL_TOOLS:
        p = attack.tool_path(key)
        res.append((f"tool: {key} (optional)", OK if p else WARN,
                    p or "not found — only needed for the gated DCSync step"))
    return res


def check_pylibs() -> list[tuple]:
    res = []
    for mod, why in (("ldap3", "live lockout-policy read; falls back to nxc bind if missing"),
                     ("cvss", "CVSS cross-check; score.py has its own engine if missing")):
        try:
            __import__(mod); res.append((f"pylib: {mod}", OK, "present"))
        except Exception:  # noqa: BLE001
            res.append((f"pylib: {mod} (optional)", WARN, f"missing — {why}"))
    return res


def check_report_engine() -> list[tuple]:
    installed = "/opt/ubden-cyber/report_v2.py"
    installed_py = "/opt/ubden-cyber/.venv/bin/python"
    parent = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report_v2.py")
    if os.path.exists(installed) and os.path.exists(installed_py):
        return [("report engine", OK, "UBDEN report_v2 + venv found at /opt/ubden-cyber")]
    if os.path.exists(parent):
        return [("report engine", WARN, "found report_v2 next to parsdx-ext but not the /opt venv "
                 "(reportlab may be missing → report regen could fail; findings still land in review.json)")]
    return [("report engine", WARN, "report_v2.py not found — findings still written to review.json, "
             "render the report manually later")]


def check_scope(path) -> tuple:
    if not path:
        return ("scope allowlist", FAIL, "no --scope given — the run will refuse to send any packet (fail-closed)")
    if not os.path.isfile(path):
        return ("scope allowlist", FAIL, f"file not found: {path}")
    try:
        nets, hosts = attack.load_scope(path)
    except OSError as e:
        return ("scope allowlist", FAIL, f"unreadable: {e}")
    if not (nets or hosts):
        return ("scope allowlist", FAIL, f"{path} parsed to ZERO valid IP/CIDR/host entries")
    return ("scope allowlist", OK, f"{len(nets)} network(s) + {len(hosts)} host(s) in scope")


def check_creds(password, hashes) -> tuple:
    if bool(password) == bool(hashes):
        return ("credential", FAIL, "provide EXACTLY one of --password / --hashes (never empty, never both)")
    return ("credential", OK, "one credential supplied (" + ("password" if password else "NT hash") + ")")


def check_context(domain, dc, ip) -> tuple:
    if not domain:
        return ("domain/DC", FAIL, "no --domain")
    if not (dc or ip):
        return ("domain/DC", FAIL, "no --dc and no --ip")
    return ("domain/DC", OK, f"domain={domain} dc={dc or '?'} ip={ip or '?'}")


def _tcp_open(host, port, timeout=3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_reachability(target) -> list[tuple]:
    """Plain TCP connect to the DC's LDAP/SMB ports — NO authentication."""
    if not target:
        return [("DC reachability", WARN, "no DC ip/host to test")]
    res = []
    for port, name in ((445, "SMB"), (389, "LDAP")):
        up = _tcp_open(target, port)
        res.append((f"DC {name} ({target}:{port})", OK if up else FAIL,
                    "reachable" if up else "no TCP path (VPN/AnyDesk network wrong, or host down)"))
    return res


def check_run_dir(run_dir) -> tuple:
    if not run_dir:
        return ("UBDEN run folder", WARN, "no --run-dir (give the UBDEN run folder before the offensive pass)")
    if not os.path.isdir(run_dir):
        return ("UBDEN run folder", WARN, f"not a directory: {run_dir}")
    if not os.path.isfile(os.path.join(run_dir, "engagement.json")):
        return ("UBDEN run folder", WARN, "no engagement.json — run UBDEN first so we can read domain/DC/hosts")
    return ("UBDEN run folder", OK, "engagement.json present")


def verdict(results) -> tuple:
    fails = [r for r in results if r[1] == FAIL]
    warns = [r for r in results if r[1] == WARN]
    go = not fails
    return go, len(fails), len(warns)


def run_checks(*, scope=None, dc=None, domain=None, ip=None, user=None, password=None,
               hashes=None, run_dir=None, net=True) -> list[tuple]:
    results = []
    results += check_tools()
    results += check_pylibs()
    results.append(check_report_engine()[0])
    results.append(check_scope(scope))
    results.append(check_creds(password, hashes))
    results.append(check_context(domain, dc, ip))
    results.append(check_run_dir(run_dir))
    if net:
        results += check_reachability(ip or dc)
    return results


def _print(results) -> int:
    sym = {OK: "  [OK]  ", WARN: "  [WARN]", FAIL: "  [FAIL]"}
    for name, status, msg in results:
        print(f"{sym[status]} {name:34s} {msg}")
    go, nf, nw = verdict(results)
    print()
    if go:
        print(f"==> GO — 0 blocker(s), {nw} warning(s). Safe to proceed (dry-run first).")
    else:
        print(f"==> NO-GO — {nf} blocker(s), {nw} warning(s). Fix the [FAIL] items above before running.")
    return 0 if go else 1


def _self_test() -> int:
    import tempfile
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    # scope
    check("no scope -> FAIL", check_scope(None)[1] == FAIL)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "s.txt"); open(p, "w").write("10.0.0.0/24\ndc01.corp.local\n")
        check("valid scope -> OK", check_scope(p)[1] == OK)
        empty = os.path.join(d, "e.txt"); open(empty, "w").write("# only a comment\n")
        check("empty scope -> FAIL", check_scope(empty)[1] == FAIL)
        check("missing scope file -> FAIL", check_scope(os.path.join(d, "nope.txt"))[1] == FAIL)

    # creds
    check("password only -> OK", check_creds("pw", None)[1] == OK)
    check("hashes only -> OK", check_creds(None, "aad3b:31d6")[1] == OK)
    check("no credential -> FAIL", check_creds(None, None)[1] == FAIL)
    check("both credentials -> FAIL", check_creds("pw", "hash")[1] == FAIL)

    # context
    check("full context -> OK", check_context("corp.local", "dc01", "10.0.0.10")[1] == OK)
    check("no domain -> FAIL", check_context(None, "dc01", None)[1] == FAIL)
    check("no dc/ip -> FAIL", check_context("corp.local", None, None)[1] == FAIL)

    # verdict aggregation
    go, nf, nw = verdict([("a", OK, ""), ("b", WARN, ""), ("c", FAIL, "")])
    check("verdict NO-GO with a FAIL", (go is False) and nf == 1 and nw == 1)
    go2, nf2, _ = verdict([("a", OK, ""), ("b", WARN, "")])
    check("verdict GO with only warnings", go2 is True and nf2 == 0)

    # run_dir
    with tempfile.TemporaryDirectory() as d:
        check("run-dir without engagement.json -> WARN", check_run_dir(d)[1] == WARN)
        open(os.path.join(d, "engagement.json"), "w").write("{}")
        check("run-dir with engagement.json -> OK", check_run_dir(d)[1] == OK)

    # end-to-end (net off) never crashes and returns a verdict
    res = run_checks(scope=None, domain="corp.local", ip="10.0.0.10", password="pw", net=False)
    check("run_checks returns a NO-GO verdict when scope missing", verdict(res)[0] is False)

    total = 16
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PARSDX pre-engagement readiness check (GO/NO-GO)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--scope"); ap.add_argument("--run-dir")
    ap.add_argument("--dc"); ap.add_argument("--domain")
    ap.add_argument("--ip", dest="ip"); ap.add_argument("--user")
    ap.add_argument("--password"); ap.add_argument("--hashes")
    ap.add_argument("--no-net", action="store_true", help="skip the DC TCP reachability check")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    ctx_dc, ctx_dom, ctx_ip = a.dc, a.domain, a.ip
    if a.run_dir:  # fill missing bits from the UBDEN run folder
        ctx = attack.load_context(a.run_dir)
        ctx_dom = ctx_dom or ctx.domain; ctx_dc = ctx_dc or ctx.dc; ctx_ip = ctx_ip or ctx.dc_ip
    results = run_checks(scope=a.scope, dc=ctx_dc, domain=ctx_dom, ip=ctx_ip, user=a.user,
                         password=a.password, hashes=a.hashes, run_dir=a.run_dir, net=not a.no_net)
    return _print(results)


if __name__ == "__main__":
    sys.exit(main())
