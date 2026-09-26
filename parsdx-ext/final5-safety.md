# FINAL adversarial safety audit — parsdx-ext

Date: 2026-09-26 · Scope: all `.py` in `parsdx-ext/` read in full, incl. recent additions
(`doctor.py`, `crack.py`, `remediation.py`, `cracked_credential` wiring in `pipeline.py`).
Method: read every code path, ran all 7 module self-tests (102/102 pass), and wrote bypass
harnesses for scope / lockout / writes / secrets / denylist.

Verdict: **one CONFIRMED out-of-scope-traffic bug (`doctor.py`, MEDIUM). No path can lock
accounts, crash a DC, change state unattended, or leak the working credential to disk. The
offensive engine (`attack.py`/`pipeline.py`) remains fail-closed after the additions.** Fix
the doctor scope gate before Monday.

---

## CONFIRMED

### C-1 [MEDIUM] `doctor.py` sends network probes to a target it never checks against `--scope`
`doctor.py:108-118` (`check_reachability`), `:144-169` (`check_clock_skew`), `:120-131`
(`check_dns`) all fire at `ip or dc` (`run_checks`, `:200-202`). `check_scope` (`:72-83`) only
validates that the allowlist *file parses* — it never asserts the DC target is **in** it. There
is no equivalent of `attack.py:432-433` (`if ... not in_scope(dc_target): raise SafetyAbort`).

Concrete scenario (demonstrated): scope file = `10.0.0.0/24`, `--ip 8.8.8.8` →
```
('DNS', 'corp.local')            # getaddrinfo, leaves the box
('TCP', ('8.8.8.8', 445))        # socket.create_connection
('TCP', ('8.8.8.8', 389))
('NMAP', ['/usr/bin/nmap','-Pn','-p445','--script','smb2-time','8.8.8.8'])
```
Realistic trigger on engagement day: `doctor.py:288-290` auto-fills `ctx_ip` from
`engagement.json` when `--run-dir` is given (RUNBOOK line 49-50 passes both). If UBDEN
discovered a DC that is **not** in the human-signed `scope.txt`, doctor TCP-connects and
`nmap`s it. This directly violates the C1 remediation promise ("out-of-scope hosts skipped")
and RUNBOOK line 136 ("Kapsam dışına tek paket gitmesin").

Impact bound: read-only packets only (TCP SYN, one SMB2 `smb2-time` script, a DNS lookup) — an
authorization/contract violation, **not** a DoS or lockout. nmap is invoked with a fixed safe
argv (no injectable field). Severity is MEDIUM only because the target is operator/UBDEN-
supplied rather than attacker-controlled.

Fix: in `run_checks`, after `attack.load_scope(scope)`, compute
`in_scope(ip or dc, nets, hosts)` and, if false, emit a `FAIL` row and **skip**
`check_reachability` / `check_clock_skew` / `check_dns` entirely (fail closed, same as
`attack.py`). Do not send a packet to a host the allowlist rejects.

---

## THEORETICAL / LOW (accept + note)

### T-1 [LOW] Name-vs-resolved-IP scope gap (`attack.py`, `doctor.py`)
`in_scope` (`attack.py:117-124`) matches the literal host **string**; the underlying tool
(nxc / impacket / bloodhound / nmap) does its own DNS resolution. A hostname that is in scope
but resolves to an out-of-scope IP (stale record, split-horizon, DNS rebinding) sends traffic
off-scope. Inherent to name-based allowlists. Mitigation: prefer IP/CIDR entries in `scope.txt`
and pin `--ip`; the RUNBOOK example already does both.

### T-2 [LOW] `_scrub_secrets` misses short/transformed secrets (`attack.py:309-328`)
Literal `str.replace`, and secrets `< 3` chars are skipped (`:315`). A 1–2-char password, or a
credential a tool echoes in a different encoding/split form, could survive in an evidence file.
Real passwords are longer; DCSync loot is the finding itself (relies on 0600 + gating + no
exfil, as documented). Low.

### T-3 [INFO] argv secrets (already-documented residual H1)
`attack.py` steps, the nxc pre-flight (`:261`), `doctor.py --password`, and
`guard.py --policy` pass `-p`/`-H` on argv → visible to `ps` for the process window. Documented
in SAFETY.md; mitigation is single-user box + short timeouts. No code fix without wrapper/env
support in the downstream tools.

---

## PROVEN SAFE (each item checked against the question list)

**1. Scope fail-closed — `attack.py`/`pipeline.py` (holds after additions).**
- No allowlist ⇒ `SafetyAbort` before any packet (`run_offensive:426-427`; self-test
  "fails closed without scope").
- DC out-of-scope ⇒ abort **before** pre-flight (`:432-433`); pre-flight/LDAP/nxc network
  therefore only ever hits an already-in-scope DC (`:440-446`, order verified).
- Per-step defense-in-depth re-check in `run_plan:351` using the same allowlist.
- Host source: `load_context` reads `DEVICE_INVENTORY.json`/`engagement.json`, then
  `valid_target` drops junk/option-like entries (`:167`; self-test "junk host '-M' dropped").
- `build_plan` receives only scope-filtered `in_hosts` (`:429`, `:448`).

**2. Lockout — cannot lock a real account on the default chain.**
- Pre-flight bind ALWAYS before fan-out; `skip_preflight` is **not** exposed on any CLI
  (`attack.main`/`pipeline.main` have no such flag) — reachable only in-process for the STOP
  self-test, and it prints a loud warning.
- A **correct** single credential never increments `badPwdCount`; pre-flight proves correctness
  before multi-host fan-out, so host count is irrelevant to lockout.
- Every authenticated nxc step is `-t 1` and steps run sequentially in one loop
  (`build_plan:217/221`, self-test "nxc steps single-thread").
- Output kill-switch: after each auth step `is_lockout_signal(tail)` → `break`, and
  `_LOGON_FAIL` → `break` (`run_plan:394-403`). External `STOP` file checked before every step
  (`:347-349`, self-test "STOP file aborts the run").
- Guard edge policy: `budget()` handles threshold 0 (→cap), 1 (→0, refuses), 2 (→1), and
  window `None` (never prunes = most conservative) — all in `guard._self_test` (18/18). Note:
  `guarded_attempt`/budget is **display-only** in the default chain (SAFETY.md); the live
  control is single-cred + kill-switch, which is stronger.

**3. `crack.py` is OFFLINE — no network at all.** No `socket`/`subprocess`/`http` import or
call (grep-confirmed across the module). It reads collected evidence, writes `.hash`
(0600) + `cracked.json` (0600), and only **prints** hashcat/john commands — it never executes
them. Malicious `show.txt`: read line-by-line, `rsplit(':',1)` + regex, `json.dump` — no shell,
no eval, no path derived from content; `run_dir`/`show_file` are operator paths. The cracked
**password value is not persisted** (only "cracked" + account), so ingest leaks nothing.

**4. Writes / DCSync gating (single choke point, both entrypoints).** `pipeline.run` →
`attack.run_offensive` → `confirm_writes` (`attack.py:435`, always). DCSync step is built only
under `enable_writes AND allow_dcsync` (`build_plan:228`); it is the **only** write step, so
`--enable-writes` alone builds nothing state-changing. Non-tty without `--assume-yes` ⇒
`SafetyAbort` (`confirm_writes:245-246`, self-test). `--allow-dcsync` alone (no
`--enable-writes`) ⇒ no dcsync (self-test "no dcsync without allow flag"). `doctor.py`,
`crack.py`, `remediation.py` have **no** state-changing or write-to-AD path.

**5. Denylist unreachable.** `DENYLIST` (`attack.py:47`) includes zerologon, nopac,
eternalblue/ms17-010, mimikatz, mitm6, printnightmare, petitpotam(fire). `_assert_not_denylisted`
runs in `build_plan` (`:233-234`) and again per step in `run_plan` (`:355`). No code path
constructs any of those commands. New tool invocations are safe: `nmap -Pn -p445 --script
smb2-time` (read-only, fixed argv) and hashcat (offline, printed only, never run). certipy verb
is `find`, coercer verb is `scan` (self-tests assert both).

**6. Secrets at rest / DA claim.** `umask 0o077`; evidence dir 0700; every artifact 0600
(`parsdx_steps.json`, `SUMMARY.json`, `review.json`, `cracked.json`, `*.hash`, `REMEDIATION.md`
— each with a `chmod 0600`, grep-confirmed). `_scrub_secrets` strips the echoed cleartext
credential before hashing (self-test). Pre-flight output is captured to memory, never a file.
`doctor.py` sends no auth and does not print the password (only "one credential supplied").
`reached_da` is set only from an executed DCSync dump containing `:::`/`krbtgt`
(`pipeline.infer_reached_da:35-47`), never from file existence or read-only certipy (self-test
"does NOT claim DA from inventory only").

**Report-layer modules** (`parse`, `score`, `attck`, `narrate`, `coverage`, `remediation`,
`emit`) do no network and no AD state change (grep for socket/subprocess/network across all =
only `emit.regenerate_report` shelling the local `report_v2.py`, which renders PDFs — no target
traffic).
