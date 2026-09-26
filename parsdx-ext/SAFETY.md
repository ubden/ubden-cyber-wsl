# SAFETY — "do not wreck the client machine"

How parsdx-ext maps to the engagement contract (PARSDX↔client, Madde 5/8/9), UBDEN's bounded design,
and industry standard (PTES / NIST SP 800-115). Sources at bottom.

## What our DEFAULT chain does — and why none of it can break the box
`attack.py` build_plan default = READ-ONLY / single-credential only. Every step is normal
directory/Kerberos/SMB traffic a DC handles all day:

| Step | Action | State change? | Availability risk | Lockout risk |
|---|---|---|---|---|
| adcs_find | `certipy find` (read) | none | none | none |
| bloodhound_dconly | LDAP read (DCOnly) | none | negligible (quiet) | none |
| asrep_roast | `GetNPUsers -request` | none | none | none (no password sent) |
| kerberoast | `GetUserSPNs -request` | none | none | none (valid cred, no guessing) |
| auth_matrix | `nxc smb` with ONE known cred | none | none | none (correct cred = no bad-pw count) |
| share_triage | SMB read/spider | none | negligible | none |
| coerce_scan | `coercer scan` (probe only) | none | none | none |

## What we NEVER run (these are what actually break/DoS a machine)
Hard-excluded from the tool. Not a flag, not a mode — absent by design:
- **Zerologon (CVE-2020-1472)** — blanks the DC machine password; **breaks the domain** if not
  restored. Never. ([CrowdStrike](https://www.crowdstrike.com/en-us/blog/cve-2020-1472-zerologon-security-advisory/))
- **noPac, MS17-010/EternalBlue and other memory-corruption/service exploits** — can crash the DC/host.
- **Responder ACTIVE poisoning / mitm6** — MITMs real users network-wide; disruptive. (Only read-only
  `responder -A` / IPv6-exposure check is even considered, and not in the automated chain.)
- **DDoS / stress / availability testing** — forbidden (contract Madde 5, 9).
- **Data deletion, persistence/backdoors, deliberate shutdown, physical** — forbidden (Madde 5).

## What is GATED (off unless explicitly unlocked + `YETKILIYIM` typed)
**Implemented today** — only one write action exists in `build_plan`:
- **DCSync / secretsdump** — needs `--enable-writes` AND `--allow-dcsync` AND `YETKILIYIM` (or
  `--assume-yes` for headless). Read-heavy, pulls secrets → proof only, never exfiltrate (Madde 8).
  ⚠️ `--enable-writes --allow-dcsync --assume-yes` together = unattended full-domain dump — do not use
  that combo on a live engagement; confirm by hand.

**PLANNED — NOT implemented yet** (do not assume these run): bloodyAD directory writes with a revert
log, and coercion *firing* (only the read-only `coercer scan` runs today). When added they will sit
behind the same choke point.

## The two REAL risks and how we control them
1. **Account lockout** (the #1 realistic harm in AD testing). The default chain uses ONE known-good
   account and never sprays, so the live protection is three concrete controls (not a spray budget):
   (a) a **credential pre-flight bind** validates the account once before any fan-out — a wrong/expired
   password aborts the whole run before it can increment `badPwdCount`; (b) each authenticated step is
   **per-host, single-thread** (`-t 1`), sequential; (c) every auth step's output is scanned and the run
   **hard-stops on the first lockout / logon-failure signal**. `guard.py` reads the domain lockout policy
   and prints the safe budget at pre-flight; its budget engine (`guarded_attempt`) is reserved for a
   future password-spray path, which is NOT part of the default chain.
   ([hackndo](https://en.hackndo.com/password-spraying-lockout/))
2. **The foothold machine itself (the AnyDesk box).** The biggest risk to it is NOT our offensive
   layer — it is **UBDEN's installer** (applies mirrored networking to all WSL distros + may reboot)
   and **`destroy`** (unregisters ALL WSL). Warn the client, take a snapshot, never run `destroy`
   before exporting the report.

## Pre-flight safety checklist (engagement day)
- [ ] Scope + signed authorization confirmed; only scope.md hosts touched.
- [ ] Client took a snapshot / has backups (contract Madde 9 puts this on them, but confirm).
- [ ] `guard.py --policy ...` run BEFORE any auth; safe budget noted.
- [ ] First run is `--dry-run`; review the plan before going live.
- [ ] `--enable-writes` stays OFF unless a finding genuinely needs proof AND it's confirmed.
- [ ] Go step by step, paste output to Claude, stop on anything unexpected (contract Madde 18 right-to-suspend).

## Honest caveat
This toolkit is NEW and has not yet run against a live AD. Industry practice is to validate in a lab
first. On the day: dry-run, then step through slowly with Claude watching output. Read-only-first means
the worst realistic outcome of the default chain is "a scan showed up in their logs" — not an outage.

## Audit remediation (2026-09-26)
A hostile self-audit (`parsdx-safety-audit.md`) found the code did not match this file. All six
release-blockers are now fixed and self-tested (103/103):
- **C1 scope** — mandatory `--scope` allowlist; no allowlist ⇒ zero packets (fail closed); out-of-scope
  hosts dropped from context and skipped per-step; junk/option-like host entries rejected.
- **C2/H3/H4 guard bypass** — one guarded credential PRE-FLIGHT bind before any fan-out; a bad/expired
  credential aborts before it can lock the account; per-host auth steps, single-thread (`-t 1`).
- **C3/M4 empty credential** — password XOR hashes required; never `-p ""`; `stdin=DEVNULL`; auth-step
  timeout 120 s (no 30-min hangs).
- **C4/M6 unattended writes** — single `confirm_writes` choke point BOTH entrypoints hit; DCSync needs
  `--enable-writes` AND `--allow-dcsync`; non-interactive without `--assume-yes` refuses.
- **C5/H2 dead kill-switch** — every auth step's output scanned for lockout / logon-failure; first hit
  HARD-STOPS the run; plus a `STOP` file external kill-switch checked before each step.
- **C6/H1/M3 secrets at rest** — `umask 0o077`, evidence dir 0700, files 0600; bloodhound runs with
  `cwd=out_dir` (no loot in the shell's CWD); absolute tool paths (no PATH-hijack).
- **M1 false DA claim** — `reached_da` is set only from an EXECUTED DCSync dump, never from a read-only
  `certipy find`; the narrative labels ADCS/coercion as "path proven, final step not fired".

### Residual risks (accept + mitigate manually)
- **argv secrets (H1):** tools still take `-p` on argv (visible to `ps`). Mitigation: run on a
  single-user box for the engagement window; short timeouts shrink the exposure window.
- **share-crawl disk (L2):** `spider_plus` on a huge share can be heavy. Mitigation: don't point it at
  known-huge shares; watch disk; abort with the `STOP` file if needed.

## Sources
- PTES / internal pentest methodology: https://thecyphere.com/blog/what-is-internal-penetration-testing/
- AD pentest methodology: https://www.vaadata.com/en/blog/active-directory-pentesting-objective-methodology-black-box-and-grey-box-tests/
- Lockout-safe spraying: https://en.hackndo.com/password-spraying-lockout/ · https://github.com/Pennyw0rth/NetExec/pull/1353
- Zerologon danger: https://www.crowdstrike.com/en-us/blog/cve-2020-1472-zerologon-security-advisory/
