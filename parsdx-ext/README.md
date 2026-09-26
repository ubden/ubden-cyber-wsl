# parsdx-ext — post-UBDEN offensive + report layer

UBDEN answers "what is exposed" (read-only). This layer answers "and here is how an attacker
turns that into Domain Admin", with evidence, then folds our findings back into UBDEN's report.
That gap — an attack narrative, CVSS, chain-aware severity, coverage, ATT&CK — is exactly what a
shallow competitor report lacks.

## Modules (each has `--self-test`, all offline-safe)

| File | Role |
|---|---|
| `doctor.py` | Pre-engagement readiness check (GO/NO-GO): tools installed, scope valid, credential present, DC reachable (TCP only, no auth). Run this FIRST. |
| `guard.py` | Lockout-aware auth guard — reads domain policy, budgets attempts, hard-stops on lockout. Wraps all guessing. |
| `attack.py` | Offensive orchestrator — reads UBDEN JSON, runs a READ-ONLY-FIRST chain (ADCS→BloodHound→AS-REP→kerberoast→auth-matrix→coerce-scan), evidence into `<run>/parsdx`. Writes/dumps gated behind `--enable-writes`+confirm. |
| `parse.py` | Tool output → normalized findings (certipy/kerberoast/asrep/nxc/coercer). |
| `score.py` | CVSS 3.1 (self-tested vs known vectors) + chain-aware severity (chain→DA = Critical). |
| `attck.py` | MITRE ATT&CK tagging + Navigator layer JSON. |
| `narrate.py` | Kill-chain narrative (Turkish, client-facing). |
| `coverage.py` | Coverage matrix (tested/attempted/skipped) from executed steps. |
| `emit.py` | Writes findings into UBDEN `review.json` (verified when evidence hash-matches) + re-runs report_v2. |
| `pipeline.py` | A-to-Z: attack → parse → score → attck → chain → narrate → coverage → emit. |
| `setup-offensive.sh` | Installs the offensive toolchain on Kali (run once, on the box). |
| `ARCHITECTURE.md` | The full design + what each idea was borrowed from. |
| `RUNBOOK.md` | Step-by-step operator guide for engagement day. |

## Run (on the Kali box, after UBDEN finishes)

```bash
sudo bash parsdx-ext/setup-offensive.sh                    # once
printf '10.0.0.0/24\n<DC_IP>\n<DOMAIN>\n' > scope.txt      # REQUIRED allowlist (fail-closed)
python3 parsdx-ext/doctor.py --scope scope.txt --run-dir <UBDEN_run> \
        --dc dc01.corp.local --domain corp.local --ip <DC_IP> --user <test_acct> --password '***'  # GO/NO-GO first
python3 parsdx-ext/pipeline.py --run-dir <UBDEN_run> --scope scope.txt \
        --dc dc01.corp.local --domain corp.local \
        --user <test_acct> --password '***' --ip <DC_IP> --dry-run   # preview the plan
python3 parsdx-ext/pipeline.py --run-dir <UBDEN_run> --scope scope.txt ...   # live
python3 parsdx-ext/pipeline.py --run-dir <run> --skip-attack                 # rebuild report layer only
```

Safety (see SAFETY.md): `--scope` allowlist is mandatory (no allowlist ⇒ zero packets); a guarded
credential pre-flight aborts before any fan-out if the password is wrong; every auth step is per-host
single-thread and output-scanned for lockout (hard-stop on the first signal); a `STOP` file in the run
dir is a kill-switch; evidence is 0600; writes/dumps need `--enable-writes` + `YETKILIYIM`, DCSync also
`--allow-dcsync`. Passwords are redacted in all logs. DC-breaking tooling (Zerologon/noPac/EternalBlue)
is denylisted and absent.

## Test everything
```bash
for m in doctor guard attack score parse attck narrate coverage emit pipeline; do
  python3 parsdx-ext/$m.py --self-test | tail -1; done
```
