# PARSDX post-UBDEN extension — master plan

Our add-on runs AFTER UBDEN's read-only assessment. UBDEN answers "what is exposed";
we answer "and here is how an attacker turns that into Domain Admin", with evidence,
then we feed our findings back into UBDEN's report. This is what beats a shallow
competitor report (attack narrative + CVSS + chain severity + coverage + ATT&CK).

Grounded in: `../` (UBDEN code), `../../research-offensive-ad-tools.md`,
`../../research-report-automation.md`, `../../ubden-flow-map.md`.

## Integration seam (from the UBDEN map)
No plugin system exists. We attach at the `report_v2.py <run_dir>` boundary:
1. Read UBDEN JSON: engagement.json, steps.json, DEVICE_INVENTORY.json,
   AD_ASSESSMENT.json, ASSESSMENT_COVERAGE.json, targets/*/raw/*.
2. Do our work; save every evidence file INTO the run folder (plain relative path,
   no symlink/`..`, <25 MB).
3. Append findings to `review.json['findings']` (status `doğrulandı` + 7 required
   text fields + evidence + matching SHA-256 → lands VERIFIED; else auto-downgraded).
4. Append step events to `steps.json` with coverage-recognized name prefixes.
5. Re-run `python3 report_v2.py <run_dir>` (or `wizard.py --report-only`).

## Pipeline (modules of parsdx-ext), and what each borrows

| Module | Job | Borrow from (license posture) |
|---|---|---|
| `seed` | UBDEN JSON → NetExec workspace DB (hosts, DC, domain, services) as the shared state store | **NetExec** workspace schema (BSD-2, adapt) |
| `guard` | Reads lockoutThreshold/observationWindow over LDAP and computes the safe budget (shown at pre-flight); provides the lockout-signal detector used by the kill-switch. Live lockout protection = pre-flight validation bind + per-host single-thread auth + output kill-switch (the `guarded_attempt` budget engine is reserved for a future spray path, not the default chain) | **OURS** — no tool does this; the #1 safety piece |
| `collect` | BloodHound.py (`-c DCOnly` quiet → `All`) with client test account → ingest to BloodHound CE | **BloodHound.py** (MIT) + **BloodHound CE** (Apache-2) |
| `plan` | Query CE `shortestPath` to DA; map each edge → a primitive (edge→verb→tool table) | **BloodHound** edge taxonomy + **Adalanche** AQL edge names (AGPL → vocab only) |
| `exec` | Bounded, read-only-first offensive steps, each logged + evidence saved: `certipy find -json` (ADCS), impacket kerberoast/AS-REP, nxc auth-matrix (`Pwn3d!`), `coercer scan`; writes (`bloodyAD`) only behind explicit flag+confirm, each logged WITH its inverse (revert log) | **Certipy** (MIT), **Impacket** (Apache), **NetExec** (BSD-2), **bloodyAD** (MIT), **Coercer** (MIT); phase-gating + per-module timestamped logs from **linWinPwn** (MIT) |
| `score` | CVSS vector→score/band per finding; chain-aware severity (chain of Mediums → Critical) | **RedHat cvss** lib (LGPL, import) + **GoodHound** cost/impact path score (GPL → algorithm only) |
| `map` | Auto-tag findings with ATT&CK techniques; emit Navigator layer JSON + SVG heatmap | **mitreattack-python** `navlayers` (Apache-2, vendor) |
| `narrate` | Attack-path → sentence templates → "attacker reaches DA in N steps" section | **AD-Miner** report structure (GPL → design) + Adalanche edge verbs |
| `coverage` | Declarative check registry (id/category/weight/status/remediation) → coverage matrix (tested/passed/skipped) | **PingCastle** rule catalogue (OSL → design) + **PlumHound** task model (GPL → pattern) |
| `emit` | Write verified findings + coverage steps into the run folder; trigger report_v2 | UBDEN seam |

## License posture (firm)
- **Shell out** to heavy/GPL tools (nxc, certipy, bloodyAD, coercer, responder, bloodhound.py, mitm6) — license irrelevant when invoked as a subprocess.
- **Vendor code** only from permissive: RedHat `cvss` (LGPL, as lib), `mitreattack-python` (Apache), Ghostwriter/PeTeReport finding-schema ideas (BSD/permissive).
- GPL/AGPL/OSL (AD-Miner, GoodHound, PlumHound, PingCastle, Adalanche, Snaffler, Responder, mitm6, DonPAPI): **borrow the design/output shape, run as separate tool — never paste their source into our deliverable.**

## Safety rails baked in (contract: low-rate, lockout-aware, non-destructive)
- `guard` wraps all auth. No spray without reading the domain policy first.
- Read-only-first in the automated pass: `certipy find`, `coercer scan`, `responder -A`, BloodHound collection, share crawl. SAFE.
- Behind explicit flag + operator confirm, NEVER unattended: directory writes (bloodyAD), coercion firing, credential dumping (secretsdump/DonPAPI), Responder active / mitm6.
- Every write logs its inverse (revert log) = the non-destructive audit trail.

## Build order (MVP first — small, testable, no live target needed until `exec`)
1. **`guard`** — the lockout math + LDAP policy read. Foundational, safe, unit-testable offline. Build first.
2. **`score`** — wrap RedHat cvss + a first chain-severity rule. Pure logic, testable now, immediate report win (MILSAFE had no CVSS).
3. **`seed` + `emit`** — the UBDEN JSON ↔ our pipeline ↔ review.json glue. Makes anything we produce show up in the report.
4. **`collect` + `plan`** — BloodHound.py + CE shortestPath (needs a lab AD to test).
5. **`exec`** — the offensive steps, guarded (needs a lab AD).
6. **`map` + `narrate` + `coverage`** — the report differentiators on top.

## A live engagement vs. this build project
- **Tomorrow = manual.** UBDEN scans; we run nxc/bloodhound.py/certipy BY HAND with Claude guiding, `guard` discipline applied manually (read the lockout policy before any auth). No need for parsdx-ext to be finished.
- **parsdx-ext = the ongoing project** that bakes tomorrow's manual steps into one guarded, logged, report-integrated pipeline for future jobs.
