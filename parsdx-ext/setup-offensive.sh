#!/usr/bin/env bash
# Install the offensive toolchain the PARSDX post-UBDEN chain shells out to.
# Run this on the Kali WSL box AFTER UBDEN is installed, BEFORE running pipeline.py.
# Idempotent; safe to re-run. Kali/Debian only.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  exec sudo -- bash "$(readlink -f -- "$0")" "$@"
fi
if [[ ! -f /etc/debian_version ]]; then
  echo "[HATA] Bu script Kali/Debian icindir." >&2; exit 1
fi
export DEBIAN_FRONTEND=noninteractive
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FAILED=()

echo "[1/4] APT paketleri (repo araclari)"
apt-get update
# NOTE: netexec is NOT on PyPI (`pipx install netexec` can never work) — Kali ships it as an apt
# package, so it belongs here. ntpdate was renamed to ntpsec-ntpdate in modern Debian/Kali.
# pocl-opencl-icd + ocl-icd-libopencl1: without BOTH, hashcat finds no backend on a CPU-only box
# and silently cracks nothing ("No OpenCL ... platform found"). Measured 2026-09-27 — the ICD
# alone is not enough, the loader has to be there too. john is the CPU fallback either way.
for p in netexec ldap-utils smbclient hashcat john pocl-opencl-icd ocl-icd-libopencl1 nmap \
         ntpsec-ntpdate responder krb5-user python3-pip pipx seclists dnsutils; do
  apt-get install -y --no-install-recommends "$p" || FAILED+=("apt:$p")
done

echo "[2/4] Python offensive araclari (pipx, izole)"
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
for app in certipy-ad impacket coercer bloodyAD bloodhound-ce; do
  pipx install --force "$app" 2>/dev/null || pipx install "$app" || FAILED+=("pipx:$app")
done
pipx ensurepath >/dev/null 2>&1 || true
# netexec: apt above is the supported path; only if that failed, build from git (never from PyPI).
if ! command -v nxc >/dev/null 2>&1 && ! command -v netexec >/dev/null 2>&1; then
  echo "  [i] netexec apt'tan gelmedi, git'ten deneniyor..."
  pipx install git+https://github.com/Pennyw0rth/NetExec 2>/dev/null || FAILED+=("netexec (apt+git)")
fi

echo "[3/4] PARSDX python kutuphaneleri (izole venv; sistem python'una dokunmaz)"
# No --break-system-packages: it can break the box's Python. Use a dedicated venv.
# These libs are OPTIONAL — guard falls back to an nxc bind if ldap3 is absent, score has its own
# CVSS engine, attck works without mitreattack-python. So this step is best-effort.
if [[ -f "$HERE/requirements.txt" ]]; then
  python3 -m venv "$HERE/.venv" \
    && "$HERE/.venv/bin/pip" install -q --disable-pip-version-check -r "$HERE/requirements.txt" \
    || FAILED+=("venv:requirements (optional — tools degrade gracefully)")
fi

echo "[4/4] Dogrulama"
declare -A CHECK=(
  [nxc]="netexec nxc" [certipy]="certipy certipy-ad"
  [bloodhound-python]="bloodhound-python bloodhound-ce-python"
  [GetUserSPNs]="impacket-GetUserSPNs GetUserSPNs.py"
  [GetNPUsers]="impacket-GetNPUsers GetNPUsers.py"
  [secretsdump]="impacket-secretsdump secretsdump.py"
  [coercer]="coercer Coercer" [bloodyAD]="bloodyAD"
  [responder]="responder Responder" [hashcat]="hashcat" [ldapsearch]="ldapsearch"
)
missing=0
for key in "${!CHECK[@]}"; do
  found=""
  for name in ${CHECK[$key]}; do command -v "$name" >/dev/null 2>&1 && { found="$name"; break; }; done
  if [[ -n "$found" ]]; then printf '  [OK]      %-18s -> %s\n' "$key" "$found"
  else printf '  [MISSING] %-18s (%s)\n' "$key" "${CHECK[$key]}"; missing=$((missing+1)); fi
done
# These libs live in parsdx-ext/.venv, NOT system python — check the interpreter that actually
# runs our tools, or this always reports a false MISSING.
VENVPY="$HERE/.venv/bin/python"
[ -x "$VENVPY" ] || VENVPY="$(command -v python3)"
echo "  (kontrol eden python: $VENVPY)"
"$VENVPY" - <<'PY' || true
for m in ("ldap3","cvss"):
    try: __import__(m); print(f"  [OK]      py:{m}")
    except Exception: print(f"  [MISSING] py:{m}")
PY

# A present hashcat binary is not a working cracker — check it has a backend device.
if command -v hashcat >/dev/null 2>&1; then
  if hashcat -I 2>&1 | grep -q "compatible platform found"; then
    echo "  [UYARI]   hashcat backend YOK (CPU-only) — hicbir sey kiramaz. john kullanin." >&2
  else
    echo "  [OK]      hashcat backend  -> $(hashcat -I 2>/dev/null | grep -m1 -oP 'Name\.+:\s*\K.*' || echo device)"
  fi
fi

echo
if [[ ${#FAILED[@]} -gt 0 ]]; then printf '[UYARI] Kurulamayanlar: %s\n' "${FAILED[*]}" >&2; fi
if [[ $missing -gt 0 ]]; then
  echo "[UYARI] $missing arac eksik. pipx PATH icin yeni bir shell ac (source ~/.bashrc) ve tekrar dogrula." >&2
else
  echo "[OK] Offensive toolchain hazir. Simdi: python3 parsdx-ext/pipeline.py --run-dir <UBDEN_run> ..."
fi
