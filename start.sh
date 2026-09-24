#!/usr/bin/env bash
set -euo pipefail
SCRIPT="$(readlink -f -- "${BASH_SOURCE[0]}")"
BASE="$(cd -- "$(dirname -- "$SCRIPT")" && pwd)"
if [[ $EUID -ne 0 ]]; then
  case "${1:-}" in
    --version|--help|-h|--preview-ui|--report-only|--analyst-review|--ai-review) ;;
    *) exec sudo -- "$SCRIPT" "$@" ;;
  esac
fi
if [[ ! -x "${BASE}/.venv/bin/python" ]]; then
  echo "UBDEN Python ortamı eksik: ${BASE}/.venv/bin/python" >&2
  echo "ZIP'i açtığınız klasörde 'bash install.sh' komutuyla kurulumu yeniden çalıştırın." >&2
  exit 1
fi
exec "${BASE}/.venv/bin/python" "${BASE}/wizard.py" "$@"
