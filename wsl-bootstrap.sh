#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo 'WSL bootstrap root yetkisi gerektirir.' >&2
  exit 1
fi
if [[ "$(. /etc/os-release; echo "$ID")" != kali ]]; then
  echo 'Yalniz kali-linux dagitiminda calisir.' >&2
  exit 1
fi

IFS= read -r user_password || true
if ! id -u ubden >/dev/null 2>&1; then
  if [[ -z $user_password ]]; then
    echo 'Yeni ubden hesabi icin parola alinmadi.' >&2
    exit 1
  fi
  useradd -m -s /bin/bash -G sudo ubden
  printf 'ubden:%s\n' "$user_password" | chpasswd
fi
unset user_password

python3 - <<'PY'
from pathlib import Path
import re

path = Path('/etc/wsl.conf')
source = path.read_text(encoding='utf-8') if path.exists() else ''
if re.search(r'(?im)^\[user\]\s*$', source):
    match = re.search(r'(?ims)^\[user\]\s*$.*?(?=^\[|\Z)', source)
    section = match.group(0)
    if re.search(r'(?im)^\s*default\s*=', section):
        section = re.sub(r'(?im)^\s*default\s*=.*$', 'default=ubden', section)
    else:
        section = section.rstrip() + '\ndefault=ubden\n'
    source = source[:match.start()] + section + source[match.end():]
else:
    source = source.rstrip() + '\n\n[user]\ndefault=ubden\n'
path.write_text(source, encoding='utf-8')
PY

source_dir=$(readlink -f -- "${1:?Kaynak dizin gerekli}")
if [[ ! -f "$source_dir/install.sh" ]]; then
  echo "Kurulum kaynagi bulunamadi: $source_dir" >&2
  exit 1
fi
bash "$source_dir/install.sh" --wsl
