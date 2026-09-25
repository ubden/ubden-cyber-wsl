"""Refresh public IEEE MAC assignments for offline device inventory.

Downloads only the three IEEE registries. A failed update preserves prior files;
the inventory falls back to Nmap's local prefix database.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import urllib.request

REGISTRIES = {
    "oui.csv": ("https://standards-oui.ieee.org/oui/oui.csv", 6),
    "mam.csv": ("https://standards-oui.ieee.org/oui28/mam.csv", 7),
    "mas.csv": ("https://standards-oui.ieee.org/oui36/oui36.csv", 9),
}
MAX_BYTES = 45_000_000


def refresh(destination: Path, opener=urllib.request.urlopen) -> dict:
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, (url, width) in REGISTRIES.items():
        try:
            with opener(url, timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("dosya boyutu sınırı aşıldı")
            decoded = data.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(decoded))
            if not reader.fieldnames or not {"Assignment", "Organization Name"}.issubset(reader.fieldnames):
                raise ValueError("IEEE CSV sütunları bulunamadı")
            valid = 0
            for row in reader:
                assignment = re.sub("[^0-9A-Fa-f]", "", row.get("Assignment") or "")
                if len(assignment) == width and row.get("Organization Name"):
                    valid += 1
            if valid < 10:
                raise ValueError("IEEE CSV atamaları doğrulanamadı")
            temp = destination / ("." + name + ".pending")
            temp.write_bytes(data)
            temp.replace(destination / name)
            results[name] = {"status": "ok", "assignments": valid,
                             "sha256": hashlib.sha256(data).hexdigest(), "source": url}
        except (OSError, UnicodeError, ValueError, TimeoutError) as exc:
            results[name] = {"status": "unavailable", "reason": type(exc).__name__,
                             "cached": (destination / name).is_file()}
    manifest = destination / "SOURCE_MANIFEST.json"
    temp = destination / ".SOURCE_MANIFEST.pending"
    temp.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(manifest)
    return results


def main():
    parser = argparse.ArgumentParser(description="Resmî IEEE MAC/OUI veri kümelerini yenile")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(refresh(args.destination), ensure_ascii=False))


if __name__ == "__main__":
    main()
