#!/usr/bin/env bash
# Only the application menu uses this entrypoint: keep the terminal readable.
/usr/local/bin/ubden-cyber "$@"
status=$?
if (( status == 0 )); then
  printf '\n[UBDEN] İşlem tamamlandı. Rapor konumu yukarıdaki son bölümde.\n'
else
  printf '\n[UBDEN] İşlem hata koduyla durdu: %d. Yukarıdaki hata ve rapor yolunu inceleyin.\n' "$status" >&2
fi
if [[ -t 0 ]]; then
  read -r -p 'Pencereyi kapatmak için Enter tuşuna basın... ' _ || true
fi
exit "$status"
