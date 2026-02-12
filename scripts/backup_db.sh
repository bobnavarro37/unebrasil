#!/usr/bin/env bash
set -euo pipefail

ts="$(date +%Y%m%d_%H%M%S)"
outdir="backups"
mkdir -p "$outdir"

dump="$outdir/unebrasil_${ts}.dump"
enc="$dump.enc"
encsha="$outdir/unebrasil_${ts}.enc.SHA256"

echo "== dump: $dump"
docker compose exec -T db pg_dump -U unebrasil -d unebrasil -Fc > "$dump"

echo "== encrypt: $enc"
openssl enc -aes-256-cbc -pbkdf2 -salt -pass file:/home/unebrasil/unebrasil/.backup_pass -in "$dump" -out "$enc"
rm -f "$dump"

echo "== checksum: $encsha"
sha256sum "$enc" | sed "s|  .*|  $(basename "$enc")|" > "$encsha"
(cd "$outdir" && sha256sum -c "$(basename "$encsha")" >/dev/null)

win_root="/mnt/c/Users/Lucifer/Downloads/unebrasil_backups"
if [ -d "/mnt/c/Users/Lucifer/Downloads" ]; then
  win_dst="$win_root/$ts"
  mkdir -p "$win_dst"
  cp -v "$enc" "$encsha" "$win_dst/"
fi

ls -1t "$outdir"/*.dump.enc 2>/dev/null | tail -n +11 | while read -r old; do
  rm -f "$old" "${old%.dump.enc}.enc.SHA256"
done

echo "OK: $enc"
