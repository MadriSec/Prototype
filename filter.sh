#!/usr/bin/env bash
set -euo pipefail

IN="${1:-method_syscalls.txt}"
OUT="${2:-filtered_method_syscalls.txt}"

[[ -f "$IN" ]] || { echo "ERROR: input file '$IN' not found." >&2; exit 1; }

# Remove CR if the file might be CRLF, drop NOT_FOUND lines, then drop blanks
sed -e 's/\r$//' \
    -e '/NOT_FOUND_IN_LIBS/d' \
    -e '/^[[:space:]]*$/d' \
    "$IN" > "$OUT"

echo "Wrote $(wc -l < "$OUT") lines to $OUT"
