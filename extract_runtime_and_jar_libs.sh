#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <container_id_or_name>" >&2
  echo "Required env: IMG_SAFE" >&2
  exit 1
fi

CONTAINER_ID="$1"

if [ -z "${IMG_SAFE:-}" ]; then
  echo "ERROR: IMG_SAFE is required" >&2
  exit 1
fi

JARFILES_DIR="${JARFILES_DIR:-${SCRIPT_DIR}/JARFILES_${IMG_SAFE}}"
LIBS_DIR="${LIBS_DIR:-${SCRIPT_DIR}/LIBS_${IMG_SAFE}}"
RUNTIME_DIR="${RUNTIME_DIR:-${SCRIPT_DIR}/RUNTIME_${IMG_SAFE}}"

mkdir -p "$JARFILES_DIR" "$LIBS_DIR" "$RUNTIME_DIR"

echo "============================================================"
echo " Extracting container JDK runtime and native libraries"
echo "============================================================"
echo "Container:           $CONTAINER_ID"
echo "Runtime destination: $RUNTIME_DIR"
echo "LIB destination:     $LIBS_DIR"

python3 "${SCRIPT_DIR}/scripts/extract_container_jdk.py" \
  "$CONTAINER_ID" \
  --libs \
  --force \
  --out-name "$IMG_SAFE" \
  --runtime-dir "$RUNTIME_DIR" \
  --libs-dir "$LIBS_DIR"

echo "============================================================"
echo " Deduplicating JARFILES vs RUNTIME"
echo "============================================================"
echo "Removing JARs from $JARFILES_DIR that already exist in $RUNTIME_DIR"

DEDUP_REMOVED=0
if [ -d "$RUNTIME_DIR" ] && [ -d "$JARFILES_DIR" ]; then
  for runtime_jar in "$RUNTIME_DIR"/*.jar; do
    [ -f "$runtime_jar" ] || continue
    jar_name="$(basename "$runtime_jar")"
    if [ -f "$JARFILES_DIR/$jar_name" ]; then
      rm -f "$JARFILES_DIR/$jar_name"
      DEDUP_REMOVED=$((DEDUP_REMOVED + 1))
    fi
  done
  echo "Removed $DEDUP_REMOVED duplicate JAR(s) from JARFILES_DIR"
else
  echo "Skipped deduplication: RUNTIME_DIR or JARFILES_DIR does not exist"
fi

echo "============================================================"
echo " Extracting native libraries from JAR files"
echo "============================================================"
echo "JAR source:      $JARFILES_DIR"
echo "LIB destination: $LIBS_DIR"

bash "${SCRIPT_DIR}/extract_libs_jars.sh" "$JARFILES_DIR" "$LIBS_DIR"

