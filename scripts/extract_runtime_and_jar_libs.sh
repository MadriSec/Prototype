#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <container_id_or_name>" >&2
  echo "Required env: IMG_NAME" >&2
  exit 1
fi

CONTAINER_ID="$1"

if [ -z "${IMG_NAME:-}" ]; then
  echo "ERROR: IMG_NAME is required" >&2
  exit 1
fi

JARFILES_DIR="${JARFILES_DIR:-${PROJECT_ROOT}/JARFILES_${IMG_NAME}}"
LIBS_DIR="${LIBS_DIR:-${PROJECT_ROOT}/LIBS_${IMG_NAME}}"
RUNTIME_DIR="${RUNTIME_DIR:-${PROJECT_ROOT}/RUNTIME_${IMG_NAME}}"

mkdir -p "$JARFILES_DIR" "$LIBS_DIR" "$RUNTIME_DIR"

echo "============================================================"
echo " Extracting container JDK runtime and native libraries"
echo "============================================================"
echo "Container:           $CONTAINER_ID"
echo "Runtime destination: $RUNTIME_DIR"
echo "LIB destination:     $LIBS_DIR"

python3 "${SCRIPT_DIR}/extract_container_jdk.py" \
  "$CONTAINER_ID" \
  --libs \
  --force \
  --out-name "$IMG_NAME" \
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


echo "============================================================"
echo " Restoring SONAME symlinks"
echo "============================================================"
# docker cp copies symlink TARGETS, not the symlinks themselves, so a library
# arrives only under its versioned filename (libssl.so.1.1.1zh) while every ELF
# that depends on it records the soname (libssl.so.1.1). SysPart resolves
# DT_NEEDED entries by that soname, finds nothing, and silently emits an empty
# call graph -- the run still exits 0, so the failure is easy to miss.
#
# Recreate each missing link from the library's own SONAME. Existing files and
# links are never replaced, so this is safe to re-run.
echo "LIB directory: $LIBS_DIR"

if [ -d "$LIBS_DIR" ]; then
  LINKS_CREATED=0
  while IFS= read -r lib; do
    soname="$(readelf -d "$lib" 2>/dev/null | sed -n 's/.*soname *: *\[\(.*\)\].*/\1/p')"
    [ -n "$soname" ] || continue
    lib_dir="$(dirname "$lib")"
    lib_base="$(basename "$lib")"
    [ "$soname" = "$lib_base" ] && continue
    [ -e "$lib_dir/$soname" ] && continue
    if ln -s "$lib_base" "$lib_dir/$soname" 2>/dev/null; then
      LINKS_CREATED=$((LINKS_CREATED + 1))
    fi
  done < <(find "$LIBS_DIR" -type f -name "*.so*" 2>/dev/null)
  echo "Created $LINKS_CREATED SONAME symlink(s)"
else
  echo "Skipped: $LIBS_DIR does not exist"
fi
