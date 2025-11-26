#!/usr/bin/env bash
#
# Extract Linux-native shared libraries from a directory of JARs into a LIBS folder.
#
# What this script does:
#   - Scans each JAR in SRC for candidate native entries (*.so, *.so.*) matching the
#     current CPU architecture and skipping non-Linux OS artifacts.
#   - Extracts candidate .so files to a temp directory, then verifies they are usable
#     on this system (ELF for our arch, right loader/libc), and finally moves valid
#     ones into DEST.
#
# Inputs (positional, optional):
#   1) SRC  - Directory containing JARs to scan (default: /home/rupesh.punna/Prototype/JARFILES)
#   2) DEST - Output directory to place extracted .so files (default: /home/rupesh.punna/Prototype/LIBS)
#
# Exit behavior:
#   - Stops on error due to `set -euo pipefail`. We use `|| true` on non-critical steps.
set -euo pipefail

# Usage: ./extract_linux_natives.sh [SRC] [DEST]
# Allow override via environment vars JARFILES_DIR, JARFILES_IMAGE, LIBS_DIR, or LIBS_IMAGE
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DEFAULT="${SCRIPT_DIR}/JARFILES"
DEST_DEFAULT="${SCRIPT_DIR}/LIBS"
# Prefer image-scoped vars, then regular vars, then defaults
SRC="${1:-${JARFILES_IMAGE:-${JARFILES_DIR:-$SRC_DEFAULT}}}"
DEST="${2:-${LIBS_IMAGE:-${LIBS_DIR:-$DEST_DEFAULT}}}"

mkdir -p "$DEST" "$DEST/.tmp"

# Validate source directory
if [ ! -d "$SRC" ]; then
  echo "ERROR: Source directory does not exist: $SRC" >&2
  echo "Usage: $0 [JAR_DIR] [LIBS_DIR]" >&2
  echo "Or set: JARFILES_IMAGE, JARFILES_DIR, LIBS_IMAGE, or LIBS_DIR" >&2
  exit 1
fi

# Check if any JAR files exist
JAR_COUNT=$(find "$SRC" -maxdepth 1 -name "*.jar" 2>/dev/null | wc -l)
if [ "$JAR_COUNT" -eq 0 ]; then
  echo "WARNING: No JAR files found in: $SRC" >&2
  echo "This script is typically run from final_tool.sh with image-scoped directories." >&2
  echo "If running standalone, ensure JARFILES_IMAGE or JARFILES_DIR points to a directory with JARs." >&2
  exit 0
fi

echo "Scanning $JAR_COUNT JAR file(s) in: $SRC"
echo "Extracting to: $DEST"
echo ""

# --- Arch regex for jar paths ---
# Many projects encode architecture in the path under native/ or META-INF. 
case "$(uname -m)" in
  x86_64|amd64)   ARCH_RE='x86_64|x86-64|amd64|linux-x86_64|linux-x86-64' ;;
  aarch64|arm64)  ARCH_RE='aarch64|aarch_64|arm64|linux-aarch64|linux-aarch_64' ;;
  ppc64le)        ARCH_RE='ppc64le' ;;
  *)              ARCH_RE='x86_64|x86-64|amd64' ;;
esac

# --- Non-Linux OS tags to skip outright ---
# Ignore entries clearly intended for other operating systems.
BAD_OS_RE='darwin|osx|mac|win|windows|sunos|solaris|freebsd|openbsd|netbsd|aix|dragonfly|android'

# --- libc kind (glibc vs musl) for validation ---
# We differentiate loader/libc expectations so we don't accept binaries for the wrong libc.
LIBC_KIND="glibc"
if ldd --version 2>&1 | grep -qi musl; then LIBC_KIND="musl"; fi

# Lightweight validation of extracted .so candidates.
# Returns 0 only if the file looks runnable on this system.
verify_so() {
  local f="$1"

  # Must be ELF for our arch
  if ! file -b "$f" | grep -qiE "ELF .* (x86-64|$(uname -m))"; then
    return 1
  fi

  # Reject obvious non-Linux deps early (FreeBSD/Solaris)
  if objdump -p "$f" 2>/dev/null | grep -qiE 'NEEDED.*(libc\.so\.7|libthr\.so\.3|libdl\.so\.1)'; then
    return 1
  fi

  # Validate loader/libc - accept if it's a valid shared library
  # Shared libraries don't always have INTERP sections, and may not explicitly list libc.so.6
  # So we just check that it doesn't have non-Linux dependencies (already checked above)
  # and that it's a valid ELF shared object (already checked by file command)
  # For glibc systems, check that it doesn't have musl-specific deps
  if [[ "$LIBC_KIND" == "glibc" ]]; then
    # Reject musl-specific dependencies
    if objdump -p "$f" 2>/dev/null | grep -qiE 'NEEDED.*libc\.musl|INTERP.*/ld-musl-'; then
      return 1
    fi
    # Accept if it's a valid shared library (no explicit libc.so.6 requirement)
    return 0
  else
    # For musl, check for musl-specific loader
    objdump -p "$f" 2>/dev/null | grep -qiE 'INTERP.*/ld-musl-.*\.so'
  fi
}

shopt -s nullglob
ok=0 skipped=0

for jar in "$SRC"/*.jar; do
  echo "==> Scanning: $jar"
  # Convert jar path to absolute path for extraction (needed when we cd into temp dir)
  if [[ "$jar" = /* ]]; then
    JAR_ABS="$jar"
  else
    JAR_ABS="$(cd "$(dirname "$jar")" && pwd)/$(basename "$jar")"
  fi
  while IFS= read -r entry; do
    # ---- CHANGED: broaden matching; no "linux" requirement ----
    # accept .so and .so.* entries; many jars don't include "linux" in the path
    [[ "$entry" =~ \.so($|\.)                     ]] || continue
    
    # Check architecture in both full path and basename (for files like META-INF/native/libfoo_x86_64.so)
    base_name=$(basename "$entry")
    if [[ ! "$entry" =~ ($ARCH_RE) ]] && [[ ! "$base_name" =~ ($ARCH_RE) ]]; then
      continue
    fi
    
    # Skip non-Linux OS entries
    [[ ! "$entry" =~ ($BAD_OS_RE)                  ]] || continue

    base="$(basename "$entry")"
    out="$DEST/.tmp/$base"
    if [[ -e "$out" ]]; then
      bn="${base%.*}" ext="${base##*.}"
      out="$DEST/.tmp/${bn}_$(basename "$jar" .jar).${ext}"
    fi

    # Extract using jar (extract to temp dir, then copy the file)
    TEMP_EXTRACT_DIR=$(mktemp -d)
    if (cd "$TEMP_EXTRACT_DIR" && jar xf "$JAR_ABS" "$entry" 2>/dev/null); then
      if [ -f "$TEMP_EXTRACT_DIR/$entry" ]; then
        # Ensure destination directory exists
        mkdir -p "$(dirname "$out")"
        if cp "$TEMP_EXTRACT_DIR/$entry" "$out" 2>/dev/null; then
          echo "    extracted: $entry -> $(basename "$out")"
        else
          echo "    (failed to copy: $entry -> $out)" >&2
          ((skipped++)) || true
        fi
      else
        echo "    (file not found after extraction: $entry)" >&2
        ((skipped++)) || true
      fi
    else
      echo "    (could not extract: $entry)" >&2
      ((skipped++)) || true
    fi
    rm -rf "$TEMP_EXTRACT_DIR"
  done < <(jar -tf "$JAR_ABS" 2>/dev/null || true)
done

# Validate and move only the good ones into DEST root
shopt -s nullglob
for f in "$DEST/.tmp"/*.so*; do
  if verify_so "$f"; then
    target="$DEST/$(basename "$f")"
    if [[ -e "$target" ]]; then
      mv -f "$f" "$DEST/"
    else
      mv -f "$f" "$target"
    fi
    ((ok++)) || true
  else
    rm -f "$f"
    ((skipped++)) || true
  fi
done

rmdir "$DEST/.tmp" 2>/dev/null || true

echo
echo "Linux natives are in: $DEST"
echo "OK: $ok   SKIPPED: $skipped"
