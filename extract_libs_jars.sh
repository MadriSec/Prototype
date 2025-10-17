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
SRC="${1:-/home/rupesh.punna/Prototype/JARFILES}"
DEST="${2:-/home/rupesh.punna/Prototype/LIBS}"

mkdir -p "$DEST" "$DEST/.tmp"

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

  # Validate loader/libc
  if [[ "$LIBC_KIND" == "glibc" ]]; then
    objdump -p "$f" 2>/dev/null | grep -qiE 'NEEDED.*libc\.so\.6|INTERP.*ld-linux.*\.so'
  else
    objdump -p "$f" 2>/dev/null | grep -qiE 'INTERP.*/ld-musl-.*\.so'
  fi
}

shopt -s nullglob
ok=0 skipped=0

for jar in "$SRC"/*.jar; do
  echo "==> Scanning: $jar"
  while IFS= read -r entry; do
    # ---- CHANGED: broaden matching; no "linux" requirement ----
    # accept .so and .so.* entries; many jars don't include "linux" in the path
    [[ "$entry" =~ \.so($|\.)                     ]] || continue
    [[ "$entry" =~ ($ARCH_RE)                      ]] || continue
    [[ ! "$entry" =~ ($BAD_OS_RE)                  ]] || continue

    base="$(basename "$entry")"
    out="$DEST/.tmp/$base"
    if [[ -e "$out" ]]; then
      bn="${base%.*}" ext="${base##*.}"
      out="$DEST/.tmp/${bn}_$(basename "$jar" .jar).${ext}"
    fi

    # Stream-extract only the single entry; avoids creating full trees
    if unzip -p "$jar" "$entry" > "$out" 2>/dev/null; then
      echo "    extracted: $entry -> $(basename "$out")"
    else
      echo "    (could not extract: $entry)"; ((skipped++)) || true
      rm -f "$out"
      continue
    fi
  done < <(unzip -Z1 "$jar" 2>/dev/null || true)
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
