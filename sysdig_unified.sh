#!/bin/bash
#############################################################################
# Script: sysdig_unified.sh
# Description: Unified sysdig capture for libraries, binaries, and JARs
#
# Captures in two parallel sysdig sessions
#   - Capture 1: .so libs + .jar files  via open/openat/openat2/mmap
#   - Capture 2: executables            via execve
#
# Usage: ./sysdig_unified.sh <container_id> [duration_seconds]
#############################################################################

# -u: treat unset variables as errors
# -o pipefail: return the exit code of the first failing command in a pipeline
# NOTE: -e (errexit) is intentionally omitted because some commands (e.g. kill, docker stop)
# return non-zero when processes are already dead, and we handle those explicitly.
set -uo pipefail

# ${1:?msg} expands $1 or exits with "msg" if unset/empty — acts as a required-arg guard
CONTAINER_ID="${1:?ERROR: Container ID required. Usage: $0 <container_id> [duration_seconds]}"
# Default capture duration: 120 seconds (override with second positional argument)
DURATION="${2:-120}"


# Resolve a path inside the container, following symlinks
container_realpath() { docker exec "$CONTAINER_ID" readlink -f "$1" 2>/dev/null || echo "$1"; }

# Copy a file out of the container; return 1 on failure
container_cp() {
    local src="$1" dest_dir="$2"
    local real
    real=$(container_realpath "$src")
    docker exec "$CONTAINER_ID" test -f "$real" 2>/dev/null && \
        docker cp "$CONTAINER_ID:$real" "$dest_dir/" 2>/dev/null
}

# Print a section header
header() { printf '\n=== %s ===\n' "$*"; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# docker inspect returns "/name" with a leading slash — strip it for use in sysdig filters
CNAME=$(docker inspect -f '{{.Name}}' "$CONTAINER_ID" 2>/dev/null | sed 's/^\///')
IMG_RAW=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID" 2>/dev/null)
# Sanitize image name for use as a filesystem-safe directory suffix
# e.g. "docker.io/library/cassandra:5.0" → "docker.io_library_cassandra_5.0"
IMG_SAFE=$(echo "$IMG_RAW" | tr '/:@' '___' | sed 's/[^A-Za-z0-9._-]/_/g')

OUT_DIR="sysdig_outputs_${IMG_SAFE}"
LIBS_DIR="LIBS_${IMG_SAFE}"
BINS_DIR="BINARIES_${IMG_SAFE}"
JARS_DIR="JARFILES_${IMG_SAFE}"
mkdir -p "$OUT_DIR" "$LIBS_DIR" "$BINS_DIR" "$JARS_DIR"

RAW_OPEN="${OUT_DIR}/raw_open.txt"    # open/mmap events (libs + JARs)
RAW_EXEC="${OUT_DIR}/raw_execve.txt"  # execve events

printf 'Container : %s\nImage     : %s\nDuration  : %ss\nOutput    : %s/\n' \
    "$CNAME" "$IMG_RAW" "$DURATION" "$OUT_DIR"

# ---------------------------------------------------------------------------
# 1. Stop container for clean-start capture
# ---------------------------------------------------------------------------

header "1/5  Stopping container"
docker stop "$CNAME" 2>/dev/null || true
sleep 2

# ---------------------------------------------------------------------------
# 2. Launch both sysdig probes
# ---------------------------------------------------------------------------

header "2/5  Starting sysdig probes"


# Sysdig filter for Probe 1: capture all successful file-open and memory-map events
# that touch shared libraries (.so) or JAR files inside this container.
# - open/openat/openat2: regular file opens (openat2 is the newer kernel variant)
# - mmap: catches libs loaded via mmap (e.g. dlopen → mmap)
# - evt.failed=false: drop EACCES / ENOENT noise from library search paths
FILTER_OPEN="container.name=$CNAME and evt.type in (open,openat,openat2,mmap) and evt.failed=false and (fd.name contains .so or fd.name contains .jar)"
# Sysdig filter for Probe 2: capture all execve calls in the container
# (execve replaces process image, so fd.name is N/A — we use proc.exe instead)
FILTER_EXEC="container.name=$CNAME and evt.type=execve"

# Probe 1: file opens — .so libs and JARs
# evt.failed=false filters out permission-denied noise
# --modern-bpf uses CO-RE eBPF (no kernel headers needed, faster attach)
# -p: output format — fields are space-separated:
#   $1=time  $2=evt.type  $3=pid  $4=proc.name  $5=fd.name  $6=fd.typechar
# Runs in background (&) so we can start the execve probe in parallel
timeout "$DURATION" sudo sysdig --modern-bpf \
    "$FILTER_OPEN" \
    -p "%evt.time %evt.type %proc.pid %proc.name %fd.name %fd.typechar" \
    >"$RAW_OPEN" 2>"${RAW_OPEN}.err" &
PID_OPEN=$!  # save PID for health-check and cleanup

# Probe 2: execve — kept separate because execve replaces the process image,
# so fd.name is unavailable; proc.exe must be used instead (see README)
timeout "$DURATION" sudo sysdig --modern-bpf \
    "$FILTER_EXEC" \
    -p "%evt.time %evt.type %proc.name %proc.exe" \
    >"$RAW_EXEC" 2>"${RAW_EXEC}.err" &
PID_EXEC=$!  # save PID for health-check and cleanup

# Wait for eBPF programs to compile and attach before starting the container.
# JVM startup happens in the first ~500ms — missing that window loses the most
# interesting class-loader and JNI library events.
echo "Waiting 5s for BPF probes to attach..."
sleep 5

# Bail out early if either probe failed to start
# kill -0 checks if the process exists without sending a signal
for pid in $PID_OPEN $PID_EXEC; do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "ERROR: sysdig probe (PID $pid) failed to start"
        cat "${RAW_OPEN}.err" "${RAW_EXEC}.err" 2>/dev/null
        exit 1
    fi
done
echo "Both probes running (PIDs: $PID_OPEN, $PID_EXEC)"

# ---------------------------------------------------------------------------
# 3. Start container
# ---------------------------------------------------------------------------

header "3/5  Starting container"
docker start "$CNAME"
# Poll every 1s (up to 60s) until Docker reports the container state as "running".
# If it doesn't come up in time, kill the sysdig probes and abort.
timeout 60 bash -c \
    "until docker inspect -f '{{.State.Running}}' '$CNAME' 2>/dev/null | grep -q true; do sleep 1; done" \
    || { echo "ERROR: container did not start within 60s"; kill $PID_OPEN $PID_EXEC 2>/dev/null || true; exit 1; }
echo "Container running"

# ---------------------------------------------------------------------------
# 4. Wait for capture to finish
# ---------------------------------------------------------------------------

header "4/5  Capturing for ${DURATION}s"
# Progress loop: print event counts every 10s, break early if probe dies
elapsed=0
while [[ $elapsed -lt $DURATION ]]; do
    sleep 10
    elapsed=$((elapsed + 10))
    kill -0 $PID_OPEN 2>/dev/null || { echo "Probe stopped at ${elapsed}s"; break; }
    printf '  %3ds  open/mmap: %d  execve: %d\n' \
        "$elapsed" \
        "$(wc -l <"$RAW_OPEN" 2>/dev/null || echo 0)" \
        "$(wc -l <"$RAW_EXEC"  2>/dev/null || echo 0)"
done

# Graceful shutdown, then force-kill if still alive
kill $PID_OPEN $PID_EXEC 2>/dev/null || true
sleep 2
kill -9 $PID_OPEN $PID_EXEC 2>/dev/null || true

# -s tests if file exists AND is non-empty; abort if both captures are blank
[[ -s "$RAW_OPEN" || -s "$RAW_EXEC" ]] \
    || { echo "ERROR: no events captured"; cat "${RAW_OPEN}.err" "${RAW_EXEC}.err" 2>/dev/null; exit 1; }

# ---------------------------------------------------------------------------
# 5. Parse and deduplicate
# ---------------------------------------------------------------------------

header "5/5  Parsing events"

# --- Libraries (.so) -------------------------------------------------------
# Exclude noise: locale converters, audit hooks, kernel pseudo-paths, ldconfig
UNIQUE_LIBS="${OUT_DIR}/libs_unique.txt"
# -a: treat binary data as text (sysdig output may contain stray bytes)
# First grep: match .so or .so.N (versioned shared libs)
# Second grep -v: exclude noise paths (locale gconv, audit modules, kernel pseudo-fs, ldconfig cache)
# awk $5: fd.name is the 5th space-separated field in our -p format
grep -a -E '\.(so|so\.[0-9]+)' "$RAW_OPEN" \
    | grep -avE '(/gconv/|/audit/|/proc/|/sys/|\.so\.conf)' \
    | awk '{print $5}' \
    | sort -u >"$UNIQUE_LIBS"
echo "  Libraries : $(wc -l <"$UNIQUE_LIBS") unique paths"

# PID → process → library mapping (useful for JNI attribution)
# Format: PID<tab>proc.name<tab>fd.name — shows which process loaded which .so
grep -a -E '\.(so|so\.[0-9]+)' "$RAW_OPEN" \
    | awk '{print $3"\t"$4"\t"$5}' \
    | sort -u >"${OUT_DIR}/libs_by_pid.txt"

# --- JAR files -------------------------------------------------------------
UNIQUE_JARS="${OUT_DIR}/jars_unique.txt"
grep -a '\.jar' "$RAW_OPEN" \
    | awk '{print $5}' \
    | sort -u >"$UNIQUE_JARS"
echo "  JARs      : $(wc -l <"$UNIQUE_JARS") unique paths"

# --- Executables -----------------------------------------------------------
UNIQUE_BINS="${OUT_DIR}/bins_unique.txt"

grep -a '^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.' "$RAW_EXEC" \
    | awk '{print $4}' \
    | grep -avE '^$|[0-9]:[0-9]|execve' \
    | sort -u >"$UNIQUE_BINS"
echo "  Executables: $(wc -l <"$UNIQUE_BINS") unique paths"

# Resolve relative binary paths: try container first, then host PATH
RESOLVED_BINS="${OUT_DIR}/bins_resolved.txt"
HOST_BINS="${OUT_DIR}/bins_host.txt"    # binaries found on host but NOT in container (e.g. runc)
>"$RESOLVED_BINS"; >"$HOST_BINS"       # truncate both files

# Resolve each binary path: absolute paths pass through, relative ones are
# looked up first in the container (command -v) then on the host (which).
while read -r p; do
    [[ -z "$p" || "$p" =~ ^/(proc|sys|dev)/ ]] && continue  # skip pseudo-filesystems
    if [[ "$p" =~ ^/ ]]; then
        echo "$p" >>"$RESOLVED_BINS"
    else
        resolved=$(docker exec "$CONTAINER_ID" sh -c "command -v $p" 2>/dev/null \
                   || which "$p" 2>/dev/null || true)
        if [[ -n "$resolved" ]]; then
            echo "$resolved" >>"$RESOLVED_BINS"
            # Track host-only binaries (runc, containerd, etc.)
            if [[ -f "$resolved" ]] && ! docker exec "$CONTAINER_ID" test -e "$resolved" 2>/dev/null; then
                echo "$resolved" >>"$HOST_BINS"
            fi
        else
            echo "$p" >>"$RESOLVED_BINS"  # keep unresolved — appears in failed list
        fi
    fi
done <"$UNIQUE_BINS"

# ---------------------------------------------------------------------------
# 6. Extract files from container
# ---------------------------------------------------------------------------

# Generic extractor: reads a list of paths, copies each to dest_dir.
# Single summary line printed; failures logged to fail_log.
extract_files() {
    local label="$1" paths_file="$2" dest_dir="$3" fail_log="$4"
    local ok=0 fail=0
    >"$fail_log"  # truncate failure log
    while read -r path; do
        [[ -z "$path" || "$path" =~ ^/(proc|sys|dev)/ ]] && continue
        # Try container first; fall back to host copy for host-only binaries
        if container_cp "$path" "$dest_dir"; then
            ok=$((ok+1))
        elif [[ -f "$path" ]] && cp "$path" "$dest_dir/" 2>/dev/null; then
            # Fallback: binary lives on the host (e.g. runc, containerd-shim)
            ok=$((ok+1))
        else
            fail=$((fail+1))
            echo "$path" >>"$fail_log"
        fi
    done <"$paths_file"
    printf '  %-14s copied: %d  failed: %d\n' "$label" "$ok" "$fail"
    [[ $fail -gt 0 ]] && echo "    → see $fail_log"
}

echo ""
extract_files "Libraries"   "$UNIQUE_LIBS"   "$LIBS_DIR" "${OUT_DIR}/failed_libs.txt"
extract_files "JARs"        "$UNIQUE_JARS"   "$JARS_DIR" "${OUT_DIR}/failed_jars.txt"
extract_files "Executables" "$RESOLVED_BINS" "$BINS_DIR" "${OUT_DIR}/failed_bins.txt"

# --- NSS libraries ---------------------------------------------------------
# libnss_*.so (dns, files, compat, etc.) and libresolv.so are loaded  by
# glibc via dlopen() 

echo ""
nss_ok=0
# Check both x86_64 and aarch64 library paths (covers most container base images)
for dir in /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib64 /usr/lib64 \
           /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu; do
    docker exec "$CONTAINER_ID" test -d "$dir" 2>/dev/null || continue
    while read -r lib; do
        [[ -z "$lib" ]] && continue
        real=$(container_realpath "$dir/$lib")
        dest="$LIBS_DIR/$(basename "$real")"
        [[ -f "$dest" ]] && continue  # already copied by the main extract_files pass
        if docker cp "$CONTAINER_ID:$real" "$LIBS_DIR/" 2>/dev/null; then
            nss_ok=$((nss_ok+1))
            # Preserve symlink name alongside the real filename
            [[ "$(basename "$real")" != "$lib" && ! -f "$LIBS_DIR/$lib" ]] && \
                ln -sf "$(basename "$real")" "$LIBS_DIR/$lib" 2>/dev/null || true
        fi
    done < <(docker exec "$CONTAINER_ID" sh -c "ls $dir 2>/dev/null | grep -E '^lib(nss_|resolv)'" 2>/dev/null || true)
done
printf '  %-14s copied: %d\n' "NSS libs" "$nss_ok"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf '\n%-20s %s\n' "Sysdig events:" "$OUT_DIR/"
printf '%-20s %s\n'   "Native libraries:" "$LIBS_DIR/"
printf '%-20s %s\n'   "JAR files:"        "$JARS_DIR/"
printf '%-20s %s\n'   "Executables:"      "$BINS_DIR/"
printf '\nNext: ./automate_syscall_analysis.sh --img-safe %s --log\n' "$IMG_SAFE"
