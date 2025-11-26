#!/bin/bash
#############################################################################
# Script: sysdig_unified.sh
# Description: Unified sysdig capture for libraries, binaries, and JARs
#
# This script captures:
#   - Native libraries (.so files) via open/openat/openat2/mmap
#   - Executables via execve
#   - JAR files via open/openat/openat2
#
# All captured in one sysdig session for efficiency
#
# Usage: ./sysdig_unified.sh <container_id> [duration_seconds]
#############################################################################

CONTAINER_ID="$1"
DURATION="${2:-120}"

if [ -z "$CONTAINER_ID" ]; then
    echo "ERROR: Container ID required"
    echo "Usage: $0 <container_id> [duration_seconds]"
    echo ""
    echo "Example:"
    echo "  $0 elasticsearch 120"
    exit 1
fi

# Get container metadata
CNAME=$(docker inspect -f '{{.Name}}' "$CONTAINER_ID" 2>/dev/null | sed 's/^\///' || echo "$CONTAINER_ID")
CONTPID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER_ID" 2>/dev/null)
IMG_RAW=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID" 2>/dev/null || echo "$CNAME")
IMG_SAFE=$(echo "$IMG_RAW" | tr '/:@' '___' | sed 's/[^A-Za-z0-9._-]/_/g')

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          Unified Sysdig Capture - All Resources             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Container Name: $CNAME"
echo "Container ID:   $CONTAINER_ID"
echo "Container PID:  $CONTPID"
echo "Image:          $IMG_RAW"
echo "IMG_SAFE:       $IMG_SAFE"
echo "Duration:       ${DURATION}s"
echo ""

# Create output directory for sysdig dynamic analysis
SYSDIG_OUTPUT_DIR="sysdig_outputs_${IMG_SAFE}"
mkdir -p "$SYSDIG_OUTPUT_DIR"

# Output files
RAW_OUTPUT="$SYSDIG_OUTPUT_DIR/raw_capture.txt"
LIBS_OUTPUT="$SYSDIG_OUTPUT_DIR/libs_loaded_raw.txt"
BINARIES_OUTPUT="$SYSDIG_OUTPUT_DIR/binaries_${IMG_SAFE}.txt"
JARS_OUTPUT="$SYSDIG_OUTPUT_DIR/jars_${IMG_SAFE}.txt"

echo "Output directory: $SYSDIG_OUTPUT_DIR"
echo ""

# --- STEP 1: Stop container for clean restart ---
echo "[1/5] Stopping container for clean restart..."
docker stop "$CNAME" 2>/dev/null || true
sleep 2

# --- STEP 2: Start unified sysdig monitoring ---
echo "[2/5] Starting unified sysdig capture..."
echo "      Monitoring events: open, openat, openat2, mmap, execve"
echo ""

# Capture 1: Libraries (.so) and JARs (.jar)
# Using timeout instead of -M flag due to issues with --modern-bpf
timeout "$DURATION" sudo sysdig --modern-bpf \
  "container.name=$CNAME and evt.type in (open,openat,openat2,mmap) and (fd.name contains .so or fd.name contains .jar)" \
  -p "%evt.time %evt.type %proc.name %fd.name" \
  > "$RAW_OUTPUT" 2>"${RAW_OUTPUT}.err" &

SYSDIG_PID=$!
echo "      Sysdig PID (libs/jars): $SYSDIG_PID"

# Capture 2: Binary executions
timeout "$DURATION" sudo sysdig --modern-bpf \
  "container.name=$CNAME and evt.type=execve and evt.dir=>" \
  -p "%evt.time %evt.type %proc.name %proc.exe" \
  > "${RAW_OUTPUT}.execve" 2>"${RAW_OUTPUT}.execve.err" &

SYSDIG_EXEC_PID=$!
echo "      Sysdig PID (execve):    $SYSDIG_EXEC_PID"

# Wait for sysdig to initialize
echo "      Waiting for sysdig to initialize (10s)..."
sleep 10

# Verify both sysdig processes are running
SYSDIG_OK=true
if ! kill -0 $SYSDIG_PID 2>/dev/null; then
    echo "      ✗ ERROR: sysdig (libs/jars) failed to start"
    if [ -s "${RAW_OUTPUT}.err" ]; then
        cat "${RAW_OUTPUT}.err"
    fi
    SYSDIG_OK=false
fi

if ! kill -0 $SYSDIG_EXEC_PID 2>/dev/null; then
    echo "      ✗ ERROR: sysdig (execve) failed to start"
    if [ -s "${RAW_OUTPUT}.execve.err" ]; then
        cat "${RAW_OUTPUT}.execve.err"
    fi
    SYSDIG_OK=false
fi

if [ "$SYSDIG_OK" = "false" ]; then
    exit 1
fi

echo "      ✓ Monitoring started successfully"

# --- STEP 3: Start container ---
echo ""
echo "[3/5] Starting container to trigger resource loading..."
docker start "$CNAME"

# Wait for container to be running
timeout 60 bash -c "until docker inspect -f '{{.State.Running}}' '$CNAME' 2>/dev/null | grep -q true; do sleep 1; done" || {
    echo "      ✗ ERROR: Container failed to start within 60 seconds"
    kill $SYSDIG_PID $SYSDIG_EXEC_PID 2>/dev/null || true
    exit 1
}

echo "      ✓ Container started"

# --- STEP 4: Monitor with progress ---
echo ""
echo "[4/5] Capturing events for ${DURATION}s..."
echo -n "      Progress: "

ELAPSED=0
while [ $ELAPSED -lt $DURATION ]; do
    sleep 5
    ELAPSED=$((ELAPSED + 5))

    # Check if sysdig is still running
    if ! kill -0 $SYSDIG_PID 2>/dev/null; then
        echo ""
        echo "      ⚠ Sysdig stopped at ${ELAPSED}s"
        break
    fi

    # Show progress
    if [ $((ELAPSED % 10)) -eq 0 ]; then
        if [ -s "$RAW_OUTPUT" ]; then
            EVENTS=$(wc -l < "$RAW_OUTPUT" 2>/dev/null || echo "0")
            echo -n "${ELAPSED}s(${EVENTS}) "
        else
            echo -n "${ELAPSED}s "
        fi
    else
        echo -n "."
    fi
done

echo ""
echo "      ✓ Capture complete"

# Stop both sysdig processes gracefully
# Note: They should auto-stop due to -M flag, but kill them to be sure
kill $SYSDIG_PID 2>/dev/null || true
kill $SYSDIG_EXEC_PID 2>/dev/null || true

# Wait briefly for processes to flush and exit
sleep 2

# Force kill if still running
kill -9 $SYSDIG_PID 2>/dev/null || true
kill -9 $SYSDIG_EXEC_PID 2>/dev/null || true

# --- STEP 5: Process captured data ---
echo ""
echo "[5/5] Processing captured data..."

if [ ! -s "$RAW_OUTPUT" ] && [ ! -s "${RAW_OUTPUT}.execve" ]; then
    echo "      ✗ ERROR: No data captured!"
    echo ""
    if [ -s "${RAW_OUTPUT}.err" ]; then
        echo "Libs/JARs errors:"
        cat "${RAW_OUTPUT}.err"
    fi
    if [ -s "${RAW_OUTPUT}.execve.err" ]; then
        echo "Execve errors:"
        cat "${RAW_OUTPUT}.execve.err"
    fi
    exit 1
fi

LIBS_JAR_EVENTS=$(wc -l < "$RAW_OUTPUT" 2>/dev/null || echo "0")
EXEC_EVENTS=$(wc -l < "${RAW_OUTPUT}.execve" 2>/dev/null || echo "0")
TOTAL_EVENTS=$((LIBS_JAR_EVENTS + EXEC_EVENTS))
echo "      Total events captured: $TOTAL_EVENTS (libs/jars: $LIBS_JAR_EVENTS, execve: $EXEC_EVENTS)"

# Extract libraries (.so files from open/openat/openat2/mmap)
# Format: timestamp event_type process_name filename fd.name
# For open/mmap events, fd.name (last column) has the library path
echo "      Processing libraries..."
grep -E '\.(so|so\.[0-9]+)' "$RAW_OUTPUT" | \
  grep -E 'open|openat|openat2|mmap' | \
  grep -v '/gconv/' | \
  grep -v '/audit/' | \
  sort -u > "$LIBS_OUTPUT"
LIBS_COUNT=$(wc -l < "$LIBS_OUTPUT")
echo "        ✓ Found $LIBS_COUNT unique libraries"

# Create unique libs list (fd.name is last column for open/mmap events)
awk '{print $NF}' "$LIBS_OUTPUT" | sort -u > "$SYSDIG_OUTPUT_DIR/jni_libs_opened.txt"

# Extract binaries (files from execve events)
# Format from execve capture: timestamp event_type process_name proc.exe
echo "      Processing executables..."
if [ -s "${RAW_OUTPUT}.execve" ]; then
    cat "${RAW_OUTPUT}.execve" | sort -u > "$BINARIES_OUTPUT"
    BINS_COUNT=$(wc -l < "$BINARIES_OUTPUT")
    echo "        ✓ Found $BINS_COUNT executable invocations"

    # Create unique binaries list (column 4 is proc.exe)
    awk '{print $4}' "$BINARIES_OUTPUT" | sort -u > "$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_SAFE}.txt"
    UNIQUE_BINS=$(wc -l < "$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_SAFE}.txt")
    echo "        ✓ $UNIQUE_BINS unique executables"
else
    echo "        ⚠ No executable events captured"
    touch "$BINARIES_OUTPUT"
    touch "$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_SAFE}.txt"
fi

# Extract JAR files (from open/openat/openat2 events)
echo "      Processing JAR files..."
grep '\.jar' "$RAW_OUTPUT" | \
  grep -E 'open|openat|openat2' | \
  sort -u > "$JARS_OUTPUT"
JARS_COUNT=$(wc -l < "$JARS_OUTPUT")
echo "        ✓ Found $JARS_COUNT JAR file accesses"

# Create unique JARs list
awk '{print $NF}' "$JARS_OUTPUT" | sort -u > "$SYSDIG_OUTPUT_DIR/jars_unique_${IMG_SAFE}.txt"
UNIQUE_JARS=$(wc -l < "$SYSDIG_OUTPUT_DIR/jars_unique_${IMG_SAFE}.txt")
echo "        ✓ $UNIQUE_JARS unique JAR files"

# Generate summary files
echo "      Generating summary files..."

# Found methods placeholders (for compatibility)
touch "$SYSDIG_OUTPUT_DIR/found_jni_methods.txt"
touch "$SYSDIG_OUTPUT_DIR/found_jvm_methods.txt"
touch "$SYSDIG_OUTPUT_DIR/found_registered_methods.txt"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                      Capture Summary                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Native Libraries: $LIBS_COUNT events → $LIBS_COUNT unique"
echo "  Executables:      $BINS_COUNT events → $UNIQUE_BINS unique"
echo "  JAR Files:        $JARS_COUNT events → $UNIQUE_JARS unique"
echo ""
echo "  Output directory: $SYSDIG_OUTPUT_DIR/"
echo ""

# --- STEP 6: Extract resources from container ---
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  Extracting Resources                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Create destination directories
LIBS_DIR="LIBS_${IMG_SAFE}"
BINS_DIR="BINARIES_${IMG_SAFE}"
JARS_DIR="JARFILES_${IMG_SAFE}"

mkdir -p "$LIBS_DIR" "$BINS_DIR" "$JARS_DIR"

# Extract libraries
echo "[1/3] Extracting native libraries to $LIBS_DIR/..."
LIB_SUCCESS=0
LIB_FAILED=0

while read -r lib_path; do
    [ -z "$lib_path" ] && continue

    if docker exec "$CONTAINER_ID" test -e "$lib_path" 2>/dev/null; then
        real_path=$(docker exec "$CONTAINER_ID" readlink -f "$lib_path" 2>/dev/null || echo "$lib_path")
        lib_name=$(basename "$real_path")

        if docker cp "$CONTAINER_ID:$real_path" "$LIBS_DIR/" 2>/dev/null; then
            LIB_SUCCESS=$((LIB_SUCCESS + 1))
            [ $((LIB_SUCCESS % 10)) -eq 0 ] && echo "      Copied $LIB_SUCCESS libraries..."
        else
            LIB_FAILED=$((LIB_FAILED + 1))
        fi
    else
        LIB_FAILED=$((LIB_FAILED + 1))
    fi
done < "$SYSDIG_OUTPUT_DIR/jni_libs_opened.txt"

echo "      ✓ Success: $LIB_SUCCESS libraries"
[ $LIB_FAILED -gt 0 ] && echo "      ⚠ Failed: $LIB_FAILED libraries"

# Extract binaries
echo ""
echo "[2/3] Extracting executables to $BINS_DIR/..."
BIN_SUCCESS=0
BIN_FAILED=0

while read -r bin_path; do
    [ -z "$bin_path" ] && continue

    # Skip /proc, /sys, /dev paths
    [[ "$bin_path" =~ ^/(proc|sys|dev)/ ]] && continue

    if docker exec "$CONTAINER_ID" test -e "$bin_path" 2>/dev/null; then
        real_path=$(docker exec "$CONTAINER_ID" readlink -f "$bin_path" 2>/dev/null || echo "$bin_path")
        bin_name=$(basename "$real_path")

        # Only copy if it's actually a file
        if docker exec "$CONTAINER_ID" test -f "$real_path" 2>/dev/null; then
            if docker cp "$CONTAINER_ID:$real_path" "$BINS_DIR/" 2>/dev/null; then
                BIN_SUCCESS=$((BIN_SUCCESS + 1))
                echo "      ✓ $bin_name"
            else
                BIN_FAILED=$((BIN_FAILED + 1))
            fi
        fi
    else
        BIN_FAILED=$((BIN_FAILED + 1))
    fi
done < "$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_SAFE}.txt"

echo "      ✓ Success: $BIN_SUCCESS executables"
[ $BIN_FAILED -gt 0 ] && echo "      ⚠ Failed: $BIN_FAILED executables"

# Extract JARs
echo ""
echo "[3/3] Extracting JAR files to $JARS_DIR/..."
JAR_SUCCESS=0
JAR_FAILED=0

while read -r jar_path; do
    [ -z "$jar_path" ] && continue

    jar_name=$(basename "$jar_path")

    if docker cp "$CONTAINER_ID:$jar_path" "$JARS_DIR/$jar_name" 2>/dev/null; then
        JAR_SUCCESS=$((JAR_SUCCESS + 1))
        [ $((JAR_SUCCESS % 10)) -eq 0 ] && echo "      Copied $JAR_SUCCESS JARs..."
    else
        JAR_FAILED=$((JAR_FAILED + 1))
    fi
done < "$SYSDIG_OUTPUT_DIR/jars_unique_${IMG_SAFE}.txt"

echo "      ✓ Success: $JAR_SUCCESS JARs"
[ $JAR_FAILED -gt 0 ] && echo "      ⚠ Failed: $JAR_FAILED JARs"

# Final summary
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                     Extraction Complete                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Sysdig Outputs:     $SYSDIG_OUTPUT_DIR/"
echo "Native Libraries:   $LIBS_DIR/ ($LIB_SUCCESS files)"
echo "Executables:        $BINS_DIR/ ($BIN_SUCCESS files)"
echo "JAR Files:          $JARS_DIR/ ($JAR_SUCCESS files)"
echo ""
echo "Next step:"
echo "  Run: ./automate_syscall_analysis.sh --img-safe $IMG_SAFE --log"
echo ""
