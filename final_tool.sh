#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if SKIP_BYTECODE_ANALYSIS is set - skip directly to mapper
if [ "${SKIP_BYTECODE_ANALYSIS:-0}" = "1" ]; then
    echo "============================================================"
    echo " SKIP_BYTECODE_ANALYSIS=1 - Skipping to mapper stage"
    echo "============================================================"
    echo "Using default paths:"
    echo "  - Native methods: ${SCRIPT_DIR}/native_methods.txt"
    echo "  - LIBS_DIR:       ${LIBS_DIR:-${SCRIPT_DIR}/LIBS}"
    echo "============================================================"

    LIBS_BASE_DIR="${LIBS_IMAGE:-${LIBS_DIR:-${SCRIPT_DIR}/LIBS}}"
    OUTPUTS_BASE_DIR="${OUTPUTS_DIR:-${SCRIPT_DIR}/outputs}"

    echo ""
    echo "============================================================"
    echo " STEP 2: Native mapping and start-function preparation"
    echo "============================================================"
    LIBS_IMAGE="${LIBS_BASE_DIR}" OUTPUTS_DIR="${OUTPUTS_BASE_DIR}" \
      bash "${SCRIPT_DIR}/scripts/prepare_native_mapping.sh"

    echo "============================================================"
    echo " Analysis pipeline completed!"
    echo "============================================================"
    exit 0
fi

echo "Available Docker containers:"
docker ps
echo "------------------------------------------------------------"

read -p "Enter the CONTAINER ID to inspect: " CONTAINER_ID
echo "------------------------------------------------------------"

# Derive image-safe suffix and export dirs for this run
IMG_RAW=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID" 2>/dev/null || echo "$CONTAINER_ID")
IMG_NAME=$(echo "$IMG_RAW" | tr '/:@' '___' | sed 's/[^A-Za-z0-9._-]/_/g')
export IMG_NAME
export JARFILES_DIR="${SCRIPT_DIR}/JARFILES_${IMG_NAME}"
export JARFILES_IMAGE="${SCRIPT_DIR}/JARFILES_${IMG_NAME}"
export LIBS_DIR="${SCRIPT_DIR}/LIBS_${IMG_NAME}"
export LIBS_IMAGE="${SCRIPT_DIR}/LIBS_${IMG_NAME}"
export BINARIES_DIR="${SCRIPT_DIR}/BINARIES_${IMG_NAME}"
export OUTPUTS_DIR="${SCRIPT_DIR}/outputs_${IMG_NAME}"
export RUNTIME_DIR="${SCRIPT_DIR}/RUNTIME_${IMG_NAME}"
export SYSCALLS_OUTPUT_DIR="${SCRIPT_DIR}/syscalls_output_${IMG_NAME}"

# Ensure image-scoped outputs directory exists and point generic 'outputs' symlink to it
mkdir -p "$OUTPUTS_DIR"
if [ -L "${SCRIPT_DIR}/outputs" ] || [ -e "${SCRIPT_DIR}/outputs" ]; then
  rm -rf "${SCRIPT_DIR}/outputs"
fi
ln -s "$OUTPUTS_DIR" "${SCRIPT_DIR}/outputs"

if [ "${SKIP_SYSDIG:-0}" = "1" ]; then
    echo "============================================================"
    echo " STEP 1: SKIPPED (SKIP_SYSDIG=1)"
    echo "============================================================"
    echo "Skipping sysdig capture, JDK extraction, and JAR lib extraction."
    echo "Using existing data in:"
    echo "  LIBS_DIR     = $LIBS_DIR"
    echo "  JARFILES_DIR = $JARFILES_DIR"
    echo "  BINARIES_DIR = $BINARIES_DIR"
else
    echo "============================================================"
    echo " STEP 1: Unified Sysdig Capture (Libraries, Binaries, JARs)"
    echo "============================================================"
    bash "${SCRIPT_DIR}/scripts/sysdig_unified.sh" "$CONTAINER_ID" "120"

    echo "============================================================"
    echo " STEP 1.5: Extracting runtime and JAR native libraries"
    echo "============================================================"
    bash "${SCRIPT_DIR}/scripts/extract_runtime_and_jar_libs.sh" "$CONTAINER_ID"
fi

echo "============================================================"
echo " Resource Extraction Completed!"
echo " Libraries:   $LIBS_DIR"
echo " JARs:        $JARFILES_DIR"
echo " Binaries:    $BINARIES_DIR"
echo " Outputs:     $OUTPUTS_DIR"
echo "============================================================"

# Count extracted resources to determine analysis strategy
JAR_COUNT=$(find "$JARFILES_DIR" -name "*.jar" 2>/dev/null | wc -l)
LIB_COUNT=$(find "$LIBS_DIR" -name "*.so*" 2>/dev/null | wc -l)
BIN_COUNT=$(find "$BINARIES_DIR" -type f 2>/dev/null | wc -l)

echo ""
echo "Resource inventory:"
echo "  JAR files:           $JAR_COUNT"
echo "  Shared libraries:    $LIB_COUNT"
echo "  Executables:         $BIN_COUNT"
echo ""

echo "Using image-scoped dirs:"
echo "  JARFILES_DIR        = $JARFILES_DIR"
echo "  JARFILES_IMAGE      = $JARFILES_IMAGE"
echo "  LIBS_DIR            = $LIBS_DIR"
echo "  LIBS_IMAGE          = $LIBS_IMAGE"
echo "  BINARIES_DIR        = $BINARIES_DIR"
echo "  OUTPUTS_DIR         = $OUTPUTS_DIR"
echo "  SYSCALLS_OUTPUT_DIR = $SYSCALLS_OUTPUT_DIR"
echo ""

# Determine analysis strategy based on available resources
ANALYSIS_MODE=""
if [ "$JAR_COUNT" -gt 0 ]; then
    ANALYSIS_MODE="FULL_BYTECODE"
    echo "Analysis strategy: FULL_BYTECODE (JARs found)"
elif [ "$LIB_COUNT" -gt 0 ]; then
    ANALYSIS_MODE="LIBRARY_SYMBOLS"
    echo "Analysis strategy: LIBRARY_SYMBOLS (No JARs, but libraries found)"
elif [ "$BIN_COUNT" -gt 0 ]; then
    ANALYSIS_MODE="BINARY_ONLY"
    echo "Analysis strategy: BINARY_ONLY (Only executables found)"
else
    echo "ERROR: No resources found for analysis (no JARs, libraries, or binaries)"
    exit 1
fi
echo ""

export ANALYSIS_MODE

echo "============================================================"
echo " STEP 3: Running Static Analysis (Mode: $ANALYSIS_MODE)"
echo "============================================================"
bash "${SCRIPT_DIR}/scripts/run_analysis.sh"

echo ""
echo "============================================================"
echo " STEP 4: Organizing results into results/${IMG_NAME}/"
echo "============================================================"

# RESULTS_DIR="${SCRIPT_DIR}/results/${IMG_NAME}"
# mkdir -p "$RESULTS_DIR/Binary_Analysis" \
#          "$RESULTS_DIR/ByteCode_Analysis" \
#          "$RESULTS_DIR/Dynamic_Analysis" \
#          "$RESULTS_DIR/Extracted_Data"

# BASE="${SCRIPT_DIR}"

# # --- Binary_Analysis ---
# for dir in "syscalls_BIN_${IMG_NAME}" "syscalls_LIBS_${IMG_NAME}" "syscalls_output_${IMG_NAME}"; do
#     src="$BASE/$dir"
#     if [ -d "$src" ]; then
#         echo "  Moving $dir → Binary_Analysis/"
#         mv "$src" "$RESULTS_DIR/Binary_Analysis/"
#     fi
# done

# # --- ByteCode_Analysis ---
# src="$BASE/outputs_${IMG_NAME}"
# if [ -d "$src" ] && [ ! -L "$src" ]; then
#     echo "  Moving outputs_${IMG_NAME} → ByteCode_Analysis/"
#     mv "$src" "$RESULTS_DIR/ByteCode_Analysis/"
# elif [ -L "$src" ]; then
#     # outputs_${IMG_NAME} might be the real dir pointed to by the 'outputs' symlink
#     real_src="$(readlink -f "$src")"
#     if [ -d "$real_src" ]; then
#         rm -f "$src"  # remove symlink first
#         echo "  Moving outputs_${IMG_NAME} → ByteCode_Analysis/"
#         mv "$real_src" "$RESULTS_DIR/ByteCode_Analysis/"
#     fi
# fi
# # Clean up the generic 'outputs' symlink if it still exists
# rm -f "$BASE/outputs" 2>/dev/null || true

# # --- Dynamic_Analysis ---
# src="$BASE/sysdig_outputs_${IMG_NAME}"
# if [ -d "$src" ]; then
#     echo "  Moving sysdig_outputs_${IMG_NAME} → Dynamic_Analysis/"
#     mv "$src" "$RESULTS_DIR/Dynamic_Analysis/"
# fi

# # --- Extracted_Data ---
# for dir in "BINARIES_${IMG_NAME}" "JARFILES_${IMG_NAME}" "LIBS_${IMG_NAME}"; do
#     src="$BASE/$dir"
#     if [ -d "$src" ]; then
#         echo "  Moving $dir → Extracted_Data/"
#         mv "$src" "$RESULTS_DIR/Extracted_Data/"
#     fi
# done

# echo ""
# echo "============================================================"
# echo " Final Tool Analysis Complete!"
# echo "============================================================"
# echo "Results organized in: $RESULTS_DIR/"
# echo ""
# echo "  Binary_Analysis/"
# ls -1d "$RESULTS_DIR/Binary_Analysis"/*/ 2>/dev/null | xargs -I{} basename {} | sed 's/^/    /'
# echo "  ByteCode_Analysis/"
# ls -1d "$RESULTS_DIR/ByteCode_Analysis"/*/ 2>/dev/null | xargs -I{} basename {} | sed 's/^/    /'
# echo "  Dynamic_Analysis/"
# ls -1d "$RESULTS_DIR/Dynamic_Analysis"/*/ 2>/dev/null | xargs -I{} basename {} | sed 's/^/    /'
# echo "  Extracted_Data/"
# ls -1d "$RESULTS_DIR/Extracted_Data"/*/ 2>/dev/null | xargs -I{} basename {} | sed 's/^/    /'
# echo "============================================================"
