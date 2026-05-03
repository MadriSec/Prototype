#!/bin/bash
set -e  # stop if any command fails
#IMG_SAFE=cassandra_3.0.29 \
#LIBS_DIR=/home/rupesh.punna/Prototype/LIBS_cassandra_3.0.29 \
#  bash run_analysis.sh
ANALYSIS_MODE="${ANALYSIS_MODE:-FULL_BYTECODE}"

# IMG_SAFE is required — all per-image directories derive from it
if [ -z "${IMG_SAFE:-}" ]; then
    echo "ERROR: IMG_SAFE is required. Example: IMG_SAFE=cassandra_3.0.29 bash run_analysis.sh"
    exit 1
fi

LIBS_BASE_DIR="${LIBS_IMAGE:-${LIBS_DIR:-/home/rupesh.punna/Prototype/LIBS_${IMG_SAFE}}}"
OUTPUTS_BASE_DIR="${OUTPUTS_DIR:-/home/rupesh.punna/Prototype/outputs_${IMG_SAFE}}"
mkdir -p "$OUTPUTS_BASE_DIR"

if [ "$ANALYSIS_MODE" = "FULL_BYTECODE" ]; then
    # Check if we should skip bytecode analysis and go directly to mapper
    if [ "${SKIP_BYTECODE_ANALYSIS:-0}" = "1" ]; then
        echo "============================================================"
        echo " STEP 1: SKIPPED (SKIP_BYTECODE_ANALYSIS=1)"
        echo "============================================================"
        echo "Skipping SOOTUP bytecode analysis, using existing native_methods.txt"
    else
        echo "============================================================"
        echo " STEP 1: Running bytecode analysis"
        echo "============================================================"
        JAR_BASE_DIR="${JARFILES_DIR:-/home/rupesh.punna/Prototype/JARFILES_${IMG_SAFE}}"

        echo "Select bytecode analysis mode:"
        echo "  1) PrototypeFinal  - Include ALL native methods"
        echo "  2) FinalPrototype  - Start from main (reachability analysis)"
        read -p "Enter choice [1/2]: " BYTECODE_MODE

        if [ "$BYTECODE_MODE" = "2" ]; then
            echo "Running FinalPrototype (start from main)..."
            java -cp "target/echotrace-1.0-SNAPSHOT.jar:target/deps/*" \
              com.echotrace.app.bytecode_new.FinalPrototype \
              "${JAR_BASE_DIR}" \
              "${JAR_BASE_DIR}" \
              --1
        else
            echo "Running PrototypeFinal (all native methods)..."
            sudo mvn exec:java \
              -Dexec.mainClass="com.echotrace.app.bytecode_new.PrototypeFinal" \
              -Dexec.args="${JAR_BASE_DIR} ${JAR_BASE_DIR} --1"
        fi
    fi

    # echo "============================================================"
    # echo " STEP 2: Running formatter.py"
    # echo "============================================================"
    # python3 /home/rupesh.punna/Prototype/formatter.py

    echo "============================================================"
    echo " STEP 1.5: JFR RegisterNatives extraction (libjvm.so)"
    echo "============================================================"
    # Find libjvm.so in the LIBS directory and extract JFR RegisterNatives bindings.
    # Output: jfr_extracted_methods.txt (consumed by mapped_updated.py step 1.8)
    LIBJVM_PATH=$(find "${LIBS_BASE_DIR}" -name "libjvm.so" -type f 2>/dev/null | head -1)
    if [ -n "$LIBJVM_PATH" ]; then
        echo "Found libjvm.so: $LIBJVM_PATH"
        JFR_OUTPUT="${OUTPUTS_BASE_DIR}/jfr_extracted_methods.txt"
        if bash /home/rupesh.punna/Prototype/jfr_registernative_mapping.sh "$LIBJVM_PATH" 2>/dev/null; then
            # Move the output to the outputs directory
            if [ -f "jfr_extracted_methods.txt" ]; then
                mv jfr_extracted_methods.txt "$JFR_OUTPUT"
                echo "JFR extraction complete: $JFR_OUTPUT"
                echo "  $(grep -c '→' "$JFR_OUTPUT" 2>/dev/null || echo 0) methods extracted"
            fi
        else
            echo "WARN: JFR extraction failed (non-fatal). JFR methods will fall through to NOT_FOUND."
        fi
    else
        echo "WARN: libjvm.so not found in ${LIBS_BASE_DIR}. Skipping JFR extraction."
    fi

    echo "============================================================"
    echo " STEP 2: Running mapper (mapped_updated.py)"
    echo "============================================================"
    # Ensure mapper points to image-scoped libs; allow overriding METHODS_FILE
    METHODS_FILE_PATH="${METHODS_FILE:-/home/rupesh.punna/Prototype/native_methods.txt}"
    echo "Using LIBS_DIR       = ${LIBS_BASE_DIR}"
    echo "Using METHODS_FILE   = ${METHODS_FILE_PATH}"
    echo "Using OUTPUTS_DIR    = ${OUTPUTS_BASE_DIR}"
    LIBS_IMAGE="${LIBS_BASE_DIR}" LIBS_DIR="${LIBS_BASE_DIR}" METHODS_FILE="${METHODS_FILE_PATH}" OUTPUTS_DIR="${OUTPUTS_BASE_DIR}" \
      python3 /home/rupesh.punna/Prototype/mapped_updated.py

    echo "============================================================"
    echo " STEP 3: Running filter.sh"
    echo "============================================================"
    IMG_SAFE="${IMG_SAFE}" OUTPUTS_DIR="${OUTPUTS_BASE_DIR}" \
      bash /home/rupesh.punna/Prototype/filter.sh

    echo "============================================================"
    echo " STEP 4: Running change_format.py to change the format of the syscalls"
    echo "============================================================"
    IMG_SAFE="${IMG_SAFE}" OUTPUTS_DIR="${OUTPUTS_BASE_DIR}" \
      python3 /home/rupesh.punna/Prototype/change_format.py "${OUTPUTS_BASE_DIR}/filtered_method_syscalls.txt" --sort --uniq
    echo "============================================================"
    echo " Analysis pipeline completed!"
    echo "============================================================"

else
    echo "============================================================"
    echo " Bytecode analysis skipped (Mode: $ANALYSIS_MODE)"
    echo "============================================================"
    echo "Using symbol-based analysis instead of bytecode analysis"
    echo "Starting function file will be used directly for syscall analysis"
    echo "============================================================"
fi
echo "============================================================"
echo " STEP 5: Running binary_analysis"
echo "============================================================"

LIBS_BASE_DIR="${LIBS_IMAGE:-${LIBS_DIR:-/home/rupesh.punna/Prototype/LIBS_${IMG_SAFE}}}"
STARTFUNCS_DIR="${OUTPUTS_DIR:-/home/rupesh.punna/Prototype/outputs_${IMG_SAFE}}"
SYSCALLS_OUT_DIR="${SYSCALLS_OUTPUT_DIR:-/home/rupesh.punna/Prototype/syscalls_output_${IMG_SAFE}}"
BINARIES_BASE_DIR="${BINARIES_DIR:-/home/rupesh.punna/Prototype/BINARIES_${IMG_SAFE}}"

# Determine which binaries to analyze based on mode
if [ "$ANALYSIS_MODE" = "FULL_BYTECODE" ]; then
    # Standard flow: analyze libraries based on mapper.py output
    echo "Analyzing libraries with mapped native methods..."
    bash /home/rupesh.punna/Prototype/automate_syscall_analysis.sh \
      --binary-dir "${LIBS_BASE_DIR}" \
      --startfunc-dir "${STARTFUNCS_DIR}" \
      --output-dir "${SYSCALLS_OUT_DIR}" \
      --img-safe "${IMG_SAFE}" \
      --log

elif [ "$ANALYSIS_MODE" = "LIBRARY_SYMBOLS" ]; then
    # Analyze libraries using extracted exported symbols
    echo "Analyzing libraries with exported symbols..."

    # Create startfunc files for each library based on exported symbols
    mkdir -p "$STARTFUNCS_DIR"

    for lib in "$LIBS_BASE_DIR"/*.so*; do
        [ -f "$lib" ] || continue
        lib_name=$(basename "$lib")
        startfunc_file="$STARTFUNCS_DIR/${lib_name}.txt"

        echo "  Creating startfunc file for: $lib_name"

        # Check if library is stripped
        if file "$lib" | grep -q "stripped"; then
            echo "    Library is stripped"

            # For stripped libraries, try to extract entry point (if it exists)
            entry_point=$(readelf -h "$lib" 2>/dev/null | awk '/Entry point/ {print $4}')

            if [ -n "$entry_point" ] && [ "$entry_point" != "0x0" ]; then
                echo "$entry_point" > "$startfunc_file"
                echo "    Using entry point address: $entry_point"
            else
                # No entry point (typical for .so files) - use exported dynamic symbols
                nm -D --defined-only "$lib" 2>/dev/null | \
                    awk '$2 == "T" || $2 == "W" {print $3}' | \
                    grep -v '^_' | \
                    sort -u > "$startfunc_file"

                sym_count=$(wc -l < "$startfunc_file")
                echo "    Extracted $sym_count exported symbols"
            fi
        else
            echo "    Library is not stripped"

            # Extract exported symbols for this library
            nm -D --defined-only "$lib" 2>/dev/null | \
                awk '$2 == "T" || $2 == "W" {print $3}' | \
                grep -v '^_' | \
                sort -u > "$startfunc_file"

            sym_count=$(wc -l < "$startfunc_file")
            echo "    Extracted $sym_count symbols"
        fi
    done

    bash /home/rupesh.punna/Prototype/automate_syscall_analysis.sh \
      --binary-dir "${LIBS_BASE_DIR}" \
      --startfunc-dir "${STARTFUNCS_DIR}" \
      --output-dir "${SYSCALLS_OUT_DIR}" \
      --img-safe "${IMG_SAFE}" \
      --log

elif [ "$ANALYSIS_MODE" = "BINARY_ONLY" ]; then
    # Analyze only executables using their entry points
    echo "Analyzing binaries with entry points and exported symbols..."

    # Create startfunc files for each binary
    mkdir -p "$STARTFUNCS_DIR"

    for bin in "$BINARIES_BASE_DIR"/*; do
        [ -f "$bin" ] || continue
        bin_name=$(basename "$bin")
        startfunc_file="$STARTFUNCS_DIR/${bin_name}.txt"

        echo "  Creating startfunc file for: $bin_name"

        # Check if binary is stripped
        if file "$bin" | grep -q "stripped"; then
            echo "    Binary is stripped - using entry point address"

            # Extract entry point address from ELF header
            entry_point=$(readelf -h "$bin" 2>/dev/null | awk '/Entry point/ {print $4}')

            if [ -n "$entry_point" ] && [ "$entry_point" != "0x0" ]; then
                echo "$entry_point" > "$startfunc_file"
                echo "    Using entry point address: $entry_point"
            else
                echo "    ERROR: Could not extract valid entry point from $bin_name"
                # Fallback to trying dynamic symbols
                nm -D --defined-only "$bin" 2>/dev/null | \
                    awk '$2 == "T" {print $3}' | \
                    grep -v '^_' | \
                    sort -u > "$startfunc_file"
                sym_count=$(wc -l < "$startfunc_file")
                echo "    Fallback: extracted $sym_count dynamic symbols"
            fi
        else
            # Binary is not stripped - try to use symbol names
            echo "    Binary is not stripped - using symbols"

            if nm "$bin" 2>/dev/null | grep -q " [Tt] _start$"; then
                echo "_start" > "$startfunc_file"
                echo "    Using _start as entry point"
            elif nm "$bin" 2>/dev/null | grep -q " [Tt] main$"; then
                echo "main" > "$startfunc_file"
                echo "    Using main as entry point"
            else
                # Extract all exported symbols
                nm -D --defined-only "$bin" 2>/dev/null | \
                    awk '$2 == "T" {print $3}' | \
                    grep -v '^_' | \
                    sort -u > "$startfunc_file"

                sym_count=$(wc -l < "$startfunc_file")
                echo "    Extracted $sym_count exported symbols"
            fi
        fi
    done

    # Analyze binaries instead of libraries
    bash /home/rupesh.punna/Prototype/automate_syscall_analysis.sh \
      --binary-dir "${BINARIES_BASE_DIR}" \
      --startfunc-dir "${STARTFUNCS_DIR}" \
      --output-dir "${SYSCALLS_OUT_DIR}" \
      --img-safe "${IMG_SAFE}" \
      --log
fi

echo "============================================================"
echo " Binary analysis completed!"
echo "============================================================"
echo " STEP 6: Running combine_syscalls.sh"
# bash /home/rupesh.punna/Prototype/combine_syscalls.sh "${SYSCALLS_OUT_DIR}"
echo "============================================================"
