#!/bin/bash
set -e

echo "Available Docker containers:"
docker ps
echo "------------------------------------------------------------"

read -p "Enter the CONTAINER ID to inspect: " CONTAINER_ID
echo "------------------------------------------------------------"

# Derive image-safe suffix and export dirs for this run
IMG_RAW=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID" 2>/dev/null || echo "$CONTAINER_ID")
IMG_SAFE=$(echo "$IMG_RAW" | tr '/:@' '___' | sed 's/[^A-Za-z0-9._-]/_/g')
export JARFILES_DIR="/home/rupesh.punna/Prototype/JARFILES_${IMG_SAFE}"
export JARFILES_IMAGE="/home/rupesh.punna/Prototype/JARFILES_${IMG_SAFE}"
export LIBS_DIR="/home/rupesh.punna/Prototype/LIBS_${IMG_SAFE}"
export LIBS_IMAGE="/home/rupesh.punna/Prototype/LIBS_${IMG_SAFE}"
export BINARIES_DIR="/home/rupesh.punna/Prototype/BINARIES_${IMG_SAFE}"
export OUTPUTS_DIR="/home/rupesh.punna/Prototype/outputs_${IMG_SAFE}"
export SYSCALLS_OUTPUT_DIR="/home/rupesh.punna/Prototype/syscalls_output_${IMG_SAFE}"

# Ensure image-scoped outputs directory exists and point generic 'outputs' symlink to it
mkdir -p "$OUTPUTS_DIR"
if [ -L "/home/rupesh.punna/Prototype/outputs" ] || [ -e "/home/rupesh.punna/Prototype/outputs" ]; then
  rm -rf "/home/rupesh.punna/Prototype/outputs"
fi
ln -s "$OUTPUTS_DIR" "/home/rupesh.punna/Prototype/outputs"

echo "============================================================"
echo " STEP 1: Unified Sysdig Capture (Libraries, Binaries, JARs)"
echo "============================================================"
bash /home/rupesh.punna/Prototype/sysdig_unified.sh "$CONTAINER_ID" "120"

echo "============================================================"
echo " STEP 2: Extracting libs from JAR files"
echo "============================================================"
bash /home/rupesh.punna/Prototype/extract_libs_jars.sh "$JARFILES_DIR" "$LIBS_DIR"

echo "============================================================"
echo " Resource Extraction Completed!"
echo " Libraries:   $LIBS_DIR"
echo " JARs:        $JARFILES_DIR"
echo " Binaries:    $BINARIES_DIR"
echo " Outputs:     $OUTPUTS_DIR"
echo "============================================================"

echo "Using image-scoped dirs:"
echo "  JARFILES_DIR        = $JARFILES_DIR"
echo "  JARFILES_IMAGE      = $JARFILES_IMAGE"
echo "  LIBS_DIR            = $LIBS_DIR"
echo "  LIBS_IMAGE          = $LIBS_IMAGE"
echo "  BINARIES_DIR        = $BINARIES_DIR"
echo "  OUTPUTS_DIR         = $OUTPUTS_DIR"
echo "  SYSCALLS_OUTPUT_DIR = $SYSCALLS_OUTPUT_DIR"
echo ""

echo "============================================================"
echo " STEP 3: Running Static Analysis"
echo "============================================================"
bash /home/rupesh.punna/Prototype/run_analysis.sh
