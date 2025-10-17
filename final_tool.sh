#!/bin/bash
set -e

echo "Available Docker containers:"
docker ps
echo "------------------------------------------------------------"

read -p "Enter the CONTAINER ID to inspect: " CONTAINER_ID
echo "------------------------------------------------------------"

echo "============================================================"
echo " STEP 1: Extracting native libraries (.so) from container"
echo "============================================================"
bash /home/rupesh.punna/Prototype/toolchain_libs.sh "$CONTAINER_ID"

echo "============================================================"
echo " STEP 2: Extracting JAR/JMOD/module files + executed binaries"
echo "============================================================"
bash /home/rupesh.punna/Prototype/toolchain_jars_bin.sh "$CONTAINER_ID"


echo "============================================================"
echo " STEP 3: Finds libs from JAR file"
echo "============================================================"
bash /home/rupesh.punna/Prototype/extract_libs_jars.sh

echo "============================================================"
echo " Toolchain run completed!"
echo " Libraries:   /home/rupesh.punna/Prototype/LIBS"
echo " JARs:        /home/rupesh.punna/Prototype/JARFILES"
echo " Binaries:    /home/rupesh.punna/Prototype/BINARIES"
echo "============================================================"
