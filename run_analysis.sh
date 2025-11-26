#!/bin/bash
set -e  # stop if any command fails

echo "============================================================"
echo " STEP 1: Running bytecode analysis with SOOTUP"
echo "============================================================"
JAR_BASE_DIR="${JARFILES_DIR:-/home/rupesh.punna/Prototype/JARFILES}"
sudo mvn exec:java \
  -Dexec.mainClass="com.echotrace.app.bytecode_new.PrintDFS" \
  -Dexec.args="/home/rupesh.punna/Prototype/TARGET/ ${JAR_BASE_DIR} --4"

# echo "============================================================"
# echo " STEP 2: Running formatter.py"
# echo "============================================================"
# python3 /home/rupesh.punna/Prototype/formatter.py

echo "============================================================"
echo " STEP 2: Running mapper.py"
echo "============================================================"
# Ensure mapper points to image-scoped libs; allow overriding METHODS_FILE
LIBS_BASE_DIR="${LIBS_IMAGE:-${LIBS_DIR:-/home/rupesh.punna/Prototype/LIBS}}"
METHODS_FILE_PATH="${METHODS_FILE:-/home/rupesh.punna/Prototype/formatted_methods.txt}"
OUTPUTS_BASE_DIR="${OUTPUTS_DIR:-/home/rupesh.punna/Prototype/outputs}"
echo "Using LIBS_DIR       = ${LIBS_BASE_DIR}"
echo "Using METHODS_FILE   = ${METHODS_FILE_PATH}"
echo "Using OUTPUTS_DIR    = ${OUTPUTS_BASE_DIR}"
LIBS_IMAGE="${LIBS_BASE_DIR}" LIBS_DIR="${LIBS_BASE_DIR}" METHODS_FILE="${METHODS_FILE_PATH}" OUTPUTS_DIR="${OUTPUTS_BASE_DIR}" \
  python3 /home/rupesh.punna/Prototype/mapper.py

echo "============================================================"
echo " STEP 3: Running filter.sh"
echo "============================================================"
bash /home/rupesh.punna/Prototype/filter.sh


echo "============================================================"
echo " STEP 4: Running change_format.py to change the format of the syscalls"
python3 change_format.py filtered_method_syscalls.txt
echo "============================================================"
echo " Analysis pipeline completed!"
echo "============================================================"
echo " STEP 5 : Running binary_analysis"
LIBS_BASE_DIR="${LIBS_IMAGE:-${LIBS_DIR:-/home/rupesh.punna/Prototype/LIBS}}"
STARTFUNCS_DIR="${OUTPUTS_DIR:-/home/rupesh.punna/Prototype/outputs}"
SYSCALLS_OUT_DIR="${SYSCALLS_OUTPUT_DIR:-/home/rupesh.punna/Prototype/syscalls_output}"
bash /home/rupesh.punna/Prototype/automate_syscall_analysis.sh \
  --binary-dir "${LIBS_BASE_DIR}" \
  --startfunc-dir "${STARTFUNCS_DIR}" \
  --output-dir "${SYSCALLS_OUT_DIR}"
echo "============================================================"
echo " Binary analysis completed!"
echo "============================================================"
echo " STEP 6 : Running combine_syscalls.sh"
bash /home/rupesh.punna/Prototype/combine_syscalls.sh "${SYSCALLS_OUT_DIR}"
echo "============================================================"
