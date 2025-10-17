#!/bin/bash
set -e  # stop if any command fails

echo "============================================================"
echo " STEP 1: Running bytecode analysis with SOOTUP"
echo "============================================================"
sudo mvn exec:java \
  -Dexec.mainClass="com.echotrace.app.bytecode_new.PrintDFS" \
  -Dexec.args="/home/rupesh.punna/Prototype/TARGET/ /home/rupesh.punna/Prototype/JARFILES --4"

echo "============================================================"
echo " STEP 2: Running formatter.py"
echo "============================================================"
# python3 /home/rupesh.punna/Prototype/formatter.py

echo "============================================================"
echo " STEP 3: Running mapper.py"
echo "============================================================"
python3 /home/rupesh.punna/Prototype/mapper.py

echo "============================================================"
echo " STEP 4: Running filter.sh"
echo "============================================================"
bash /home/rupesh.punna/Prototype/filter.sh

python3 change_format.py filtered_method_syscalls.txt
echo "============================================================"
echo " Analysis pipeline completed!"
echo "============================================================"
