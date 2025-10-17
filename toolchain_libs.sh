#!/bin/bash

CONTAINER_ID=$1
if [ -z "$CONTAINER_ID" ]; then
  echo "ERROR: Container ID not provided!"
  exit 1
fi

CNAME=$(docker inspect -f '{{.Name}}' "$CONTAINER_ID" | sed 's/^\///')
CONTPID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER_ID")
CG=$(awk -F: '/:\/docker\//{print $3} $0~/0::/{print $3}' /proc/$CONTPID/cgroup | head -1)

echo "Container Name: $CNAME"
echo "Container PID: $CONTPID"
echo "Container cgroup: $CG"
echo "------------------------------------------------------------"

# --- STEP 2: Capture libraries with sysdig ---
echo "Monitoring file open events for native libraries for 60 seconds..."
sudo sysdig --modern-bpf -M 60 \
  "thread.cgroups contains $CG and evt.dir=< and evt.type in (open,openat,openat2) and fd.name contains .so" \
  -p "%evt.time %proc.name %fd.name" | sort -u | tee jni_libs_opened.txt &

SYSDIG_PID=$!
sleep 5

echo "Restarting container '$CNAME' to trigger the loading of all files..."
docker restart "$CNAME"

wait $SYSDIG_PID
echo "------------------------------------------------------------"
echo "List of loaded native libraries (.so files):"
cat jni_libs_opened.txt
echo "------------------------------------------------------------"

# --- STEP 3: Copy libraries to host ---
DEST_DIR="/home/rupesh.punna/Prototype/LIBS"
echo "Creating destination directory: $DEST_DIR"
mkdir -p "$DEST_DIR"

echo "Extracting unique native library paths..."
LIB_FILES=$(awk '{print $NF}' jni_libs_opened.txt | sort -u)

echo "Downloading native libraries from container $CONTAINER_ID..."
for lib_path in $LIB_FILES; do
    echo "Checking $lib_path..."
    if docker exec "$CONTAINER_ID" test -e "$lib_path"; then
        real_path=$(docker exec "$CONTAINER_ID" readlink -f "$lib_path")

        echo "Copying binary: $real_path..."
        docker cp "$CONTAINER_ID:$real_path" "$DEST_DIR/"

        if [ "$real_path" != "$lib_path" ]; then
            symlink_name=$(basename "$lib_path")
            target_name=$(basename "$real_path")
            if [ "$symlink_name" != "$target_name" ]; then
                echo "Duplicating binary for symlink name: $symlink_name"
                cp --remove-destination "$DEST_DIR/$target_name" "$DEST_DIR/$symlink_name"
            fi
        fi
    else
        echo "Skipping missing: $lib_path"
    fi
done

echo "------------------------------------------------------------"
echo "All valid native libraries have been downloaded to $DEST_DIR (no symlinks, only real binaries)."
echo "------------------------------------------------------------"
