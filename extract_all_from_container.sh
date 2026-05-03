#!/usr/bin/env bash

#############################################################################
# Complete Container Extraction and Debug Symbol Linking
#
# This is the main script that orchestrates the complete extraction process:
#   1. Extract JAR files from container
#   2. Extract native libraries from JARs and container filesystem
#   3. Extract debug symbols from container
#   4. Create debug symbol links
#   5. Fix library dependencies
#   6. Generate GDB configuration
#
# Usage: ./extract_all_from_container.sh <container_id> [options]
#
# Options:
#   --output-dir <dir>      Base output directory (default: ./outputs_<container_name>)
#   --skip-jars             Skip JAR extraction
#   --skip-libs             Skip library extraction
#   --skip-debug            Skip debug symbol extraction
#   --include-system-libs   Include system libraries (not recommended)
#   --dry-run               Show what would be done
#   --help                  Show this help message
#
# Output Structure:
#   outputs_<container>/
#   ├── JARFILES/               # Extracted JAR files
#   ├── LIBS/                   # Extracted .so files
#   ├── DEBUG_SYMBOLS/          # Debug symbol files
#   │   ├── .build-id/          # Build-ID indexed debug
#   │   └── usr/lib/debug/      # Standard debug paths
#   ├── debug_links.txt         # Library -> Debug mapping
#   ├── gdbinit                 # GDB configuration
#   ├── set_lib_path.sh         # Helper to set LD_LIBRARY_PATH
#   └── SUMMARY.txt             # Extraction summary
#
# Example:
#   ./extract_all_from_container.sh tomcat-test
#   ./extract_all_from_container.sh my-app --skip-jars
#############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default settings
CONTAINER_ID=""
OUTPUT_DIR=""
SKIP_JARS=false
SKIP_LIBS=false
SKIP_DEBUG=false
INCLUDE_SYSTEM_LIBS=false
DRY_RUN=false

#############################################################################
# Logging functions
#############################################################################
log_header() {
    echo ""
    echo -e "${BOLD}${MAGENTA}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${MAGENTA}  $*${NC}"
    echo -e "${BOLD}${MAGENTA}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

log_section() {
    echo ""
    echo -e "${CYAN}▶ $*${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
}

log_info() {
    echo -e "${BLUE}  [INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}  [✓]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}  [⚠]${NC} $*"
}

log_error() {
    echo -e "${RED}  [✗]${NC} $*"
}

log_step() {
    echo -e "${CYAN}  →${NC} $*"
}

#############################################################################
# Print usage
#############################################################################
print_usage() {
    grep "^#" "$0" | grep -v "#!/usr/bin/env bash" | sed 's/^# //g' | sed 's/^#//g'
}

#############################################################################
# Get container name
#############################################################################
get_container_name() {
    docker inspect -f '{{.Name}}' "$CONTAINER_ID" 2>/dev/null | sed 's/^\///' || echo "$CONTAINER_ID"
}

#############################################################################
# Detect container OS
#############################################################################
detect_container_os() {
    log_step "Detecting container OS..."

    local os_id=$(docker exec "$CONTAINER_ID" sh -c 'cat /etc/os-release 2>/dev/null | grep "^ID=" | cut -d= -f2 | tr -d \"\047\"' 2>/dev/null || echo "unknown")
    local os_version=$(docker exec "$CONTAINER_ID" sh -c 'cat /etc/os-release 2>/dev/null | grep "^VERSION_ID=" | cut -d= -f2 | tr -d \"\047\"' 2>/dev/null || echo "")

    log_info "OS: $os_id $os_version"
    echo "${os_id}|${os_version}"
}

#############################################################################
# Extract JAR files from container
#############################################################################
extract_jars() {
    log_section "Step 1: Extracting JAR Files"

    local jar_dir="$OUTPUT_DIR/JARFILES"
    mkdir -p "$jar_dir"

    log_step "Finding JAR files in container..."

    # Find all JAR files
    local jar_list=$(docker exec "$CONTAINER_ID" sh -c 'find / -name "*.jar" -type f 2>/dev/null' || true)

    if [ -z "$jar_list" ]; then
        log_warning "No JAR files found in container"
        return 0
    fi

    local jar_count=$(echo "$jar_list" | wc -l)
    log_info "Found $jar_count JAR files"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would extract $jar_count JARs"
        return 0
    fi

    local extracted=0
    while IFS= read -r jar_path; do
        [ -z "$jar_path" ] && continue

        local jar_name=$(basename "$jar_path")

        # Handle duplicates
        local dest="$jar_dir/$jar_name"
        if [ -e "$dest" ]; then
            local base="${jar_name%.jar}"
            dest="$jar_dir/${base}_$(echo $jar_path | md5sum | cut -c1-8).jar"
        fi

        if docker cp "$CONTAINER_ID:$jar_path" "$dest" 2>/dev/null; then
            ((extracted++))
            if (( extracted % 10 == 0 )); then
                log_step "Extracted $extracted/$jar_count JARs..."
            fi
        fi
    done <<< "$jar_list"

    log_success "Extracted $extracted JAR files to: $jar_dir"
}

#############################################################################
# Extract native libraries
#############################################################################
extract_libraries() {
    log_section "Step 2: Extracting Native Libraries"

    local libs_dir="$OUTPUT_DIR/LIBS"
    mkdir -p "$libs_dir"

    # First, extract libraries from JARs if JARs were extracted
    local jar_dir="$OUTPUT_DIR/JARFILES"
    if [ -d "$jar_dir" ] && [ "$(ls -A "$jar_dir"/*.jar 2>/dev/null | wc -l)" -gt 0 ]; then
        log_step "Extracting native libraries from JARs..."

        if [ "$DRY_RUN" = false ] && [ -x "$SCRIPT_DIR/extract_libs_jars.sh" ]; then
            JARFILES_DIR="$jar_dir" LIBS_DIR="$libs_dir" \
                "$SCRIPT_DIR/extract_libs_jars.sh" "$jar_dir" "$libs_dir" || log_warning "JAR library extraction had issues"
        fi
    fi

    # Then, extract libraries from container filesystem
    log_step "Extracting native libraries from container filesystem..."

    if [ "$DRY_RUN" = false ] && [ -x "$SCRIPT_DIR/extract_container_libraries.sh" ]; then
        local opts=""
        [ "$INCLUDE_SYSTEM_LIBS" = true ] && opts="--include-system"

        "$SCRIPT_DIR/extract_container_libraries.sh" "$CONTAINER_ID" --output-dir "$libs_dir" $opts || \
            log_warning "Container library extraction had issues"
    fi

    log_success "Libraries extracted to: $libs_dir"
}

#############################################################################
# Install and extract debug symbols
#############################################################################
extract_debug_symbols() {
    log_section "Step 3: Extracting Debug Symbols"

    local debug_dir="$OUTPUT_DIR/DEBUG_SYMBOLS"
    mkdir -p "$debug_dir"

    # Install debug packages in container
    log_step "Installing debug packages in container..."

    local os_info="$1"
    IFS='|' read -r os_id os_version <<< "$os_info"

    local install_log="$debug_dir/install.log"

    case "$os_id" in
        ol|rhel|centos|fedora)
            log_info "Installing debug packages for $os_id..."
            docker exec "$CONTAINER_ID" bash -c '
                command -v yum-config-manager >/dev/null 2>&1 || yum install -y yum-utils 2>&1 || true
                yum-config-manager --enable \*debuginfo 2>&1 || true
                yum-config-manager --enable \*debug\* 2>&1 || true
                yum clean all 2>&1
                yum install -y glibc-debuginfo glibc-debuginfo-common openssl-debuginfo 2>&1 || true
            ' > "$install_log" 2>&1 || log_warning "Some debug packages failed to install"
            ;;

        ubuntu|debian)
            log_info "Installing debug packages for $os_id..."
            docker exec "$CONTAINER_ID" bash -c '
                export DEBIAN_FRONTEND=noninteractive
                apt-get update 2>&1 || true
                apt-get install -y --no-install-recommends libc6-dbg libssl*-dbg 2>&1 || true
            ' > "$install_log" 2>&1 || log_warning "Some debug packages failed to install"
            ;;

        alpine)
            log_info "Installing debug packages for $os_id..."
            docker exec "$CONTAINER_ID" sh -c '
                apk update 2>&1 || true
                apk add --no-cache musl-dbg 2>&1 || true
            ' > "$install_log" 2>&1 || log_warning "Some debug packages failed to install"
            ;;

        *)
            log_warning "Unknown OS: $os_id - skipping debug package installation"
            ;;
    esac

    # Extract debug symbols
    log_step "Extracting debug symbol files..."

    local extracted=0
    local debug_paths=(
        "/usr/lib/debug"
        "/lib/debug"
        "/usr/lib64/debug"
        "/lib64/debug"
        "/usr/lib/debug/.build-id"
    )

    for debug_path in "${debug_paths[@]}"; do
        if docker exec "$CONTAINER_ID" test -d "$debug_path" 2>/dev/null; then
            log_info "Extracting: $debug_path"
            if [ "$DRY_RUN" = false ]; then
                docker cp "$CONTAINER_ID:$debug_path/." "$debug_dir/" 2>/dev/null && {
                    local count=$(find "$debug_dir" -type f 2>/dev/null | wc -l)
                    extracted=$count
                } || true
            fi
        fi
    done

    if [ "$extracted" -gt 0 ]; then
        log_success "Extracted $extracted debug files to: $debug_dir"
    else
        log_warning "No debug symbols found - function names may show as 'fuzzyfunc-<address>'"
        log_info "This is normal for minimal container images"
    fi

    echo "$extracted"
}

#############################################################################
# Link debug symbols to libraries
#############################################################################
link_debug_symbols() {
    log_section "Step 4: Linking Debug Symbols"

    local libs_dir="$OUTPUT_DIR/LIBS"
    local debug_dir="$OUTPUT_DIR/DEBUG_SYMBOLS"
    local links_file="$OUTPUT_DIR/debug_links.txt"

    [ ! -d "$libs_dir" ] && { log_warning "No libraries directory found"; return; }
    [ ! -d "$debug_dir" ] && { log_warning "No debug symbols directory found"; return; }

    > "$links_file"

    local linked=0
    local total=0

    log_step "Creating library -> debug symbol mappings..."

    while IFS= read -r lib; do
        [ -z "$lib" ] || [ ! -f "$lib" ] && continue

        ((total++))
        local lib_name=$(basename "$lib")

        # Get build-id
        local build_id=""
        if command -v readelf &>/dev/null; then
            build_id=$(readelf -n "$lib" 2>/dev/null | grep "Build ID:" | awk '{print $3}' | head -1)
        fi

        local debug_file=""

        # Look for build-id based debug file
        if [ -n "$build_id" ] && [ ${#build_id} -gt 2 ]; then
            local bid_prefix="${build_id:0:2}"
            local bid_suffix="${build_id:2}"
            local bid_path="$debug_dir/.build-id/$bid_prefix/$bid_suffix.debug"

            [ -f "$bid_path" ] && debug_file="$bid_path"
        fi

        # Look for standard path debug file
        if [ -z "$debug_file" ]; then
            debug_file=$(find "$debug_dir" -name "$lib_name.debug" -type f 2>/dev/null | head -1)
        fi

        if [ -n "$debug_file" ] && [ -f "$debug_file" ]; then
            echo "$lib|$debug_file|$build_id" >> "$links_file"
            ((linked++))
        fi
    done < <(find "$libs_dir" -maxdepth 1 -type f -name "*.so*" 2>/dev/null)

    log_success "Linked $linked out of $total libraries to debug symbols"
    log_info "Debug links saved to: $links_file"
}

#############################################################################
# Fix library dependencies
#############################################################################
fix_dependencies() {
    log_section "Step 5: Fixing Library Dependencies"

    local libs_dir="$OUTPUT_DIR/LIBS"

    if [ ! -d "$libs_dir" ]; then
        log_warning "No libraries directory found"
        return
    fi

    if [ "$DRY_RUN" = false ] && [ -x "$SCRIPT_DIR/fix_lib_dependencies.sh" ]; then
        log_step "Running fix_lib_dependencies.sh..."
        "$SCRIPT_DIR/fix_lib_dependencies.sh" --lib-dir "$libs_dir" || log_warning "Dependency fixing had issues"
    else
        log_info "[DRY-RUN] Would fix library dependencies"
    fi
}

#############################################################################
# Create GDB configuration
#############################################################################
create_gdb_config() {
    log_section "Step 6: Creating GDB Configuration"

    local gdbinit="$OUTPUT_DIR/gdbinit"
    local libs_dir="$OUTPUT_DIR/LIBS"
    local debug_dir="$OUTPUT_DIR/DEBUG_SYMBOLS"

    cat > "$gdbinit" << EOF
# Auto-generated GDB initialization file
# Container: $(get_container_name)
# Generated: $(date)

# Set debug file directories
set debug-file-directory $debug_dir:$debug_dir/.build-id:/usr/lib/debug

# Add library search path
set solib-search-path $libs_dir

# Enable verbose symbol loading
set verbose on
set print symbol-filename on

# Auto-load safe path
set auto-load safe-path /

# Pretty printing
set print pretty on
set print object on

echo ═══════════════════════════════════════════════════════\\n
echo   Debug Environment Loaded\\n
echo ═══════════════════════════════════════════════════════\\n
echo\\n
echo Libraries:     $libs_dir\\n
echo Debug symbols: $debug_dir\\n
echo\\n
echo Commands:\\n
echo   info sharedlibrary  - Show loaded libraries\\n
echo   info sources        - Show source files\\n
echo   info functions      - Show all functions\\n
echo\\n
EOF

    chmod +x "$gdbinit"
    log_success "Created GDB config: gdbinit"
}

#############################################################################
# Create helper scripts
#############################################################################
create_helper_scripts() {
    log_section "Step 7: Creating Helper Scripts"

    local libs_dir="$OUTPUT_DIR/LIBS"

    # Create LD_LIBRARY_PATH helper
    local lib_helper="$OUTPUT_DIR/set_lib_path.sh"
    cat > "$lib_helper" << EOF
#!/bin/bash
# Auto-generated helper to set LD_LIBRARY_PATH
# Usage: source ./set_lib_path.sh

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="\$SCRIPT_DIR/LIBS:\$LD_LIBRARY_PATH"

echo "[INFO] LD_LIBRARY_PATH set to: \$LD_LIBRARY_PATH"
EOF
    chmod +x "$lib_helper"
    log_success "Created: set_lib_path.sh"

    # Create quick analysis script
    local analyze_script="$OUTPUT_DIR/analyze.sh"
    cat > "$analyze_script" << 'EOF'
#!/bin/bash
# Quick analysis helper script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "═══════════════════════════════════════════════════════"
echo "  Container Analysis Environment"
echo "═══════════════════════════════════════════════════════"
echo ""

# Set library path
export LD_LIBRARY_PATH="$SCRIPT_DIR/LIBS:$LD_LIBRARY_PATH"

# Count resources
JAR_COUNT=$(find "$SCRIPT_DIR/JARFILES" -name "*.jar" 2>/dev/null | wc -l)
LIB_COUNT=$(find "$SCRIPT_DIR/LIBS" -name "*.so*" -type f 2>/dev/null | wc -l)
DEBUG_COUNT=$(find "$SCRIPT_DIR/DEBUG_SYMBOLS" -type f 2>/dev/null | wc -l)

echo "Resources:"
echo "  JARs:          $JAR_COUNT"
echo "  Libraries:     $LIB_COUNT"
echo "  Debug symbols: $DEBUG_COUNT"
echo ""

if [ -f "$SCRIPT_DIR/debug_links.txt" ]; then
    LINKED=$(wc -l < "$SCRIPT_DIR/debug_links.txt")
    echo "  Linked debug:  $LINKED"
fi

echo ""
echo "Available commands:"
echo "  source set_lib_path.sh      - Set LD_LIBRARY_PATH"
echo "  gdb -x gdbinit <binary>     - Debug with GDB"
echo "  cat SUMMARY.txt             - View full summary"
echo ""
EOF
    chmod +x "$analyze_script"
    log_success "Created: analyze.sh"
}

#############################################################################
# Generate summary
#############################################################################
generate_summary() {
    log_section "Generating Summary"

    local summary="$OUTPUT_DIR/SUMMARY.txt"

    {
        echo "═══════════════════════════════════════════════════════"
        echo "  Container Extraction Summary"
        echo "═══════════════════════════════════════════════════════"
        echo ""
        echo "Container:    $(get_container_name)"
        echo "Date:         $(date)"
        echo "Output:       $OUTPUT_DIR"
        echo ""
        echo "───────────────────────────────────────────────────────"
        echo "  Extracted Resources"
        echo "───────────────────────────────────────────────────────"

        if [ -d "$OUTPUT_DIR/JARFILES" ]; then
            local jar_count=$(find "$OUTPUT_DIR/JARFILES" -name "*.jar" 2>/dev/null | wc -l)
            echo "JARs:             $jar_count files"
        fi

        if [ -d "$OUTPUT_DIR/LIBS" ]; then
            local lib_count=$(find "$OUTPUT_DIR/LIBS" -name "*.so*" -type f 2>/dev/null | wc -l)
            echo "Libraries:        $lib_count files"
        fi

        if [ -d "$OUTPUT_DIR/DEBUG_SYMBOLS" ]; then
            local debug_count=$(find "$OUTPUT_DIR/DEBUG_SYMBOLS" -type f 2>/dev/null | wc -l)
            echo "Debug symbols:    $debug_count files"
        fi

        if [ -f "$OUTPUT_DIR/debug_links.txt" ]; then
            local linked=$(wc -l < "$OUTPUT_DIR/debug_links.txt")
            echo "Linked debug:     $linked libraries"
        fi

        echo ""
        echo "───────────────────────────────────────────────────────"
        echo "  Usage"
        echo "───────────────────────────────────────────────────────"
        echo ""
        echo "Quick start:"
        echo "  cd $OUTPUT_DIR"
        echo "  ./analyze.sh"
        echo ""
        echo "For GDB debugging:"
        echo "  gdb -x $OUTPUT_DIR/gdbinit <your_binary>"
        echo ""
        echo "For analysis tools:"
        echo "  export LD_LIBRARY_PATH=$OUTPUT_DIR/LIBS:\$LD_LIBRARY_PATH"
        echo ""

    } | tee "$summary"

    log_success "Summary saved to: SUMMARY.txt"
}

#############################################################################
# Main function
#############################################################################
main() {
    log_header "Container Extraction & Debug Symbol Linking"

    # Validate container
    if ! docker inspect "$CONTAINER_ID" &>/dev/null; then
        log_error "Container not found: $CONTAINER_ID"
        exit 1
    fi

    local container_name=$(get_container_name)
    log_info "Container: $container_name"

    # Setup output directory
    [ -z "$OUTPUT_DIR" ] && OUTPUT_DIR="$SCRIPT_DIR/outputs_$container_name"
    log_info "Output: $OUTPUT_DIR"

    [ "$DRY_RUN" = false ] && mkdir -p "$OUTPUT_DIR"

    # Detect OS
    local os_info=$(detect_container_os)

    # Execute extraction steps
    [ "$SKIP_JARS" = false ] && extract_jars
    [ "$SKIP_LIBS" = false ] && extract_libraries

    local debug_count=0
    if [ "$SKIP_DEBUG" = false ]; then
        debug_count=$(extract_debug_symbols "$os_info")
    fi

    # Post-processing steps
    if [ "$DRY_RUN" = false ]; then
        [ "$debug_count" -gt 0 ] && link_debug_symbols
        fix_dependencies
        create_gdb_config
        create_helper_scripts
        generate_summary
    fi

    log_header "Complete!"

    echo ""
    echo "Next steps:"
    echo "  1. cd $OUTPUT_DIR"
    echo "  2. ./analyze.sh"
    echo "  3. cat SUMMARY.txt"
    echo ""
}

#############################################################################
# Parse arguments
#############################################################################
while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir)
            OUTPUT_DIR="$2"; shift 2 ;;
        --skip-jars)
            SKIP_JARS=true; shift ;;
        --skip-libs)
            SKIP_LIBS=true; shift ;;
        --skip-debug)
            SKIP_DEBUG=true; shift ;;
        --include-system-libs)
            INCLUDE_SYSTEM_LIBS=true; shift ;;
        --dry-run)
            DRY_RUN=true; shift ;;
        --help)
            print_usage; exit 0 ;;
        -*)
            log_error "Unknown option: $1"
            print_usage; exit 1 ;;
        *)
            [ -z "$CONTAINER_ID" ] && CONTAINER_ID="$1" || {
                log_error "Unknown argument: $1"
                print_usage; exit 1
            }
            shift ;;
    esac
done

# Validate
if [ -z "$CONTAINER_ID" ]; then
    log_error "Container ID/name is required"
    echo ""
    print_usage
    exit 1
fi

# Run
main
