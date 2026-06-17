#!/usr/bin/env python3
"""
Script: merge_all_syscalls.py
Description: Merge syscalls from binary and library analysis directories and generate seccomp profile

This script:
  1. Parses syscalls_BIN_<IMG_SAFE>/<binary>/syscalls.txt files
  2. Reports empty syscalls.txt files in binaries
  3. Creates binary_syscalls.txt with unique syscalls from all binaries
  4. Parses syscalls_LIBS_<IMG_SAFE>/<library>/syscalls.txt files
  5. Reports empty syscalls.txt files in libraries
  6. Creates library_syscalls.txt with unique syscalls from all libraries
  7. Merges with runc.txt default whitelist (if present)
  8. Creates <IMG_SAFE>.txt with combined syscalls (no duplicates)
  9. Generates <IMG_SAFE>.json seccomp profile from combined syscalls

Usage: ./merge_all_syscalls.py <IMG_SAFE>

Example:
  ./merge_all_syscalls.py jetty_9.4.58-jdk8-amazoncorretto

Note: Place runc.txt in the same directory as this script to include default runtime syscalls.
"""

import os
import sys
import json
from pathlib import Path
from typing import Set, List, Tuple


DEFAULT_SECCOMP_ARCHES = [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32",
]


def read_syscalls_file(filepath: Path) -> Set[str]:
    """Read syscalls from a file and return as a set (removes duplicates)."""
    syscalls = set()

    if not filepath.exists():
        return syscalls

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    syscalls.add(line)
    except Exception as e:
        print(f"  ⚠ Error reading {filepath}: {e}")

    return syscalls


def process_directory(base_dir: Path, dir_type: str) -> Tuple[Set[str], List[str], List[str]]:
    """
    Process a directory (syscalls_BIN_* or syscalls_LIBS_*) and collect syscalls.

    Returns:
        - Set of all unique syscalls
        - List of subdirectories with empty syscalls.txt
        - List of subdirectories with missing syscalls.txt
    """
    all_syscalls = set()
    empty_files = []
    missing_files = []

    if not base_dir.exists():
        print(f"⚠ Warning: Directory does not exist: {base_dir}")
        return all_syscalls, empty_files, missing_files

    # Get all subdirectories
    subdirs = [d for d in base_dir.iterdir() if d.is_dir()]

    if not subdirs:
        print(f"⚠ Warning: No subdirectories found in {base_dir}")
        return all_syscalls, empty_files, missing_files

    print(f"\n[Processing {dir_type}]")
    print(f"Directory: {base_dir}")
    print(f"Found {len(subdirs)} subdirectories")
    print("")

    for subdir in sorted(subdirs):
        syscalls_file = subdir / "syscalls.txt"
        subdir_name = subdir.name

        if not syscalls_file.exists():
            missing_files.append(subdir_name)
            print(f"  ✗ {subdir_name}: syscalls.txt MISSING")
            continue

        syscalls = read_syscalls_file(syscalls_file)

        if len(syscalls) == 0:
            empty_files.append(subdir_name)
            print(f"  ⚠ {subdir_name}: syscalls.txt EMPTY (0 syscalls)")
        else:
            print(f"  ✓ {subdir_name}: {len(syscalls)} syscalls")
            all_syscalls.update(syscalls)

    return all_syscalls, empty_files, missing_files


def write_syscalls_file(filepath: Path, syscalls: Set[str]):
    """Write syscalls to a file, sorted alphabetically."""
    try:
        with open(filepath, 'w') as f:
            for syscall in sorted(syscalls):
                f.write(f"{syscall}\n")
        print(f"  ✓ Written: {filepath} ({len(syscalls)} syscalls)")
    except Exception as e:
        print(f"  ✗ Error writing {filepath}: {e}")


def build_seccomp_profile(syscalls: Set[str]) -> dict:
    """
    Build a seccomp profile from syscall names.

    Returns a Docker-style seccomp profile that:
    - Allows the specified syscalls (SCMP_ACT_ALLOW)
    - Denies all other syscalls with EPERM (SCMP_ACT_ERRNO)
    """
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": DEFAULT_SECCOMP_ARCHES,
        "syscalls": [
            {
                "names": sorted(syscalls),
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }


def write_seccomp_profile(filepath: Path, syscalls: Set[str]):
    """Generate and write a seccomp profile JSON file."""
    try:
        profile = build_seccomp_profile(syscalls)
        with open(filepath, 'w') as f:
            json.dump(profile, f, indent=2)
            f.write("\n")
        print(f"  ✓ Written: {filepath} ({len(syscalls)} syscalls)")
    except Exception as e:
        print(f"  ✗ Error writing {filepath}: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: ./merge_all_syscalls.py <IMG_SAFE>")
        print("")
        print("Example:")
        print("  ./merge_all_syscalls.py jetty_9.4.58-jdk8-amazoncorretto")
        sys.exit(1)

    img_safe = sys.argv[1]
    script_dir = Path(__file__).resolve().parent

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              Syscall Merge & Analysis Tool                   ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"\nIMG_SAFE: {img_safe}")
    print(f"Working directory: {script_dir}")

    # Define directories
    bin_dir = script_dir / f"syscalls_BIN_{img_safe}"
    libs_dir = script_dir / f"syscalls_output_{img_safe}"

    # =========================================================================
    # STEP 1: Process Binary Syscalls
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 1: Processing Binary Syscalls")
    print("="*70)

    binary_syscalls, bin_empty, bin_missing = process_directory(bin_dir, "Binaries")

    if bin_empty:
        print(f"\n⚠ Warning: {len(bin_empty)} binaries with EMPTY syscalls.txt:")
        for name in bin_empty:
            print(f"    - {name}")

    if bin_missing:
        print(f"\n✗ Error: {len(bin_missing)} binaries with MISSING syscalls.txt:")
        for name in bin_missing:
            print(f"    - {name}")

    # Write binary_syscalls.txt
    print("")
    if binary_syscalls:
        binary_output = bin_dir / "binary_syscalls.txt"
        write_syscalls_file(binary_output, binary_syscalls)
    else:
        print("  ⚠ No syscalls found in any binary, skipping binary_syscalls.txt")

    # =========================================================================
    # STEP 2: Process Library Syscalls
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 2: Processing Library Syscalls")
    print("="*70)

    library_syscalls, lib_empty, lib_missing = process_directory(libs_dir, "Libraries")

    if lib_empty:
        print(f"\n⚠ Warning: {len(lib_empty)} libraries with EMPTY syscalls.txt:")
        for name in lib_empty:
            print(f"    - {name}")

    if lib_missing:
        print(f"\n✗ Error: {len(lib_missing)} libraries with MISSING syscalls.txt:")
        for name in lib_missing:
            print(f"    - {name}")

    # Write library_syscalls.txt
    print("")
    if library_syscalls:
        library_output = libs_dir / "library_syscalls.txt"
        write_syscalls_file(library_output, library_syscalls)
    else:
        print("  ⚠ No syscalls found in any library, skipping library_syscalls.txt")

    # =========================================================================
    # STEP 3: Load runc.txt Default Whitelist
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 3: Loading runc.txt Default Whitelist")
    print("="*70)

    runc_whitelist_path = script_dir / "runc.txt"
    runc_syscalls = set()

    if runc_whitelist_path.exists():
        print(f"\nReading default whitelist from: {runc_whitelist_path}")
        runc_syscalls = read_syscalls_file(runc_whitelist_path)
        print(f"  ✓ Loaded {len(runc_syscalls)} syscalls from runc.txt")
    else:
        print(f"\n⚠ Warning: runc.txt not found at {runc_whitelist_path}")
        print("  Continuing without default whitelist...")

    # =========================================================================
    # STEP 4: Create Combined Syscalls File
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 4: Creating Combined Syscalls File")
    print("="*70)

    # Combine all sets (set union automatically removes duplicates)
    # Order: binary + library + runc whitelist
    combined_syscalls = binary_syscalls | library_syscalls | runc_syscalls

    print(f"\nBinary syscalls:   {len(binary_syscalls)}")
    print(f"Library syscalls:  {len(library_syscalls)}")
    print(f"Runc whitelist:    {len(runc_syscalls)}")
    print(f"Combined (unique): {len(combined_syscalls)}")

    # Calculate what runc.txt adds
    before_runc = len(binary_syscalls | library_syscalls)
    added_by_runc = len(combined_syscalls) - before_runc
    if added_by_runc > 0:
        print(f"  → runc.txt added {added_by_runc} additional syscalls")
    print("")

    if combined_syscalls:
        # Write to syscalls_LIBS_<IMG_SAFE>/<IMG_SAFE>.txt
        combined_output = libs_dir / f"{img_safe}.txt"
        write_syscalls_file(combined_output, combined_syscalls)
    else:
        print("  ⚠ No syscalls found, skipping combined file")

    # =========================================================================
    # STEP 5: Generate Seccomp Profile
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 5: Generating Seccomp Profile")
    print("="*70)

    if combined_syscalls:
        # Create seccomp profile in syscalls_LIBS_<IMG_SAFE>/<IMG_SAFE>.json
        seccomp_output = libs_dir / f"{img_safe}.json"
        print(f"\nGenerating seccomp profile from combined syscalls...")
        write_seccomp_profile(seccomp_output, combined_syscalls)
        print(f"\nSeccomp profile configuration:")
        print(f"  - Default action: SCMP_ACT_ERRNO (deny all by default)")
        print(f"  - Allowed syscalls: {len(combined_syscalls)}")
        print(f"  - Architectures: {', '.join(DEFAULT_SECCOMP_ARCHES)}")
    else:
        print("\n  ⚠ No syscalls found, skipping seccomp profile generation")

    # =========================================================================
    # STEP 6: Summary
    # =========================================================================
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    print(f"\nBinaries:")
    print(f"  - Analyzed:  {len([d for d in bin_dir.iterdir() if d.is_dir()]) if bin_dir.exists() else 0}")
    print(f"  - Empty:     {len(bin_empty)}")
    print(f"  - Missing:   {len(bin_missing)}")
    print(f"  - Syscalls:  {len(binary_syscalls)} unique")

    print(f"\nLibraries:")
    print(f"  - Analyzed:  {len([d for d in libs_dir.iterdir() if d.is_dir()]) if libs_dir.exists() else 0}")
    print(f"  - Empty:     {len(lib_empty)}")
    print(f"  - Missing:   {len(lib_missing)}")
    print(f"  - Syscalls:  {len(library_syscalls)} unique")

    print(f"\nRunc Whitelist:")
    if runc_syscalls:
        print(f"  - Loaded from: {runc_whitelist_path}")
        print(f"  - Syscalls:    {len(runc_syscalls)} unique")
        before_runc = len(binary_syscalls | library_syscalls)
        added_by_runc = len(combined_syscalls) - before_runc
        if added_by_runc > 0:
            print(f"  - Added:       {added_by_runc} additional syscalls")
    else:
        print(f"  - Not loaded (file not found)")

    print(f"\nCombined:")
    print(f"  - Total unique syscalls: {len(combined_syscalls)}")
    if runc_syscalls:
        print(f"  - Includes: binaries + libraries + runc whitelist")

    print(f"\nOutput files:")
    if binary_syscalls:
        print(f"  - {bin_dir / 'binary_syscalls.txt'} (text)")
    if library_syscalls:
        print(f"  - {libs_dir / 'library_syscalls.txt'} (text)")
    if combined_syscalls:
        print(f"  - {libs_dir / f'{img_safe}.txt'} (text)")
        print(f"  - {libs_dir / f'{img_safe}.json'} (seccomp profile)")

    print("")

    # Exit with error code if there were issues
    if bin_missing or lib_missing or (not combined_syscalls):
        print("⚠ Completed with warnings or errors")
        sys.exit(1)
    else:
        print("✓ Completed successfully")
        sys.exit(0)


if __name__ == "__main__":
    main()
