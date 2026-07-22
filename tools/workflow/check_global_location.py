#!/usr/bin/env python3
"""
Check that // GLOBAL: markers live in global_data_tables.cpp only,
and global declarations live in global_data_tables.h or include/game/globals/*.h.
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

from tools.common.file_scan import is_excluded_scan_path


def find_global_markers(source_dir: Path) -> List[Tuple[Path, int, str]]:
    """Find all // GLOBAL: markers in source files."""
    violations = []
    global_pattern = re.compile(r'^\s*//\s*GLOBAL:\s*IMPERIALISM\s+0x[0-9a-fA-F]+')

    for cpp_file in source_dir.rglob("*.cpp"):
        if is_excluded_scan_path(cpp_file):
            continue
        if cpp_file.name == "global_data_tables.cpp":
            continue  # This is the allowed location
            
        with open(cpp_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if global_pattern.search(line):
                    violations.append((cpp_file, line_num, line.strip()))
    
    return violations


def check_global_declarations(header_dir: Path) -> List[Tuple[Path, int, str]]:
    """Check that global declarations are in global_data_tables.h."""
    violations = []
    
    # Check for extern declarations in headers other than global_data_tables.h
    extern_pattern = re.compile(r'^\s*extern\s+\w+.*\s+g_\w+')
    
    for header_file in header_dir.rglob("*.h"):
        if is_excluded_scan_path(header_file):
            continue
        if header_file.name == "global_data_tables.h":
            continue  # This is the allowed location (umbrella)
        if header_file.parent.name == "globals":
            continue  # The per-subsystem globals headers (split, bead 8mo.2)
        if header_file.name.startswith("mfc_"):
            continue  # Skip MFC headers
            
        with open(header_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if extern_pattern.search(line) and 'g_' in line:
                    # Skip if it's a function declaration
                    if '(' not in line:
                        violations.append((header_file, line_num, line.strip()))
    
    return violations


def main():
    parser = argparse.ArgumentParser(description='Check global location gate')
    parser.add_argument('--source-dir', default='src', help='Source directory')
    parser.add_argument('--include-dir', default='include', help='Include directory')
    args = parser.parse_args()
    
    source_dir = Path(args.source_dir)
    include_dir = Path(args.include_dir)
    
    if not source_dir.exists():
        print(f"Error: Source directory {source_dir} does not exist")
        sys.exit(1)
    
    if not include_dir.exists():
        print(f"Error: Include directory {include_dir} does not exist")
        sys.exit(1)
    
    # Check for // GLOBAL: markers outside global_data_tables.cpp
    marker_violations = find_global_markers(source_dir)
    
    # Check for global declarations outside global_data_tables.h
    declaration_violations = check_global_declarations(include_dir)
    
    has_errors = False
    
    if marker_violations:
        print("ERROR: // GLOBAL: markers found outside global_data_tables.cpp:")
        for file_path, line_num, line in marker_violations:
            rel_path = file_path.relative_to(source_dir.parent)
            print(f"  {rel_path}:{line_num}: {line}")
        print()
        has_errors = True
    
    if declaration_violations:
        print("ERROR: Global declarations found outside global_data_tables.h:")
        for file_path, line_num, line in declaration_violations:
            rel_path = file_path.relative_to(include_dir.parent)
            print(f"  {rel_path}:{line_num}: {line}")
        print()
        has_errors = True
    
    if not has_errors:
        print("Global location gate passed.")
        sys.exit(0)
    else:
        print(f"Failed: {len(marker_violations)} marker violations, {len(declaration_violations)} declaration violations")
        sys.exit(1)


if __name__ == '__main__':
    main()
