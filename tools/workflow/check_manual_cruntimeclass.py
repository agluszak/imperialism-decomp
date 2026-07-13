#!/usr/bin/env python3
"""
Check for manual CRuntimeClass definitions that should be replaced with MFC macros.

Manual CRuntimeClass definitions like:
  CRuntimeClass g_pClassDescTShipyardCluster = {nullptr, 0, 0, nullptr, nullptr};

Should be replaced with MFC macros:
  IMPLEMENT_DYNCREATE(TShipyardCluster, TBaseClass)
  IMPLEMENT_SERIAL(TClass, TBaseClass, schema)
  IMPLEMENT_DYNAMIC(TClass, TBaseClass)

Run `just mfc-runtime-macros --apply` to automatically migrate manual definitions
to the appropriate MFC macro based on the descriptor's schema and create-object pointer.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple

from tools.common.file_scan import is_excluded_scan_path


def find_manual_cruntimeclass_definitions(source_dir: Path) -> List[Tuple[Path, int, str]]:
    """Find manual CRuntimeClass definitions that should use MFC macros."""
    violations = []
    
    # Pattern for manual CRuntimeClass definitions
    # Matches: CRuntimeClass variable_name = {nullptr, 0, 0, nullptr, nullptr};
    # and similar patterns
    manual_pattern = re.compile(
        r'^\s*(?:extern\s+["]C["]\s+)?CRuntimeClass\s+\w+\s*=\s*\{[^}]*\}\s*;?',
        re.MULTILINE
    )
    
    # Also look for the old-style comment pattern
    comment_pattern = re.compile(r'^\s*//\s*GLOBAL:\s*IMPERIALISM\s+0x[0-9a-fA-F]+')
    
    for cpp_file in source_dir.rglob("*.cpp"):
        if is_excluded_scan_path(cpp_file):
            continue
        # Skip global_data_tables.cpp as it's the migration target
        if cpp_file.name == "global_data_tables.cpp":
            continue
            
        with open(cpp_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Check for manual CRuntimeClass definitions
            for match in manual_pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                line_content = content.split('\n')[line_num - 1].strip()
                
                # Only flag if it's not already using MFC macros
                if 'IMPLEMENT_' not in line_content and 'DECLARE_' not in line_content:
                    violations.append((cpp_file, line_num, line_content))
    
    return violations


def main():
    parser = argparse.ArgumentParser(description='Check for manual CRuntimeClass definitions')
    parser.add_argument('--source-dir', default='src', help='Source directory')
    args = parser.parse_args()
    
    source_dir = Path(args.source_dir)
    
    if not source_dir.exists():
        print(f"Error: Source directory {source_dir} does not exist")
        sys.exit(1)
    
    violations = find_manual_cruntimeclass_definitions(source_dir)
    
    if violations:
        print("ERROR: Manual CRuntimeClass definitions found.")
        print("These should be replaced with MFC macros (IMPLEMENT_DYNCREATE, IMPLEMENT_SERIAL, IMPLEMENT_DYNAMIC).")
        print("Run `just mfc-runtime-macros --apply` to automatically migrate these definitions.")
        print()
        print("Violations:")
        for file_path, line_num, line in violations:
            rel_path = file_path.relative_to(source_dir.parent)
            print(f"  {rel_path}:{line_num}: {line}")
        print()
        print(f"Total violations: {len(violations)}")
        sys.exit(1)
    else:
        print("Manual CRuntimeClass gate passed.")
        sys.exit(0)


if __name__ == '__main__':
    main()
