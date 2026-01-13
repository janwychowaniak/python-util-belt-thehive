#!/usr/bin/env python3
"""
list_modules.py - List available utilities in python-util-belt-thehive

Extracts metadata from module docstrings and displays a catalog.
"""

import ast
import sys
from pathlib import Path
from typing import Dict, Optional

def extract_module_info(filepath: Path) -> Dict[str, Optional[str]]:
    """Extract metadata from module docstring using AST parsing."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())

        docstring = ast.get_docstring(tree)
        if not docstring:
            return {
                'name': filepath.stem,
                'description': 'No description available',
                'version': 'Unknown',
                'author': 'Unknown',
                'has_dependency': False
            }

        # Extract first line as description
        lines = [line.strip() for line in docstring.split('\n') if line.strip()]
        description = lines[0] if lines else 'No description'

        # Extract version and author
        version = 'Unknown'
        author = 'Unknown'
        has_dependency = False

        for i, line in enumerate(lines):
            if line.startswith('Version:'):
                version = line.split(':', 1)[1].strip()
            elif line.startswith('Author:'):
                author = line.split(':', 1)[1].strip()
            elif 'External Dependency:' in line:
                # Check this line and the next few lines for "No external"
                context = ' '.join(lines[i:i+3])  # Check current and next 2 lines
                if 'No external' not in context and 'pure Python stdlib' not in context:
                    has_dependency = True

        return {
            'name': filepath.stem,
            'description': description,
            'version': version,
            'author': author,
            'has_dependency': has_dependency
        }
    except Exception as e:
        return {
            'name': filepath.stem,
            'description': f'Error reading module: {e}',
            'version': 'Unknown',
            'author': 'Unknown',
            'has_dependency': False
        }

def list_modules():
    """List all available modules in the utility belt."""
    # Find the modules directory
    script_dir = Path(__file__).parent
    belt_root = script_dir.parent
    modules_dir = belt_root / 'modules'

    if not modules_dir.exists():
        print("Error: modules/ directory not found")
        sys.exit(1)

    # Get all Python modules
    modules = sorted(modules_dir.glob('*.py'))

    if not modules:
        print("No modules found in modules/ directory")
        print()
        print("The repository is in bootstrap phase. Modules will be added soon.")
        return

    print("╔═══════════════════════════════════════════════════════════════════════════╗")
    print("║               PYTHON UTIL BELT (THEHIVE) - CATALOG                        ║")
    print("╚═══════════════════════════════════════════════════════════════════════════╝")
    print()

    for module_path in modules:
        info = extract_module_info(module_path)

        # Show module name with dependency indicator
        dep_marker = " [dep: thehive4py]" if info['has_dependency'] else ""
        print(f"📦 {info['name']}{dep_marker}")
        print(f"   {info['description']}")
        print(f"   Version: {info['version']} | Author: {info['author']}")
        print()

    print(f"Total modules: {len(modules)}")
    print()
    print("To copy a module to your project:")
    print("  ./scripts/copy_module.sh MODULE_NAME TARGET_DIR")
    print()
    print("Example:")
    print(f"  ./scripts/copy_module.sh {modules[0].stem} ./my_project/utils/")
    print()
    print("Note: Modules marked [dep: ...] require external dependencies.")
    print("      Check module docstring for installation instructions.")

if __name__ == '__main__':
    list_modules()
