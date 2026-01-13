#!/usr/bin/env bash
# copy_module.sh - Copy a module from python-util-belt-thehive to target project

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Usage
if [ $# -lt 2 ]; then
    echo -e "${RED}Usage: $0 MODULE_NAME TARGET_DIR${NC}"
    echo
    echo "Example:"
    echo "  $0 thehive_search ~/my-project/utils/"
    echo
    echo "Available modules:"
    ./scripts/list_modules.py
    exit 1
fi

MODULE_NAME="$1"
TARGET_DIR="$2"

# Find script directory and belt root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BELT_ROOT="$(dirname "$SCRIPT_DIR")"
MODULES_DIR="$BELT_ROOT/modules"

# Find module file
MODULE_FILE="$MODULES_DIR/${MODULE_NAME}.py"

if [ ! -f "$MODULE_FILE" ]; then
    echo -e "${RED}Error: Module '$MODULE_NAME' not found${NC}"
    echo
    echo "Available modules:"
    ls -1 "$MODULES_DIR"/*.py 2>/dev/null | xargs -n1 basename | sed 's/\.py$//' || echo "No modules found yet"
    exit 1
fi

# Create target directory if needed
mkdir -p "$TARGET_DIR"

# Copy module
cp "$MODULE_FILE" "$TARGET_DIR/"
echo -e "${GREEN}✓ Copied $MODULE_NAME.py to $TARGET_DIR/${NC}"

# Show usage instructions
echo
echo -e "${YELLOW}Usage in your project:${NC}"
echo "  from $(basename "$TARGET_DIR").$MODULE_NAME import *"
echo
echo -e "${YELLOW}Check module docstring for dependencies:${NC}"
echo "  python3 -c \"import $MODULE_NAME; help($MODULE_NAME)\""
