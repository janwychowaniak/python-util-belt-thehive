# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**python-util-belt-thehive** is a curated collection of tiny, well-documented, self-contained Python utilities for TheHive Platform integration. This is NOT a traditional Python package distributed via PyPI - it's a collection of copy-paste utilities designed for security engineers working with TheHive in environments with restricted package installation.

**Target Users**: Security engineers in SOCs/CSIRTs who need TheHive integration utilities but face organizational restrictions on installing packages.

**Core Philosophy**: Copy-paste workflow, self-contained modules, minimal dependencies, git as version control, corporate-friendly.

## Current Repository State

The repository is in **bootstrap phase**. The complete architectural blueprint exists in `UTILITY_BELT_SEED_THEHIVE.md` (2337 lines), which contains:
- Complete module templates
- Development patterns
- TheHive-specific integration patterns
- Example implementations
- Anti-patterns to avoid

**Next Steps**: Execute the replication checklist (Section 10 of the seed document) to create the initial utility modules and supporting infrastructure.

## Architecture

### Directory Structure (Target)

```
python-util-belt-thehive/
├── README.md              # User-facing catalog with philosophy and examples
├── CLAUDE.md              # This file - developer guidance
├── LICENSE                # MIT License
├── .gitignore             # Standard Python + custom ignores
├── UTILITY_BELT_SEED_THEHIVE.md  # Complete architectural blueprint
├── modules/               # Self-contained utility modules (to be created)
│   ├── thehive_search.py  # Example: TheHive API search helper
│   ├── case_bulk.py       # Example: Bulk case operations
│   └── ioc_parser.py      # Example: Standalone IOC extraction
├── dev-notes/             # Manual testing reference guides (to be created)
│   ├── thehive_search.md
│   ├── case_bulk.md
│   └── ioc_parser.md
└── scripts/               # Simple helper tools (to be created)
    ├── copy_module.sh     # Bash: copy module to target project
    └── list_modules.py    # Python: list available modules with metadata
```

## Key Principles

1. **Self-contained modules**: Each module is a single `.py` file that works independently
2. **Minimal dependencies**: Prefer stdlib; `thehive4py` is acceptable for API modules
3. **Copy-paste workflow**: Users clone repo and copy individual modules to their projects
4. **No package management**: No pip install, no setup.py, no pyproject.toml for the belt itself
5. **Git as truth**: Git history is the single source of truth for changes and versions
6. **Manual testing**: dev-notes guide testing; automated tests belong in target projects

## What NOT to Include (Critical)

These patterns would violate the utility belt philosophy:
- ❌ `requirements.txt` in repo root
- ❌ `setup.py` or `pyproject.toml`
- ❌ Automated test frameworks (pytest, unittest)
- ❌ CI/CD pipelines (except basic linting)
- ❌ `__init__.py` in modules/ directory
- ❌ Complex build systems or CLI tools
- ❌ Package metadata files
- ❌ Dependency lock files
- ❌ `examples/` directory (examples live in docstrings)
- ❌ `tests/` directory (tests belong in target projects)

## Module Structure Template

Every module follows this pattern (see Section 3 of seed document for complete template):

```python
"""
ONE-LINE DESCRIPTION

Multi-paragraph description explaining problem, features, and use cases.

Key Features:
    - Feature 1 with specific benefit
    - Feature 2 with specific benefit
    - Feature 3 with specific benefit

Basic Usage:
    >>> from module_name import function_name
    >>> result = function_name('example')

Advanced Usage:
    >>> result = function_name('example', custom_param=True)

Environment Variables:
    THEHIVE_URL - TheHive instance URL (e.g., https://thehive.example.com)
    THEHIVE_API_KEY - API key for authentication
        OR
    NONE

Functions:
    function_name(arg1, arg2, **kwargs) -> ReturnType
        Detailed description

External Dependency:
    - Requires 'thehive4py' library: pip install thehive4py
        OR
    - No external dependencies (pure Python stdlib)

Author: Jan
Version: 1.0
"""

# External dependency imports with graceful error handling
try:
    from thehive4py.api import TheHiveApi
except ImportError:
    raise ImportError(
        "module_name.py requires 'thehive4py' library\n"
        "Install: pip install thehive4py"
    )

# Standard library imports
import os
import logging
from typing import Optional, Dict, List, Any

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Private helper functions (prefix with underscore)

def _get_api_connection(
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> TheHiveApi:
    """Establish TheHive API connection with env var fallback."""
    if logger is None:
        logger = logging.getLogger(__name__)

    thehive_url = thehive_url or os.getenv('THEHIVE_URL')
    api_key = api_key or os.getenv('THEHIVE_API_KEY')

    if not thehive_url:
        raise ValueError("TheHive URL must be provided or set in THEHIVE_URL env var")
    if not api_key:
        raise ValueError("API key must be provided or set in THEHIVE_API_KEY env var")

    logger.info(f"Connecting to TheHive at {thehive_url}")
    return TheHiveApi(thehive_url, api_key, cert=True)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Public API functions

def main_function(
    arg1: str,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Main public function with comprehensive docstring.

    Args:
        arg1: Description
        thehive_url: Optional TheHive URL (defaults to THEHIVE_URL env var)
        api_key: Optional API key (defaults to THEHIVE_API_KEY env var)
        logger: Optional logger instance (defaults to stdlib logging)

    Returns:
        Dict containing results with keys: 'status', 'data', 'message'

    Raises:
        ValueError: If arguments are invalid
        ConnectionError: If TheHive API is unreachable

    Examples:
        >>> main_function('test')
        {'status': 'success', 'data': [...]}
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        api = _get_api_connection(thehive_url, api_key, logger)
        # Implementation here
        return {'status': 'success', 'data': [], 'message': 'Completed'}
    except ValueError as e:
        logger.error(f"Invalid arguments: {e}")
        return {'status': 'error', 'data': None, 'message': str(e)}
    except ConnectionError as e:
        logger.error(f"Connection failed: {e}")
        return {'status': 'error', 'data': None, 'message': 'TheHive API unreachable'}
```

## TheHive-Specific Patterns

### Authentication Pattern
```python
# Always use environment variables with explicit parameter override
THEHIVE_URL = os.getenv('THEHIVE_URL') or thehive_url_param
THEHIVE_API_KEY = os.getenv('THEHIVE_API_KEY') or api_key_param
```

### Error Handling for TheHive API
- 200: Success - return data
- 401/403: Authentication/Authorization errors - raise ValueError
- 404: Not found - return None (graceful)
- 400: Validation error - raise ValueError with details
- 500+: Server error - raise ConnectionError

### Case ID Normalization
```python
def normalize_case_id(case_id: Union[str, int]) -> str:
    """Normalize case ID to TheHive API format (~12345)."""
    if isinstance(case_id, int):
        return f"~{case_id}"
    elif isinstance(case_id, str) and not case_id.startswith('~'):
        return f"~{case_id}"
    return case_id
```

### Query Building Pattern
```python
from thehive4py.query import Eq, In, Contains, And

# Combine filters with AND logic
query = And(
    Eq('status', 'Open'),
    In('severity', [3, 4]),
    Contains('tags', 'phishing')
)
```

### Observable Structure
```python
observable = {
    'dataType': 'ip',           # ip, domain, url, hash, etc.
    'data': '192.168.1.1',
    'tlp': 2,                   # 0=WHITE, 1=GREEN, 2=AMBER, 3=RED
    'ioc': True,
    'sighted': False,
    'tags': ['malware'],
    'message': 'Found in logs'
}
```

## Current Modules

### thehive_search (v1.0)

**Purpose**: Search TheHive cases with flexible filters

**Location**: `modules/thehive_search.py`

**Functions**:
- `search_cases(status, severity, tags, max_results, thehive_url, api_key, logger) -> List[Dict]` - Search cases with filters
- `get_case_by_id(case_id, thehive_url, api_key, logger) -> Optional[Dict]` - Retrieve single case

**Dependencies**: `thehive4py`

**Environment Variables**: `THEHIVE_URL`, `THEHIVE_API_KEY`

**Dev-notes**: See `dev-notes/thehive_search.md`

### ioc_parser (v1.0)

**Purpose**: Extract and normalize Indicators of Compromise from text

**Location**: `modules/ioc_parser.py`

**Functions**:
- `extract_iocs(text, refang, deduplicate, normalize) -> Dict[str, List[str]]` - Extract IOCs from text
- `format_for_thehive(iocs, tlp, tags, message) -> List[Dict]` - Convert to TheHive observable format

**Dependencies**: None (pure stdlib)

**Environment Variables**: None

**Dev-notes**: See `dev-notes/ioc_parser.md`

### api_connector (v1.0)

**Purpose**: Bulletproof connection establishment and health checking for TheHive and Cortex APIs

**Location**: `modules/api_connector.py`

**Functions**:
- `get_thehive_api(thehive_url, api_key, logger) -> TheHiveApi` - Establish health-checked TheHive connection
- `get_cortex_api(cortex_url, api_key, logger) -> CortexApi` - Establish health-checked Cortex connection

**Dependencies**:
- `thehive4py` - TheHive API client library
- `cortex4py` - Cortex API client library

**Environment Variables**:
- `THEHIVE_URL`, `THEHIVE_API_KEY` - TheHive connection details
- `CORTEX_URL`, `CORTEX_API_KEY` - Cortex connection details

**Error Handling**:
- `ValueError` - Configuration errors (missing/invalid credentials)
- `ConnectionError` - Infrastructure errors (bad host/port, network issues)

**Health Checks**:
- TheHive: `api.get_current_user()` with status code parsing (401=bad key, 502=bad host, TheHiveException=bad port)
- Cortex: `api.analyzers.find_all({})` with exception type parsing (AuthenticationError=bad key, InvalidInputError=bad host, ServiceUnavailableError=bad port)

**Dev-notes**: See `dev-notes/api_connector.md`

## Development Workflow

### Adding New Modules

1. Create module in `modules/your_utility.py` following the template
2. Include comprehensive docstring with all required sections
3. Implement error handling with proper categorization
4. Add type hints throughout
5. Support logging flexibility (stdlib fallback, logger param)
6. Create `dev-notes/your_utility.md` with manual test scenarios
7. Update README.md with utility description and examples
8. Commit: `git commit -m "Add your_utility module"`

### Module Quality Standards

- **Comprehensive docstrings**: Include Key Features, Basic/Advanced Usage, Environment Variables, Functions, External Dependency, Author, Version
- **Type hints**: Use throughout for clarity
- **Error handling**: Categorize exceptions (ValueError, ConnectionError, Exception)
- **Graceful failures**: Return dict with 'error' status or None, don't raise in most cases
- **Logging flexibility**: Accept logger param, fallback to stdlib logging
- **Environment variables**: Support TheHive auth via env vars with explicit override
- **Self-contained**: Single file, minimal dependencies, no imports between modules

### Testing Approach

- No automated tests in belt repository
- Provide comprehensive dev-notes with:
  - Test configuration (env vars, test constants)
  - Manual test scenarios grouped by functionality
  - Expected results with inline comments
  - Common issues and troubleshooting
  - Development observations

## Reference Documentation

**Complete reference**: See `UTILITY_BELT_SEED_THEHIVE.md` for:
- Section 3: Complete module template
- Section 4: Full example (thehive_search.py - API helper)
- Section 5: Full example (ioc_parser.py - standalone processor)
- Section 6: dev-notes template
- Section 7: Scripts implementation (copy_module.sh, list_modules.py)
- Section 8: Documentation patterns (README.md, CLAUDE.md)
- Section 9: TheHive-specific patterns (authentication, error handling, queries, observables)
- Section 10: Replication checklist (step-by-step bootstrap)
- Section 11: Anti-patterns (what NOT to do)

## Bootstrap Implementation

To implement the initial utilities structure, follow **Section 10** of the seed document:

1. Create directories: `modules/`, `dev-notes/`, `scripts/`
2. Implement `scripts/copy_module.sh` (bash, ~50 lines)
3. Implement `scripts/list_modules.py` (python, ~100 lines)
4. Create example module: `modules/thehive_search.py` (~250 lines)
5. Create example module: `modules/ioc_parser.py` (~200 lines)
6. Create dev-notes for both modules
7. Update README.md with catalog
8. Update this CLAUDE.md with current module list

## Common Commands (Once Implemented)

List available modules:
```bash
./scripts/list_modules.py
```

Copy module to project:
```bash
./scripts/copy_module.sh MODULE_NAME TARGET_DIR
```

Example:
```bash
./scripts/copy_module.sh thehive_search ~/my-soc-project/utils/
```

## External Dependencies

**Philosophy**: Prefer stdlib, but be pragmatic.

**Acceptable external dependencies**:
- `thehive4py`: Required for TheHive API operations (all API helper modules)

**How to document**:
- Prominently in module docstring "External Dependency" section
- In try/except ImportError block with installation instructions
- In README.md catalog with [dep: thehive4py] marker

## License

MIT License - See LICENSE file for full text.

## Author Attribution

Author: Jan Wychowaniak
Default module author field: "Jan" (customize per module as needed)
