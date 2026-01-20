# python-util-belt-thehive

A curated collection of tiny, well-documented, self-contained Python utilities for TheHive Platform integration. This is NOT a package - utilities are designed to be copied directly into your projects.

## Philosophy

### What is a Utility Belt?

A utility belt is a **collection of copy-paste utilities** designed for environments where traditional package management is restricted or slow. Instead of `pip install`, you simply clone the repo and copy individual modules to your project.

**Why This Approach?**

Many organizations restrict package installation, have slow approval processes, or prefer vendoring code. Traditional packages require:
- PyPI access or private package repos
- Dependency management and lock files
- Version pinning and updates
- Import namespace management

The utility belt provides:
- ✓ Instant availability (copy file, import module)
- ✓ No approval needed for "installing" code
- ✓ Full control and visibility (code is local)
- ✓ Easy modification for specific needs
- ✓ Zero dependency conflicts

### Target Audience

**Users**: Security engineers in SOCs/CSIRTs working with TheHive Platform

**Context**: TheHive case management, incident response automation, threat intelligence processing

**Skill level**: Technical audience comfortable with Python and APIs

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/python-util-belt-thehive.git
   cd python-util-belt-thehive
   ```

2. **Browse available utilities:**
   ```bash
   ./scripts/list_modules.py
   ```

3. **Copy a utility to your project:**
   ```bash
   ./scripts/copy_module.sh thehive_search ~/my-project/utils/
   ```

4. **Use in your code:**
   ```python
   from utils.thehive_search import search_cases
   cases = search_cases(status='Open', severity=3)
   ```

## Available Utilities

### thehive_search

**TheHive Case Search** - Search TheHive cases with flexible filters

Provides a simple interface for searching cases in TheHive with support for status, severity, tags, and pagination. Wraps the thehive4py API with proper error handling and environment-based authentication.

**Features:**
- Flexible case search with multiple filter criteria
- Support for status, severity, tags, date ranges
- Automatic pagination handling
- Environment-based authentication (THEHIVE_URL, THEHIVE_API_KEY)
- Configurable logging (stdlib, loguru, or custom)
- Returns clean dictionaries for easy processing

**Usage:**
```python
from thehive_search import search_cases, get_case_by_id

# Find open high-severity cases
cases = search_cases(status='Open', severity=[3, 4])

# Search with tags
phishing_cases = search_cases(
    status='Open',
    tags=['phishing', 'malware']
)

# Get specific case
case = get_case_by_id(12345)

# Custom authentication (not using env vars)
cases = search_cases(
    status='Open',
    thehive_url='https://thehive.local',
    api_key='your-key'
)
```

**Dependencies:** Requires `thehive4py` library
```bash
pip install thehive4py
```

**Version:** 1.0 | **Author:** Jan

---

### ioc_parser

**IOC Parser** - Extract and normalize Indicators of Compromise from text

Extracts and normalizes IOCs (IP addresses, domains, URLs, file hashes) from unstructured text. Useful for parsing threat intelligence reports, email bodies, or log files before adding observables to TheHive.

**Features:**
- Extract IPs (IPv4), domains, URLs, file hashes (MD5, SHA1, SHA256)
- Normalize IOC formats (lowercase domains, strip whitespace)
- Deduplicate extracted IOCs
- Defang/refang support (hxxp → http, [.] → .)
- Returns structured data ready for TheHive observable creation
- Zero external dependencies (pure stdlib)

**Usage:**
```python
from ioc_parser import extract_iocs, format_for_thehive

# Extract IOCs from text
text = """
Threat report: Malware contacted hxxp://evil[.]com
and IP 192.168.1.100. Hash: 5d41402abc4b2a76b9719d911017c592
"""

iocs = extract_iocs(text, refang=True)
print(iocs['ip'])      # ['192.168.1.100']
print(iocs['domain'])  # ['evil.com']
print(iocs['url'])     # ['http://evil.com']
print(iocs['md5'])     # ['5d41402abc4b2a76b9719d911017c592']

# Format for TheHive
observables = format_for_thehive(
    iocs,
    tlp=2,
    tags=['malware', 'apt'],
    message='Extracted from threat report'
)

# Each observable is ready to add to TheHive
for obs in observables:
    print(f"{obs['dataType']}: {obs['data']}")
```

**Dependencies:** None (pure Python stdlib)

**Version:** 1.0 | **Author:** Jan

---

### api_connector

**API Connector** - Bulletproof connection establishment and health checking for TheHive and Cortex

Provides reliable, health-checked API connections with intelligent error categorization. Each connection is immediately verified with a probe call to distinguish between configuration errors (bad credentials) and infrastructure problems (bad host/port, network issues).

**Features:**
- Automatic health checking for both TheHive and Cortex connections
- Intelligent error categorization (ValueError for config, ConnectionError for infrastructure)
- Environment variable support with explicit parameter override
- Detailed error messages with actionable hints
- Flexible logging (stdlib, loguru, or custom)

**Usage:**
```python
from api_connector import get_thehive_api, get_cortex_api

# Using environment variables
thehive_api = get_thehive_api()
cortex_api = get_cortex_api()

# Using explicit parameters
thehive_api = get_thehive_api(
    thehive_url='https://thehive.local:9000',
    api_key='your-thehive-key'
)

cortex_api = get_cortex_api(
    cortex_url='https://cortex.local:9001',
    api_key='your-cortex-key'
)

# With custom logger
from loguru import logger
api = get_thehive_api(logger=logger)

# Handle errors
try:
    api = get_thehive_api()
except ValueError as e:
    print(f"Configuration error: {e}")
except ConnectionError as e:
    print(f"Connection failed: {e}")
```

**Environment Variables:**
- `THEHIVE_URL` - TheHive instance URL
- `THEHIVE_API_KEY` - TheHive API key
- `CORTEX_URL` - Cortex instance URL
- `CORTEX_API_KEY` - Cortex API key

**Dependencies:** Requires both `thehive4py` and `cortex4py` libraries
```bash
pip install thehive4py cortex4py
```

**Version:** 1.0 | **Author:** Jan

---

### thehive_extended_api

**Extended TheHive API Operations** - Access endpoints not covered by thehive4py

Extends thehive4py functionality by providing direct access to TheHive API endpoints that aren't exposed in the library's public interface.
Designed for TheHive v3.4.0 environments where thehive4py==1.6.0 doesn't cover all available endpoints. Provides 15 functions across three categories: server operations, case manipulation, and observable operations.

**Features:**
- Server metadata access (status, connectors, custom fields, observable data types)
- Case manipulation (append tags without replace, append descriptions, update TLP/fields)
- Observable operations (get by ID, update with field filtering, tag management, TLP updates)
- Observable search (find by dataType + data pair for deduplication checking)
- Hybrid API pattern (accept existing API object OR url/key params for maximum flexibility)
- Environment variable support with explicit parameter override
- Intelligent error handling (ValueError for config, ConnectionError for infrastructure)

**Usage:**
```python
from thehive_extended_api import (
    case_append_tags, case_append_description,
    obs_append_tags, obsfind_any_by_type_data,
    get_custom_fields, get_connectors
)

# Case operations - append tags without replacing existing
case = case_append_tags('12345', ['malware', 'phishing'])

# Append to case description with titled separator
case = case_append_description(
    '12345',
    'Additional investigation findings',
    title='SIEM Analysis'
)

# Observable operations - append tags
obs = obs_append_tags('abc123def456', ['suspicious', 'external'])

# Search for observables by type + data (name-based for files)
duplicates = obsfind_any_by_type_data('ip', '192.168.1.100')
print(f"Found {len(duplicates)} existing IP observables")

# Find true duplicates by content (hash-based for files)
from thehive_extended_api import obsfind_dupes_by_id
similars = obsfind_dupes_by_id('abc123def456')  # obs_id
print(f"Found {len(similars)} files with same hash (excluding original)")

# Server metadata
fields = get_custom_fields()
for field in fields:
    print(f"{field['name']}: {field['type']}")

connectors = get_connectors()
for conn_type, servers in connectors.items():
    print(f"{conn_type}: {len(servers)} servers")

# Hybrid pattern - pass existing API object for efficiency
from thehive4py.api import TheHiveApi
api = TheHiveApi('https://thehive.local:9000', 'your-key')
case = case_append_tags('12345', ['test'], api=api)
obs = obs_append_tags('abc123', ['test'], api=api)
```

**Environment Variables:**
- `THEHIVE_URL` - TheHive instance URL
- `THEHIVE_API_KEY` - TheHive API key

**Dependencies:** Requires `thehive4py` and `requests` libraries
```bash
pip install thehive4py requests
```

**Functions:**
- **Server:** `get_status()`, `get_connectors()`, `get_custom_fields()`, `get_list_artifactDataType()`, `get_describe_model()`
- **Case:** `case_append_tags()`, `case_update_tlp()`, `case_append_description()`, `case_update_anyfield()`, `get_linked_cases()`
- **Observable:** `get_observable()`, `update_observable()`, `obs_append_tags()`, `obs_update_tlp()`, `obsfind_any_by_type_data()`, `obsfind_dupes_by_id()`

**Version:** 1.0 | **Author:** Jan

---

## Development Workflow

### Adding New Utilities

1. Create module in `modules/your_utility.py` following the template (see CLAUDE.md)
2. Include comprehensive docstring with all required sections
3. Create `dev-notes/your_utility.md` with manual test scenarios
4. Update this README with utility description and examples
5. Commit: `git commit -m "Add your_utility module"`

### Testing Utilities

Manual testing is used instead of automated tests. See `dev-notes/MODULE.md` for each module's test scenarios.

**Why manual testing?**
- Utilities are context-dependent (your TheHive instance vs. mine)
- Tests belong in target projects where utilities are used
- dev-notes provide clear guidance for verifying functionality

## Module Guidelines

All modules follow these principles:

- **Self-contained**: Single file, minimal dependencies
- **Well-documented**: Comprehensive docstring with examples
- **Typed**: Use type hints throughout
- **Logged**: Support flexible logging (stdlib, loguru, custom)
- **Error handling**: Graceful failures with descriptive errors
- **Environment variables**: Support TheHive auth via THEHIVE_URL and THEHIVE_API_KEY

## FAQ

**Q: Why not publish to PyPI?**

A: The utility belt approach provides instant availability, no package approvals, full code visibility, and easy modification. Perfect for corporate environments with restricted package installation.

**Q: How do I update a utility?**

A: Pull latest from git, re-copy the module to your project. Check `git log modules/MODULE_NAME.py` to see what changed.

**Q: Can I modify copied utilities?**

A: Absolutely! That's the point. Utilities are starting points for your specific needs. Fork the code and adapt it.

**Q: What about tests?**

A: Write tests in your target project where utilities are used. This repo provides manual test scenarios in `dev-notes/` as reference.

**Q: Do utilities depend on each other?**

A: No. Each module is independently copyable. No imports between modules.

**Q: What's the license?**

A: MIT License (see LICENSE file). Use freely in your projects.

## Project Structure

```
python-util-belt-thehive/
├── README.md              # This file - user-facing catalog
├── CLAUDE.md              # Developer guidance for future development
├── LICENSE                # MIT License
├── .gitignore             # Standard Python ignores
├── UTILITY_BELT_SEED_THEHIVE.md  # Complete architectural blueprint
├── modules/               # Self-contained utility modules
│   ├── thehive_search.py  # TheHive API search helper
│   ├── ioc_parser.py      # IOC extraction and normalization
│   ├── api_connector.py   # Connection establishment and health checking
│   └── thehive_extended_api.py  # Extended TheHive API operations
├── dev-notes/             # Manual testing reference guides
│   ├── thehive_search.md  # Test scenarios for thehive_search
│   ├── ioc_parser.md      # Test scenarios for ioc_parser
│   ├── api_connector.md   # Test scenarios for api_connector
│   └── thehive_extended_api.md  # Test scenarios for thehive_extended_api
└── scripts/               # Helper tools
    ├── copy_module.sh     # Copy module to target project
    └── list_modules.py    # List available modules with metadata
```

## Contributing

This is a personal utility belt, but contributions are welcome:

1. Follow the module template (see CLAUDE.md)
2. Include comprehensive docstring
3. Create dev-notes with test scenarios
4. Keep modules self-contained
5. Prefer stdlib over external dependencies (except thehive4py for API modules)

## Resources

- **TheHive Platform**: https://thehive-project.org/
- **TheHive4py Library**: https://github.com/TheHive-Project/TheHive4py
- **TheHive API Docs**: https://docs.thehive-project.org/thehive/

## License

MIT License - See LICENSE file for full text.

## Author

Jan Wychowaniak - 2026
