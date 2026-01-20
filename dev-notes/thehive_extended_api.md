# dev-notes: thehive_extended_api.py

Manual test scenarios for the thehive_extended_api module.

## Test Configuration

```sh
# Environment setup (add to your env or run before tests)
export THEHIVE_URL="https://thehive.example.com:9000"
export THEHIVE_API_KEY="your-test-api-key-here"
```

```python
THEHIVE_URL = "https://thehive.example.com:9000"
THEHIVE_API_KEY = "your-test-api-key-here"
# Test constants
TEST_CASE_ID = '~12345'           # Known case ID in test instance
TEST_CASE_ID_INVALID = '~99999'   # Non-existent case ID
TEST_OBS_ID_IP = 'abc123def456'   # Known IP observable ID
TEST_OBS_ID_FILE = 'def789ghi012' # Known file observable ID
TEST_OBS_ID_INVALID = 'notfound'  # Non-existent observable ID
TEST_DATATYPE_IP = 'ip'
TEST_DATA_IP = '192.168.1.100'    # Known IP in test instance
TEST_DATATYPE_DOMAIN = 'domain'
TEST_DATA_DOMAIN = 'evil.com'     # Known domain in test instance
TEST_FILENAME = 'malware.exe'     # Known file name in test instance
```

## Test Scenarios

### Group A: Server Operations

#### Scenario A1: Get Server Status

```python
from thehive_extended_api import get_status

# Fetch server status
status = get_status()
print(f"TheHive version: {status['versions']['TheHive']}")  # Expected: '3.4.0-1' or similar
print(f"Health: {status.get('health', {})}")
print("✓ Server status retrieved")

# Verify structure
assert 'versions' in status
assert 'TheHive' in status['versions']
```

#### Scenario A2: Get Connectors

```python
from thehive_extended_api import get_connectors

# Fetch connector info
connectors = get_connectors()
print(f"Found {len(connectors)} connector types")  # Expected: varies

for conn_type, servers in connectors.items():
    print(f"{conn_type}: {len(servers)} servers")
    for srv in servers:
        print(f"  - {srv['name']}: {srv['status']}")  # Expected: 'OK' or 'ERROR'

print("✓ Connectors retrieved")
```

#### Scenario A3: Get Custom Fields

```python
from thehive_extended_api import get_custom_fields

# Fetch custom field definitions
fields = get_custom_fields()
print(f"Found {len(fields)} custom fields")  # Expected: varies

for field in fields:
    print(f"  {field['name']}: {field['type']}")  # Expected: string, number, boolean, date, etc.

print("✓ Custom fields retrieved")
```

#### Scenario A4: Get Observable Data Types

```python
from thehive_extended_api import get_list_artifactDataType

# Fetch available observable types
data_types = get_list_artifactDataType()
print(f"Found {len(data_types)} data types")  # Expected: 15-30 types

# Verify common types exist
assert 'ip' in data_types.values()
assert 'domain' in data_types.values()
assert 'hash' in data_types.values()
assert 'file' in data_types.values()
print("✓ Observable data types retrieved")
```

#### Scenario A5: Get Model Description

```python
from thehive_extended_api import get_describe_model

# Describe case model
case_schema = get_describe_model('case')
print(f"Case model attributes: {list(case_schema.keys())}")

# Describe observable model
obs_schema = get_describe_model('case_artifact')
print(f"Observable model attributes: {list(obs_schema.keys())}")

print("✓ Model descriptions retrieved")

# Test invalid model
try:
    get_describe_model('invalid_model')
    print("✗ Should have raised ValueError")
except ValueError as e:
    print(f"✓ Invalid model raises ValueError: {e}")
```

### Group B: Case Operations

#### Scenario B1: Append Tags to Case

```python
from thehive_extended_api import case_append_tags
from thehive4py.api import TheHiveApi

# Setup (fetch current tags)
api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)
case_before = api.get_case(TEST_CASE_ID).json()
tags_before = set(case_before.get('tags', []))
print(f"Tags before: {sorted(tags_before)}")

# Append new tags
new_tags = ['test-tag-1', 'test-tag-2']
case_after = case_append_tags(TEST_CASE_ID, new_tags)
tags_after = set(case_after.get('tags', []))
print(f"Tags after: {sorted(tags_after)}")

# Verify merge (old + new)
assert tags_before.issubset(tags_after)
assert 'test-tag-1' in tags_after
assert 'test-tag-2' in tags_after
print("✓ Tags appended successfully")
```

#### Scenario B2: Append Tags with Duplicates (Deduplication)

```python
from thehive_extended_api import case_append_tags

# Append tags that already exist
existing_tags = ['test-tag-1']  # Assuming this tag already exists from B1
case = case_append_tags(TEST_CASE_ID, existing_tags)
tags = case.get('tags', [])

# Count occurrences of test-tag-1
count = tags.count('test-tag-1')
assert count == 1, f"Tag duplicated: found {count} occurrences"
print("✓ Duplicate tags deduplicated correctly")
```

#### Scenario B3: Update Case TLP

```python
from thehive_extended_api import case_update_tlp

# Update to AMBER (2)
case = case_update_tlp(TEST_CASE_ID, 2)
assert case.get('tlp') == 2 or case['tlp'] == 2
print(f"✓ Case TLP updated to AMBER: {case['tlp']}")

# Update to RED (3)
case = case_update_tlp(TEST_CASE_ID, 3)
assert case.get('tlp') == 3 or case['tlp'] == 3
print(f"✓ Case TLP updated to RED: {case['tlp']}")

# Test invalid TLP
try:
    case_update_tlp(TEST_CASE_ID, 5)
    print("✗ Should have raised ValueError")
except ValueError as e:
    print(f"✓ Invalid TLP raises ValueError: {e}")
```

#### Scenario B4: Append to Case Description

```python
from thehive_extended_api import case_append_description
from thehive4py.api import TheHiveApi

# Fetch current description
api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)
case_before = api.get_case(TEST_CASE_ID).json()
desc_before = case_before.get('description', '')
desc_len_before = len(desc_before)
print(f"Description length before: {desc_len_before}")

# Append new content with title
new_content = "Additional investigation findings from SIEM analysis."
case_after = case_append_description(TEST_CASE_ID, new_content, title='SIEM Analysis')

# Fetch updated description
case_updated = api.get_case(TEST_CASE_ID).json()
desc_after = case_updated.get('description', '')
desc_len_after = len(desc_after)
print(f"Description length after: {desc_len_after}")

# Verify append
assert desc_len_after > desc_len_before
assert new_content in desc_after
assert 'SIEM Analysis' in desc_after  # Title in separator bar
print("✓ Description appended successfully")
```

#### Scenario B5: Update Arbitrary Case Field

```python
from thehive_extended_api import case_update_anyfield

# Update status field
case = case_update_anyfield(TEST_CASE_ID, {'status': 'Open'})
assert case.get('status') == 'Open' or case['status'] == 'Open'
print(f"✓ Case status updated to Open")

# Update multiple fields
case = case_update_anyfield(TEST_CASE_ID, {
    'severity': 2,
    'flag': True
})
assert case.get('severity') == 2 or case['severity'] == 2
print(f"✓ Multiple fields updated")
```

#### Scenario B6: Get Linked Cases

```python
from thehive_extended_api import get_linked_cases

# Fetch linked cases
linked = get_linked_cases(TEST_CASE_ID)
print(f"Found {len(linked)} linked cases")  # Expected: varies

if linked:
    for case in linked:
        print(f"  Linked case: {case.get('caseId', 'N/A')} - {case.get('title', 'N/A')}")

print("✓ Linked cases retrieved")
```

#### Scenario B7: Error Handling - Non-existent Case

```python
from thehive_extended_api import case_append_tags

# Try to update non-existent case
try:
    case_append_tags(TEST_CASE_ID_INVALID, ['test-tag'])
    print("✗ Should have raised ValueError")
except ValueError as e:
    assert 'not found' in str(e).lower()
    print(f"✓ Non-existent case raises ValueError: {e}")
```

### Group C: Observable Operations

#### Scenario C1: Get Observable by ID

```python
from thehive_extended_api import get_observable

# Fetch existing observable
obs = get_observable(TEST_OBS_ID_IP)
assert obs is not None
print(f"✓ Observable retrieved: {obs['dataType']} = {obs['data']}")

# Verify structure
assert 'id' in obs
assert 'dataType' in obs
assert 'data' in obs
assert 'tlp' in obs
assert 'tags' in obs

# Fetch non-existent observable
obs_invalid = get_observable(TEST_OBS_ID_INVALID)
assert obs_invalid is None
print("✓ Non-existent observable returns None")
```

#### Scenario C2: Update Observable (Field Filtering)

```python
from thehive_extended_api import get_observable, update_observable

# Fetch observable
obs = get_observable(TEST_OBS_ID_IP)
original_message = obs.get('message', '')
print(f"Original message: {original_message}")

# Update only message field
obs['message'] = 'Updated via extended API test'
updated_obs = update_observable(obs, fields=['message'])

assert updated_obs['message'] == 'Updated via extended API test'
print("✓ Observable updated (single field)")

# Update multiple fields
obs['ioc'] = True
obs['sighted'] = True
updated_obs = update_observable(obs, fields=['ioc', 'sighted'])

assert updated_obs['ioc'] == True
assert updated_obs['sighted'] == True
print("✓ Observable updated (multiple fields)")
```

#### Scenario C3: Append Tags to Observable

```python
from thehive_extended_api import obs_append_tags, get_observable

# Fetch current tags
obs_before = get_observable(TEST_OBS_ID_IP)
tags_before = obs_before.get('tags', [])
tags_count_before = len(tags_before)
print(f"Tags before: {tags_before}")

# Append new tags
new_tags = ['test-obs-tag-1', 'test-obs-tag-2']
obs_after = obs_append_tags(TEST_OBS_ID_IP, new_tags)
tags_after = obs_after.get('tags', [])
tags_count_after = len(tags_after)
print(f"Tags after: {tags_after}")

# Verify tags added
assert tags_count_after >= tags_count_before
assert 'test-obs-tag-1' in tags_after
assert 'test-obs-tag-2' in tags_after
print("✓ Tags appended to observable")
```

#### Scenario C4: Update Observable TLP

```python
from thehive_extended_api import obs_update_tlp, get_observable

# Update to GREEN (1)
obs = obs_update_tlp(TEST_OBS_ID_IP, 1)
assert obs['tlp'] == 1
print(f"✓ Observable TLP updated to GREEN")

# Update to AMBER (2)
obs = obs_update_tlp(TEST_OBS_ID_IP, 2)
assert obs['tlp'] == 2
print(f"✓ Observable TLP updated to AMBER")

# Test invalid TLP
try:
    obs_update_tlp(TEST_OBS_ID_IP, 10)
    print("✗ Should have raised ValueError")
except ValueError as e:
    print(f"✓ Invalid TLP raises ValueError: {e}")
```

#### Scenario C5: Search Observables by Type + Data (IP)

```python
from thehive_extended_api import obsfind_any_by_type_data

# Search for IP observables
results = obsfind_any_by_type_data('ip', TEST_DATA_IP)
print(f"Found {len(results)} observables for IP {TEST_DATA_IP}")

# Verify all results match search criteria
for obs in results:
    assert obs['dataType'] == 'ip'
    assert obs['data'] == TEST_DATA_IP
    print(f"  Case: {obs.get('_parent', 'N/A')}, ID: {obs['id']}")

print("✓ IP observable search working")
```

#### Scenario C6: Search Observables by Type + Data (Domain)

```python
from thehive_extended_api import obsfind_any_by_type_data

# Search for domain observables
results = obsfind_any_by_type_data('domain', TEST_DATA_DOMAIN)
print(f"Found {len(results)} observables for domain {TEST_DATA_DOMAIN}")

# Verify results
for obs in results:
    assert obs['dataType'] == 'domain'
    assert obs['data'] == TEST_DATA_DOMAIN

print("✓ Domain observable search working")
```

#### Scenario C7: Search Observables by Type + Data (File - by name)

```python
from thehive_extended_api import obsfind_any_by_type_data

# Note: File search is by name, not hash
results = obsfind_any_by_type_data('file', TEST_FILENAME)
print(f"Found {len(results)} file observables named '{TEST_FILENAME}'")

# Verify all results have matching filename
for obs in results:
    assert obs['dataType'] == 'file'
    assert 'attachment' in obs
    assert obs['attachment']['name'] == TEST_FILENAME
    print(f"  Case: {obs.get('_parent', 'N/A')}, Hash: {obs['attachment']['id']}")

print("✓ File observable search working")
```

#### Scenario C8: Search with No Results

```python
from thehive_extended_api import obsfind_any_by_type_data

# Search for non-existent observable
results = obsfind_any_by_type_data('ip', '255.255.255.255')
assert len(results) == 0
print("✓ No results handled gracefully")
```

#### Scenario C9: Find Similar Observables by ID (Hash-based for Files)

```python
from thehive_extended_api import obsfind_dupes_by_id, get_observable

# Fetch a file observable
file_obs = get_observable(TEST_OBS_ID_FILE)
print(f"Original file: {file_obs['attachment']['name']}")
print(f"Hash: {file_obs['attachment']['id']}")

# Find all files with same hash (content-based duplicates)
similars = obsfind_dupes_by_id(TEST_OBS_ID_FILE)
print(f"Found {len(similars)} similar files (same hash)")

# Verify all have same hash but may have different names
original_hash = file_obs['attachment']['id']
for similar in similars:
    assert similar['dataType'] == 'file'
    assert similar['attachment']['id'] == original_hash
    assert similar['id'] != TEST_OBS_ID_FILE  # Original excluded
    print(f"  Similar file: {similar['attachment']['name']} (Case: {similar.get('_parent')})")

print("✓ Hash-based file duplicate detection working")
```

#### Scenario C10: Find Similar Observables by ID (Value-based for Non-files)

```python
from thehive_extended_api import obsfind_dupes_by_id, get_observable

# Fetch an IP observable
ip_obs = get_observable(TEST_OBS_ID_IP)
print(f"Original IP: {ip_obs['data']}")

# Find all observables with same IP
similars = obsfind_dupes_by_id(TEST_OBS_ID_IP)
print(f"Found {len(similars)} similar IPs")

# Verify all have same data value
original_data = ip_obs['data']
for similar in similars:
    assert similar['dataType'] == 'ip'
    assert similar['data'] == original_data
    assert similar['id'] != TEST_OBS_ID_IP  # Original excluded
    print(f"  Similar IP in case: {similar.get('_parent')}")

print("✓ Value-based non-file duplicate detection working")
```

#### Scenario C11: Compare Name-based vs Hash-based File Search

```python
from thehive_extended_api import (
    obsfind_any_by_type_data,
    obsfind_dupes_by_id,
    get_observable
)

# Assume we have a file observable
file_obs = get_observable(TEST_OBS_ID_FILE)
filename = file_obs['attachment']['name']
file_hash = file_obs['attachment']['id']

print(f"Searching for file: {filename} (hash: {file_hash})")

# Name-based search (finds files with same name)
by_name = obsfind_any_by_type_data('file', filename)
print(f"Name-based search: {len(by_name)} files named '{filename}'")

# Hash-based search (finds files with same content, any name)
by_hash = obsfind_dupes_by_id(TEST_OBS_ID_FILE)
print(f"Hash-based search: {len(by_hash)} files with same hash")

# Hash-based may find more (if same file renamed) or same amount
print("✓ Name vs hash search comparison complete")
print(f"  Files with same name: {len(by_name)}")
print(f"  Files with same content: {len(by_hash)}")
```

#### Scenario C12: Error Handling - Non-existent Observable

```python
from thehive_extended_api import obs_append_tags

# Try to update non-existent observable
try:
    obs_append_tags(TEST_OBS_ID_INVALID, ['test-tag'])
    print("✗ Should have raised ValueError")
except ValueError as e:
    assert 'not found' in str(e).lower()
    print(f"✓ Non-existent observable raises ValueError: {e}")
```

### Group D: Hybrid API Pattern

#### Scenario D1: Using Existing API Object

```python
from thehive4py.api import TheHiveApi
from thehive_extended_api import case_append_tags, get_observable

# Create API object once
api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)

# Pass to multiple functions
case = case_append_tags(TEST_CASE_ID, ['api-object-test'], api=api)
obs = get_observable(TEST_OBS_ID_IP, api=api)

print("✓ API object passed successfully")
```

#### Scenario D2: Using Explicit URL/Key Parameters

```python
from thehive_extended_api import get_status, get_custom_fields

# Explicit credentials (not using env vars)
status = get_status(
    thehive_url=THEHIVE_URL,
    api_key=THEHIVE_API_KEY
)
print(f"✓ Explicit credentials working: {status['versions']['TheHive']}")

# Works for all functions
fields = get_custom_fields(
    thehive_url=THEHIVE_URL,
    api_key=THEHIVE_API_KEY
)
print(f"✓ Found {len(fields)} custom fields")
```

#### Scenario D3: Using Environment Variables Only

```python
import os
from thehive_extended_api import get_status, case_append_tags

# Ensure env vars are set
assert 'THEHIVE_URL' in os.environ
assert 'THEHIVE_API_KEY' in os.environ

# Call without any auth parameters
status = get_status()
print(f"✓ Env vars working: {status['versions']['TheHive']}")

case = case_append_tags(TEST_CASE_ID, ['env-var-test'])
print("✓ All functions work with env vars")
```

## Expected Results Summary

| Scenario                         | Expected Output                   | Notes                            |
| -------------------------------- | --------------------------------- | -------------------------------- |
| A1: get_status                   | Dict with versions, config        | Contains TheHive version         |
| A2: get_connectors               | Dict of connector types → servers | May be empty if no connectors    |
| A3: get_custom_fields            | List of field defs                | May be empty if no custom fields |
| A4: get_list_artifactDataType    | List of 15-30 data types          | Always has 'ip', 'domain', etc.  |
| A5: get_describe_model           | Dict of model schema              | Invalid model raises ValueError  |
| B1: case_append_tags             | Updated case with merged tags     | Old + new tags                   |
| B2: Tag deduplication            | No duplicate tags                 | Same tag added twice = once      |
| B3: case_update_tlp              | Updated case with new TLP         | TLP 0-3 only                     |
| B4: case_append_description      | Longer description                | Preserves old + adds new         |
| B5: case_update_anyfield         | Updated case                      | Any valid field                  |
| B6: get_linked_cases             | List of linked cases              | May be empty                     |
| B7: Non-existent case            | ValueError raised                 | Clear error message              |
| C1: get_observable               | Observable dict or None           | None if not found                |
| C2: update_observable            | Updated observable                | Field filtering works            |
| C3: obs_append_tags              | Observable with more tags         | Tags added                       |
| C4: obs_update_tlp               | Observable with new TLP           | TLP 0-3 only                     |
| C5-C7: Search by type/data       | List of matching observables      | May be empty                     |
| C8: Search no results            | Empty list                        | Graceful                         |
| C9: Hash-based file search       | Files with same hash              | Excludes original                |
| C10: Value-based non-file search | Observables with same value       | Excludes original                |
| C11: Name vs hash comparison     | Different result counts           | Name-based may differ from hash  |
| C12: Non-existent observable     | ValueError raised                 | Clear error message              |
| D1: API object                   | Functions work                    | Reuses connection                |
| D2: Explicit auth                | Functions work                    | Ignores env vars                 |
| D3: Env vars                     | Functions work                    | Default behavior                 |

## Common Issues

**Issue: "TheHive URL not provided"**
- **Cause**: THEHIVE_URL env var not set and no explicit URL passed
- **Fix**: `export THEHIVE_URL="https://thehive.example.com:9000"` or pass `thehive_url=` param

**Issue: "API key not provided"**
- **Cause**: THEHIVE_API_KEY env var not set and no explicit key passed
- **Fix**: `export THEHIVE_API_KEY="your-key"` or pass `api_key=` param

**Issue: "Observable not found" when it exists**
- **Cause**: Wrong observable ID format (check hex string)
- **Debug**: Verify observable ID from TheHive UI (not the \_id field, use the id field)

**Issue: File search returns wrong results**
- **Cause**: Searching by filename is fuzzy (uses String query), then filtered to exact
- **Note**: Use `obsfind_any_by_type_data()` for name-based search, `obsfind_dupes_by_id()` for hash-based (content) search

**Issue: Tags not deduplicating**
- **Cause**: Only case_append_tags deduplicates; obs_append_tags does not (matches original behavior)
- **Workaround**: Manually dedupe before calling obs_append_tags if needed

**Issue: "Cannot connect to TheHive"**
- **Cause**: Network issue, wrong URL, firewall, or TheHive down
- **Debug**: Test with `curl https://thehive.example.com:9000/api/status` first

**Issue: 401 Unauthorized**
- **Cause**: Invalid API key
- **Fix**: Verify API key in TheHive UI (User settings → API Keys)

## Development Notes

- **TheHive v3.4.0 specific**: This module was designed for TheHive v3.4.0 and thehive4py==1.6.0
- **API object reuse**: Passing `api=` parameter is more efficient for multiple operations
- **Case ID format**: TheHive uses both integer IDs and '~12345' format; both work
- **Observable IDs**: Always hex strings (e.g., 'abc123def456789')
- **File observables - Two search modes**:
  - `obsfind_any_by_type_data('file', name)` - Searches by **filename** (finds files with same name)
  - `obsfind_dupes_by_id(obs_id)` - Searches by **hash** for files (finds true duplicates regardless of name)
  - Hash is stored in `attachment['id']` (primary) and `attachment['hashes']` (list)
- **Use case distinction**:
  - Name-based: "Find all files called 'invoice.pdf'" (same name, potentially different content)
  - Hash-based: "Find all copies of this file" (same content, potentially different names)
- **Tag operations**: case_append_tags deduplicates; obs_append_tags does not (by design)
- **Error categorization**: ValueError = config/input error, ConnectionError = infrastructure error
- **TLP levels**: 0=WHITE, 1=GREEN, 2=AMBER, 3=RED
- **Description append format**: Uses separator bar with optional title (`--- [Title] ---`)
- **Query builder**: Uses thehive4py.query (String, And, Eq) for searches
- **Requests library**: Used directly for endpoints not exposed by thehive4py
- **Connection details**: Extracted from API object (url, auth, proxies, cert)
