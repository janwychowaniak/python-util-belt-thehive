# dev-notes: thehive_search.py

Manual test scenarios for the thehive_search module.

## Test Configuration

```sh
# Environment setup (add to your env or run before tests)
export THEHIVE_URL="https://thehive.example.com"
export THEHIVE_API_KEY="your-test-api-key-here"
```

```python
# Test constants
TEST_CASE_ID_OPEN = '~12345'     # Known open case in test instance
TEST_CASE_ID_CLOSED = '~12346'   # Known closed case
TEST_CASE_ID_INVALID = '~99999'  # Non-existent case ID
TEST_TAG_PHISHING = 'phishing'   # Commonly used tag
TEST_TAG_RARE = 'very-rare-tag'  # Tag with few/no cases
```

## Test Scenarios

### Scenario 1: Basic Search (No Filters)

```python
from thehive_search import search_cases

# Should return all cases (up to max_results limit)
cases = search_cases(max_results=10)
print(f"Found {len(cases)} cases")  # Expected: 10 or fewer

# Verify structure
if cases:
    case = cases[0]
    assert 'caseId' in case
    assert 'title' in case
    assert 'status' in case
    print("✓ Case structure valid")
```

### Scenario 2: Status Filter

```python
from thehive_search import search_cases

# Find open cases
open_cases = search_cases(status='Open')
print(f"Open cases: {len(open_cases)}")  # Expected: varies

# Verify all cases have status='Open'
assert all(c['status'] == 'Open' for c in open_cases)
print("✓ Status filter working")

# Find resolved cases
resolved = search_cases(status='Resolved')
print(f"Resolved cases: {len(resolved)}")  # Expected: varies
```

### Scenario 3: Severity Filter

```python
from thehive_search import search_cases

# Find high cases (severity 3)
high = search_cases(severity=3)
print(f"High cases: {len(high)}")  # Expected: varies

# Find medium or high cases (severity 2 or 3)
med_high = search_cases(severity=[2, 3])
print(f"Medium/High cases: {len(med_high)}")  # Expected: >= len(high)
print("✓ Severity filter working")
```

### Scenario 4: Combined Filters

```python
from thehive_search import search_cases

# Find open, high-severity phishing cases
cases = search_cases(
    status='Open',
    severity=3,
    tags=['phishing']
)
print(f"Open high-severity phishing cases: {len(cases)}")  # Expected: varies

# Verify filters applied
for case in cases:
    assert case['status'] == 'Open'
    assert case['severity'] == 3
    assert 'phishing' in case.get('tags', [])
print("✓ Combined filters working")
```

### Scenario 5: Get Case by ID

```python
from thehive_search import get_case_by_id

# Fetch known case
case = get_case_by_id(TEST_CASE_ID_OPEN)
assert case is not None
assert case['id'] == TEST_CASE_ID_OPEN
print(f"✓ Retrieved case: {case['title']}")

# Fetch non-existent case
case = get_case_by_id(TEST_CASE_ID_INVALID)
assert case is None
print("✓ Invalid case returns None")
```

### Scenario 6: Custom Logger (loguru)

```python
from loguru import logger
from thehive_search import search_cases

logger.add("thehive_search.log", rotation="1 MB")

cases = search_cases(status='Open', logger=logger)
print(f"Found {len(cases)} cases (logged to file)")
print("✓ Custom logger working")
```

### Scenario 7: Explicit Authentication

```python
from thehive_search import search_cases

# Explicit URL and API key (not using env vars)
cases = search_cases(
    status='Open',
    thehive_url='https://thehive.prod.example.com',
    api_key='prod-api-key-here'
)
print(f"Found {len(cases)} cases in prod")
print("✓ Explicit auth working")
```

### Scenario 8: Error Handling

```python
from thehive_search import search_cases

# Missing credentials (no env vars, no explicit params)
try:
    cases = search_cases(status='Open')  # Should raise ValueError
    print("✗ Should have raised ValueError")
except ValueError as e:
    print(f"✓ Correctly raised ValueError: {e}")

# Invalid TheHive URL
try:
    cases = search_cases(
        status='Open',
        thehive_url='http://invalid-url',
        api_key='fake-key'
    )  # Should raise ConnectionError or return []
    print("Result:", cases)  # Expected: [] (empty list on connection failure)
except ConnectionError as e:
    print(f"✓ Connection error caught: {e}")
```

## Expected Results Summary

| Scenario | Expected Output | Notes |
|----------|----------------|-------|
| Basic search | 0-10 cases | Depends on test instance |
| Status='Open' | List of open cases | All have status='Open' |
| Severity=4 | Critical cases only | All have severity=4 |
| Combined filters | Cases matching ALL filters | AND logic, not OR |
| get_case_by_id (valid) | Case dict | Contains caseId, title, etc. |
| get_case_by_id (invalid) | None | Not found |
| Custom logger | Cases + log file | Check log file created |
| Explicit auth | Cases from specified instance | Ignores env vars |
| Missing credentials | ValueError raised | Clear error message |
| Invalid URL | ConnectionError or [] | Graceful failure |

## Common Issues

**Issue: "TheHive URL not provided"**
- **Cause**: THEHIVE_URL env var not set and no explicit URL passed
- **Fix**: `export THEHIVE_URL="https://thehive.example.com"` or pass `thehive_url=` param

**Issue: "API key not provided"**
- **Cause**: THEHIVE_API_KEY env var not set and no explicit key passed
- **Fix**: `export THEHIVE_API_KEY="your-key"` or pass `api_key=` param

**Issue: Search returns []**
- **Cause**: Either no matching cases OR connection failure (check logs)
- **Debug**: Enable logging to see API responses

**Issue: "Cannot connect to TheHive"**
- **Cause**: Network issue, wrong URL, firewall, or TheHive down
- **Debug**: Test with `curl https://thehive.example.com` first

## Development Notes

- TheHive API pagination: use `range` parameter (e.g., '0-100', '100-200')
- Case IDs are strings (TheHive v4: with '~' prefix, e.g., '~12345')
- Tags are AND-filtered: case must have ALL specified tags
- Query builder uses thehive4py.query (Eq, In, And)
- API responses are requests.Response objects; check status_code before .json()
