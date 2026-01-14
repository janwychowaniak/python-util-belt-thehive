# dev-notes: api_connector.py

Manual test scenarios for the api_connector module.

## Test Configuration

```bash
# TheHive configuration
export THEHIVE_URL="https://thehive.example.com:9000"
export THEHIVE_API_KEY="your-thehive-test-api-key"

# Cortex configuration
export CORTEX_URL="https://cortex.example.com:9001"
export CORTEX_API_KEY="your-cortex-test-api-key"
```

```python
# Test constants (replace with your actual test values)
VALID_THEHIVE_URL = "https://thehive.example.com:9000"
VALID_THEHIVE_KEY = "your-valid-thehive-key"
INVALID_THEHIVE_KEY = "INVALID_KEY_12345"
BAD_THEHIVE_HOST = "https://nonexistent.host.local:9000"
BAD_THEHIVE_PORT = "https://thehive.example.com:9999"

VALID_CORTEX_URL = "https://cortex.example.com:9001"
VALID_CORTEX_KEY = "your-valid-cortex-key"
INVALID_CORTEX_KEY = "INVALID_KEY_67890"
BAD_CORTEX_HOST = "https://nonexistent.host.local:9001"
BAD_CORTEX_PORT = "https://cortex.example.com:9999"
```

## Test Scenarios

### TheHive Tests

#### Scenario 1: Valid TheHive Connection (Environment Variables)

```python
from api_connector import get_thehive_api

# Assumes THEHIVE_URL and THEHIVE_API_KEY env vars are set
try:
    api = get_thehive_api()
    print(f"✓ Successfully connected to TheHive")

    # Verify we can use the API
    user = api.get_current_user()
    print(f"  Connected as: {user.json()}")
except ValueError as e:
    print(f"✗ Configuration error: {e}")
except ConnectionError as e:
    print(f"✗ Connection error: {e}")
```

#### Scenario 2: Valid TheHive Connection (Explicit Parameters)

```python
from api_connector import get_thehive_api

try:
    api = get_thehive_api(
        thehive_url=VALID_THEHIVE_URL,
        api_key=VALID_THEHIVE_KEY
    )
    print(f"✓ Successfully connected to TheHive with explicit params")

    # Verify API works
    user = api.get_current_user()
    print(f"  Connected as user: {user.json().get('name', 'Unknown')}")
except Exception as e:
    print(f"✗ Unexpected error: {e}")
```

#### Scenario 3: Invalid TheHive API Key (401)

```python
from api_connector import get_thehive_api

try:
    api = get_thehive_api(
        thehive_url=VALID_THEHIVE_URL,
        api_key=INVALID_THEHIVE_KEY
    )
    print("✗ Should have raised ValueError for invalid API key")
except ValueError as e:
    print(f"✓ Correctly raised ValueError: {e}")
    assert "Invalid API key" in str(e)
    assert "THEHIVE_API_KEY" in str(e)
except Exception as e:
    print(f"✗ Wrong exception type: {type(e).__name__}: {e}")
```

#### Scenario 4: Invalid TheHive Host (502)

```python
from api_connector import get_thehive_api

try:
    api = get_thehive_api(
        thehive_url=BAD_THEHIVE_HOST,
        api_key=VALID_THEHIVE_KEY
    )
    print("✗ Should have raised ConnectionError for bad host")
except ConnectionError as e:
    print(f"✓ Correctly raised ConnectionError: {e}")
    assert "Cannot connect" in str(e) or "hostname" in str(e).lower()
except Exception as e:
    print(f"✗ Wrong exception type: {type(e).__name__}: {e}")
```

#### Scenario 5: Invalid TheHive Port (Connection Refused)

```python
from api_connector import get_thehive_api

try:
    api = get_thehive_api(
        thehive_url=BAD_THEHIVE_PORT,
        api_key=VALID_THEHIVE_KEY
    )
    print("✗ Should have raised ConnectionError for bad port")
except ConnectionError as e:
    print(f"✓ Correctly raised ConnectionError: {e}")
    assert "port" in str(e).lower() or "connectivity" in str(e).lower()
except Exception as e:
    print(f"✗ Wrong exception type: {type(e).__name__}: {e}")
```

#### Scenario 6: Missing TheHive Credentials

```python
from api_connector import get_thehive_api
import os

# Temporarily clear environment variables
original_url = os.environ.get('THEHIVE_URL')
original_key = os.environ.get('THEHIVE_API_KEY')

try:
    if 'THEHIVE_URL' in os.environ:
        del os.environ['THEHIVE_URL']
    if 'THEHIVE_API_KEY' in os.environ:
        del os.environ['THEHIVE_API_KEY']

    api = get_thehive_api()
    print("✗ Should have raised ValueError for missing credentials")
except ValueError as e:
    print(f"✓ Correctly raised ValueError: {e}")
    assert "not provided" in str(e)
finally:
    # Restore environment variables
    if original_url:
        os.environ['THEHIVE_URL'] = original_url
    if original_key:
        os.environ['THEHIVE_API_KEY'] = original_key
```

### Cortex Tests

#### Scenario 7: Valid Cortex Connection (Environment Variables)

```python
from api_connector import get_cortex_api

# Assumes CORTEX_URL and CORTEX_API_KEY env vars are set
try:
    api = get_cortex_api()
    print(f"✓ Successfully connected to Cortex")

    # Verify we can use the API
    analyzers = api.analyzers.find_all({})
    print(f"  Found {len(analyzers)} analyzers")
except ValueError as e:
    print(f"✗ Configuration error: {e}")
except ConnectionError as e:
    print(f"✗ Connection error: {e}")
```

#### Scenario 8: Valid Cortex Connection (Explicit Parameters)

```python
from api_connector import get_cortex_api

try:
    api = get_cortex_api(
        cortex_url=VALID_CORTEX_URL,
        api_key=VALID_CORTEX_KEY
    )
    print(f"✓ Successfully connected to Cortex with explicit params")

    # Verify API works
    analyzers = api.analyzers.find_all({})
    print(f"  Found {len(analyzers)} analyzers")
except Exception as e:
    print(f"✗ Unexpected error: {e}")
```

#### Scenario 9: Invalid Cortex API Key (AuthenticationError)

```python
from api_connector import get_cortex_api

try:
    api = get_cortex_api(
        cortex_url=VALID_CORTEX_URL,
        api_key=INVALID_CORTEX_KEY
    )
    print("✗ Should have raised ValueError for invalid API key")
except ValueError as e:
    print(f"✓ Correctly raised ValueError: {e}")
    assert "Invalid API key" in str(e)
    assert "CORTEX_API_KEY" in str(e)
except Exception as e:
    print(f"✗ Wrong exception type: {type(e).__name__}: {e}")
```

#### Scenario 10: Invalid Cortex Host (InvalidInputError)

```python
from api_connector import get_cortex_api

try:
    api = get_cortex_api(
        cortex_url=BAD_CORTEX_HOST,
        api_key=VALID_CORTEX_KEY
    )
    print("✗ Should have raised ConnectionError for bad host")
except ConnectionError as e:
    print(f"✓ Correctly raised ConnectionError: {e}")
    assert "Cannot connect" in str(e) or "network" in str(e).lower()
except Exception as e:
    print(f"✗ Wrong exception type: {type(e).__name__}: {e}")
```

#### Scenario 11: Invalid Cortex Port (ServiceUnavailableError)

```python
from api_connector import get_cortex_api

try:
    api = get_cortex_api(
        cortex_url=BAD_CORTEX_PORT,
        api_key=VALID_CORTEX_KEY
    )
    print("✗ Should have raised ConnectionError for bad port")
except ConnectionError as e:
    print(f"✓ Correctly raised ConnectionError: {e}")
    assert "port" in str(e).lower() or "service" in str(e).lower()
except Exception as e:
    print(f"✗ Wrong exception type: {type(e).__name__}: {e}")
```

#### Scenario 12: Missing Cortex Credentials

```python
from api_connector import get_cortex_api
import os

# Temporarily clear environment variables
original_url = os.environ.get('CORTEX_URL')
original_key = os.environ.get('CORTEX_API_KEY')

try:
    if 'CORTEX_URL' in os.environ:
        del os.environ['CORTEX_URL']
    if 'CORTEX_API_KEY' in os.environ:
        del os.environ['CORTEX_API_KEY']

    api = get_cortex_api()
    print("✗ Should have raised ValueError for missing credentials")
except ValueError as e:
    print(f"✓ Correctly raised ValueError: {e}")
    assert "not provided" in str(e)
finally:
    # Restore environment variables
    if original_url:
        os.environ['CORTEX_URL'] = original_url
    if original_key:
        os.environ['CORTEX_API_KEY'] = original_key
```

### Integration Tests

#### Scenario 13: Custom Logger (loguru)

```python
from api_connector import get_thehive_api, get_cortex_api
from loguru import logger

# Configure loguru to log to file
logger.add("api_connector_test.log", rotation="1 MB")

try:
    thehive_api = get_thehive_api(logger=logger)
    print("✓ TheHive connection with custom logger working")

    cortex_api = get_cortex_api(logger=logger)
    print("✓ Cortex connection with custom logger working")

    print("  Check api_connector_test.log for detailed logs")
except Exception as e:
    print(f"✗ Error: {e}")
```

#### Scenario 14: Using Returned API Objects

```python
from api_connector import get_thehive_api, get_cortex_api

# Get health-checked API objects
thehive_api = get_thehive_api()
cortex_api = get_cortex_api()

# Use TheHive API
print("Testing TheHive API operations:")
try:
    # Get current user
    user = thehive_api.get_current_user()
    print(f"  ✓ Current user: {user.json().get('name', 'Unknown')}")

    # Search for cases (limited to 5)
    cases_response = thehive_api.find_cases(query=None, range='0-5', sort='-startDate')
    if cases_response.status_code == 200:
        cases = cases_response.json()
        print(f"  ✓ Found {len(cases)} recent cases")
    else:
        print(f"  ✗ Case search failed: {cases_response.status_code}")
except Exception as e:
    print(f"  ✗ TheHive API error: {e}")

# Use Cortex API
print("\nTesting Cortex API operations:")
try:
    # List analyzers
    analyzers = cortex_api.analyzers.find_all({})
    print(f"  ✓ Found {len(analyzers)} analyzers")

    # Show first few analyzer names
    for analyzer in analyzers[:3]:
        print(f"    - {analyzer.name}")
except Exception as e:
    print(f"  ✗ Cortex API error: {e}")
```

## Expected Results Summary

| Scenario | Expected Exception | Error Message Pattern |
|----------|-------------------|----------------------|
| Valid TheHive (env) | None | "Successfully connected" |
| Valid TheHive (params) | None | "Successfully connected" |
| Invalid TheHive API key | ValueError | "Invalid API key for TheHive" + "THEHIVE_API_KEY" |
| Invalid TheHive host | ConnectionError | "Bad Gateway" or "hostname" |
| Invalid TheHive port | ConnectionError | "port" or "connectivity" |
| Missing TheHive creds | ValueError | "not provided" |
| Valid Cortex (env) | None | "Successfully connected" |
| Valid Cortex (params) | None | "Successfully connected" |
| Invalid Cortex API key | ValueError | "Invalid API key for Cortex" + "CORTEX_API_KEY" |
| Invalid Cortex host | ConnectionError | "hostname" or "network" |
| Invalid Cortex port | ConnectionError | "port" or "service" |
| Missing Cortex creds | ValueError | "not provided" |
| Custom logger | None | Logs written to file |
| Using API objects | None | Successful API operations |

## Common Issues

**Issue: "TheHive URL not provided"**
- **Cause**: THEHIVE_URL env var not set and no explicit URL passed
- **Fix**: `export THEHIVE_URL="https://thehive.example.com:9000"` or pass `thehive_url` parameter

**Issue: "Invalid API key for TheHive"**
- **Cause**: Wrong API key or expired key
- **Fix**: Verify API key in TheHive user settings (Admin > Users > [user] > Create API Key)

**Issue: "Bad Gateway error"**
- **Cause**: Hostname/IP is incorrect or TheHive service is down
- **Fix**: Check hostname, verify TheHive is running: `curl https://thehive.example.com:9000`

**Issue: "Cannot connect to TheHive... Check port number"**
- **Cause**: Wrong port or firewall blocking connection
- **Fix**: Verify port in TheHive config (usually 9000), check firewall rules: `telnet thehive.example.com 9000`

**Issue: "Cortex service unavailable"**
- **Cause**: Wrong port or Cortex service is down
- **Fix**: Verify Cortex is running on expected port (usually 9001): `curl https://cortex.example.com:9001`

**Issue: "Invalid hostname or network error connecting to Cortex"**
- **Cause**: DNS resolution failure or bad hostname
- **Fix**: Check hostname can be resolved: `nslookup cortex.example.com` or `ping cortex.example.com`

## Development Notes

### Health Check Methods

- **TheHive**: Uses `api.get_current_user()` - requires valid authentication, returns user details
- **Cortex**: Uses `api.analyzers.find_all({})` - first authenticated endpoint, returns analyzer list
- Both methods are read-only and non-destructive

### Error Detection Patterns

**TheHive (HTTP status codes)**:
- 200: Success - connection healthy
- 401: Authentication failure - bad API key
- 502: Bad Gateway - typically bad hostname
- TheHiveException (no status): Connection refused - typically bad port

**Cortex (exception types)**:
- AuthenticationError: Bad API key
- InvalidInputError: Bad hostname or DNS failure
- ServiceUnavailableError: Bad port or service down
- CortexException: General connection error

### Environment Variable Priority

1. Explicit parameters (thehive_url, api_key) take precedence
2. Environment variables (THEHIVE_URL, THEHIVE_API_KEY, etc.) as fallback
3. Error raised if neither provided

### Logging Levels

- `logger.info()`: Connection attempts and successes
- `logger.debug()`: API client creation details
- `logger.error()`: All failure conditions

### Type Hints

- All functions use comprehensive type hints
- Return types: `TheHiveApi` or `CortexApi`
- Exception types: `ValueError` or `ConnectionError`
- Logger type: `Optional[Any]` for duck typing flexibility
