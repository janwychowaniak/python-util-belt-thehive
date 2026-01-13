# dev-notes: ioc_parser.py

Manual test scenarios for the ioc_parser module.

## Test Configuration

```python
# No environment variables needed - pure stdlib module

# Test data
SAMPLE_TEXT_BASIC = """
Threat report: Malware contacted 192.168.1.100 and evil.com
Secondary C2: 10.0.0.5
"""

SAMPLE_TEXT_DEFANGED = """
Indicators:
- hxxp://malicious[.]example[.]com/payload
- hxxps://bad[.]actor[.]net
- Contact IP: 203.0.113[.]45
"""

SAMPLE_TEXT_HASHES = """
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""

SAMPLE_TEXT_MIXED = """
Investigation findings:
- Phishing email from suspicious@evil.com
- Payload downloaded from hxxp://malware[.]site/download
- Callback to 198.51.100.42
- File hash: 5d41402abc4b2a76b9719d911017c592
"""
```

## Test Scenarios

### Scenario 1: Basic IOC Extraction

```python
from ioc_parser import extract_iocs

text = "Malware contacted 192.168.1.100 and evil.com"
iocs = extract_iocs(text)

print(f"IPs found: {iocs['ip']}")       # Expected: ['192.168.1.100']
print(f"Domains found: {iocs['domain']}") # Expected: ['evil.com']
print(f"URLs found: {iocs['url']}")      # Expected: []

assert '192.168.1.100' in iocs['ip']
assert 'evil.com' in iocs['domain']
print("✓ Basic extraction working")
```

### Scenario 2: Defanged IOC Refanging

```python
from ioc_parser import extract_iocs

text = "Contacted hxxp://evil[.]com and 192.168[.]1[.]1"
iocs = extract_iocs(text, refang=True)

print(f"URLs found: {iocs['url']}")  # Expected: ['http://evil.com']
print(f"Domains found: {iocs['domain']}")  # Expected: ['evil.com']

assert 'http://evil.com' in iocs['url']
assert 'evil.com' in iocs['domain']
print("✓ Refanging working")
```

### Scenario 3: Hash Extraction

```python
from ioc_parser import extract_iocs

text = """
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""

iocs = extract_iocs(text)

print(f"MD5 hashes: {len(iocs['md5'])}")      # Expected: 1
print(f"SHA1 hashes: {len(iocs['sha1'])}")    # Expected: 1
print(f"SHA256 hashes: {len(iocs['sha256'])}")  # Expected: 1

assert len(iocs['md5']) == 1
assert len(iocs['sha1']) == 1
assert len(iocs['sha256']) == 1
print("✓ Hash extraction working")
```

### Scenario 4: Normalization

```python
from ioc_parser import extract_iocs

text = "Contacted EVIL.COM and Evil.Com"
iocs_normalized = extract_iocs(text, normalize=True, deduplicate=True)
iocs_raw = extract_iocs(text, normalize=False, deduplicate=False)

print(f"Normalized: {iocs_normalized['domain']}")  # Expected: ['evil.com'] (1 entry)
print(f"Raw: {iocs_raw['domain']}")                # Expected: ['EVIL.COM', 'Evil.Com'] (2 entries)

assert len(iocs_normalized['domain']) == 1
assert iocs_normalized['domain'][0] == 'evil.com'
print("✓ Normalization working")
```

### Scenario 5: Deduplication

```python
from ioc_parser import extract_iocs

text = "IP 192.168.1.1 contacted 192.168.1.1 and 192.168.1.1"
iocs_dedup = extract_iocs(text, deduplicate=True)
iocs_no_dedup = extract_iocs(text, deduplicate=False)

print(f"Deduplicated: {len(iocs_dedup['ip'])} IPs")  # Expected: 1
print(f"Not deduplicated: {len(iocs_no_dedup['ip'])} IPs")  # Expected: 3

assert len(iocs_dedup['ip']) == 1
assert len(iocs_no_dedup['ip']) == 3
print("✓ Deduplication working")
```

### Scenario 6: Format for TheHive (Basic)

```python
from ioc_parser import extract_iocs, format_for_thehive

text = "Contacted 8.8.8.8 and malware.com"
iocs = extract_iocs(text)
observables = format_for_thehive(iocs, tlp=2, tags=['malware'])

print(f"Total observables: {len(observables)}")  # Expected: 2

for obs in observables:
    print(f"  {obs['dataType']}: {obs['data']}")
    assert 'dataType' in obs
    assert 'data' in obs
    assert obs['tlp'] == 2
    assert 'malware' in obs['tags']
    assert obs['ioc'] == True
    assert obs['sighted'] == False

print("✓ TheHive format working")
```

### Scenario 7: Format for TheHive (With Message)

```python
from ioc_parser import extract_iocs, format_for_thehive

text = "Found IP 192.168.1.100"
iocs = extract_iocs(text)
observables = format_for_thehive(
    iocs,
    tlp=3,
    tags=['phishing', 'campaign-2024'],
    message='Extracted from phishing email'
)

obs = observables[0]
print(f"Observable: {obs}")

assert obs['tlp'] == 3
assert 'phishing' in obs['tags']
assert 'campaign-2024' in obs['tags']
assert obs['message'] == 'Extracted from phishing email'
print("✓ TheHive format with message working")
```

### Scenario 8: Empty Input

```python
from ioc_parser import extract_iocs

text = "No indicators in this text"
iocs = extract_iocs(text)

for ioc_type, values in iocs.items():
    assert len(values) == 0, f"Expected empty list for {ioc_type}"

print("✓ Empty input handling working")
```

### Scenario 9: Mixed IOC Types

```python
from ioc_parser import extract_iocs, format_for_thehive

text = """
Investigation findings:
- Email: suspicious@evil.com
- URL: http://malware.site/download
- IP: 198.51.100.42
- Hash: 5d41402abc4b2a76b9719d911017c592
"""

iocs = extract_iocs(text)

print(f"IPs: {iocs['ip']}")
print(f"Domains: {iocs['domain']}")
print(f"URLs: {iocs['url']}")
print(f"MD5 hashes: {iocs['md5']}")

total_iocs = sum(len(v) for v in iocs.values())
print(f"Total IOCs found: {total_iocs}")

observables = format_for_thehive(iocs, tlp=2)
print(f"Total observables: {len(observables)}")

assert len(observables) == total_iocs
print("✓ Mixed IOC types working")
```

### Scenario 10: Real-World Threat Report

```python
from ioc_parser import extract_iocs, format_for_thehive

report = """
THREAT INTELLIGENCE REPORT - APT Campaign

The malicious actor used the following infrastructure:
- C2 servers: hxxp://c2-server[.]malicious[.]net and 203.0.113.50
- Phishing domains: fake-login[.]phishing[.]site
- Payload hash (SHA256): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- Secondary IP: 198.51.100.100

All indicators should be considered high confidence.
"""

iocs = extract_iocs(report, refang=True, deduplicate=True, normalize=True)

print("Extracted IOCs:")
for ioc_type, values in iocs.items():
    if values:
        print(f"  {ioc_type}: {values}")

observables = format_for_thehive(
    iocs,
    tlp=2,
    tags=['apt', 'high-confidence'],
    message='Extracted from threat intelligence report'
)

print(f"\nGenerated {len(observables)} TheHive observables")
print("✓ Real-world scenario working")
```

## Expected Results Summary

| Scenario | Expected Output | Notes |
|----------|----------------|-------|
| Basic extraction | IPs and domains found | Clean extraction |
| Defanged refanging | hxxp→http, [.]→. | Automatic conversion |
| Hash extraction | MD5, SHA1, SHA256 detected | All hash types |
| Normalization | Lowercase, deduplicated | evil.com from EVIL.COM |
| Deduplication | Single entry per unique IOC | Removes duplicates |
| TheHive format (basic) | Valid observable dicts | Has all required fields |
| TheHive format (message) | Observable with custom fields | TLP, tags, message set |
| Empty input | All empty lists | Graceful handling |
| Mixed IOC types | All types extracted | Multiple IOC types |
| Real-world report | Complete IOC extraction | Defanged + mixed types |

## Common Issues

**Issue: Domain extraction picks up file extensions**
- **Cause**: Regex may match `.txt`, `.log` as domains
- **Workaround**: Filter results or adjust regex for your use case

**Issue: Hash detection conflicts (MD5 vs SHA1)**
- **Cause**: All are hex strings; longer hashes include shorter patterns
- **Note**: This is expected; SHA256 won't match MD5 pattern due to length check

**Issue: Refanging doesn't work**
- **Cause**: `refang=False` parameter set
- **Fix**: Ensure `refang=True` (default)

**Issue: Too many false positives for domains**
- **Cause**: Domain regex is broad to catch variants
- **Workaround**: Post-process results, filter known false positives (e.g., 'example.com')

## Development Notes

- IPv4 only currently supported (no IPv6 in base implementation)
- Domain regex requires at least 2-character TLD (.co, .io, etc.)
- URLs must have protocol (http, https, ftp, or defanged variants)
- Hash detection is length-based (32=MD5, 40=SHA1, 64=SHA256)
- Regex patterns are compiled at module load for performance
- No network calls - pure text processing
- TheHive observable format follows TheHive4 schema
