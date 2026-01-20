# Dev Notes: thehive_case_models.py

Manual testing reference for the thehive_case_models module.

## Test Configuration

```python
# No environment variables required (pure stdlib module)
import json
import os
from thehive_case_models import (
    CaseDatamodel,
    ObservableDatamodel,
    Generator,
    dictonarize_case,
    dump
)

# Test output directory
TEST_DIR = '/tmp/thehive_case_models_test'
os.makedirs(TEST_DIR, exist_ok=True)
```

## Test Scenarios

### 1. Model Creation - Minimal (Required Fields Only)

```python
# Create case with only required fields
case_minimal = CaseDatamodel(
    title='Minimal Test Case',
    description='Testing minimal case creation',
    casetype='incident'
)

# Verify defaults applied
assert case_minimal.severity == 2  # MEDIUM
assert case_minimal.tlp == 2       # AMBER
assert case_minimal.pap == 2       # AMBER
assert case_minimal.tags == []
assert case_minimal.customFields == {}
assert case_minimal.nonstandards == {}

print("✓ Minimal case creation works with defaults")
```

### 2. Model Creation - Full (All Fields Populated)

```python
# Create case with all fields
case_full = CaseDatamodel(
    title='Full Test Case',
    description='Testing full case creation with all fields',
    casetype='phishing',
    severity=3,
    pap=2,
    tlp=3,
    tags=['phishing', 'email', 'finance'],
    customFields={'caseOwner': 'soc@example.com'},
    nonstandards={'caseReporter': 'SIEM', 'otrsTicket': '12345'}
)

assert case_full.severity == 3
assert case_full.tlp == 3
assert len(case_full.tags) == 3
assert case_full.nonstandards['caseReporter'] == 'SIEM'

print("✓ Full case creation works with all fields")
```

### 3. Observable Creation - Basic

```python
# Create basic observable
obs1 = ObservableDatamodel(
    type='ip',
    value='192.168.1.100'
)

# Verify defaults
assert obs1.description == ""
assert obs1.tlp == 2  # AMBER
assert obs1.ioc == False
assert obs1.sighted == False
assert obs1.tags == []

print("✓ Basic observable creation works with defaults")
```

### 4. Observable Creation - Advanced

```python
# Create observable with all fields
obs2 = ObservableDatamodel(
    type='domain',
    value='evil.com',
    description='C2 domain from malware analysis',
    tlp=3,
    ioc=True,
    sighted=True,
    tags=['c2', 'malware'],
    nonstandards={'firstSeen': '2024-01-15', 'source': 'VirusTotal'}
)

assert obs2.ioc == True
assert obs2.sighted == True
assert obs2.tlp == 3
assert obs2.nonstandards['source'] == 'VirusTotal'

print("✓ Advanced observable creation works")
```

### 5. Normalization - TLP (All Formats)

```python
# Test TLP normalization from different input formats
test_cases_tlp = [
    (0, 0),           # int
    (2, 2),           # int
    ('1', 1),         # string int
    ('3', 3),         # string int
    ('white', 0),     # lowercase color
    ('green', 1),     # lowercase color
    ('amber', 2),     # lowercase color
    ('red', 3),       # lowercase color
    ('WHITE', 0),     # uppercase color
    ('GREEN', 1),     # uppercase color
    ('AMBER', 2),     # uppercase color
    ('RED', 3),       # uppercase color
    ('White', 0),     # title case color
    ('Amber', 2),     # title case color
]

for input_val, expected in test_cases_tlp:
    gen = Generator({'title': 'Test', 'description': 'Test', 'casetype': 'test', 'tlp': input_val})
    case = gen.get_case_datamodel()
    assert case.tlp == expected, f"Failed for input {input_val}: got {case.tlp}, expected {expected}"

print("✓ TLP normalization works for all formats")
```

### 6. Normalization - PAP (Same as TLP)

```python
# Test PAP normalization
test_cases_pap = [
    (0, 0), (2, 2), ('1', 1), ('3', 3),
    ('white', 0), ('amber', 2), ('WHITE', 0), ('Red', 3)
]

for input_val, expected in test_cases_pap:
    gen = Generator({'title': 'Test', 'description': 'Test', 'casetype': 'test', 'pap': input_val})
    case = gen.get_case_datamodel()
    assert case.pap == expected, f"Failed for input {input_val}"

print("✓ PAP normalization works for all formats")
```

### 7. Normalization - Severity (Numbers and Letters)

```python
# Test severity normalization
test_cases_severity = [
    (1, 1), (2, 2), (3, 3),           # int
    ('1', 1), ('2', 2), ('3', 3),     # string int
    ('l', 1), ('m', 2), ('h', 3),     # lowercase letters
    ('L', 1), ('M', 2), ('H', 3),     # uppercase letters
    ('low', 1), ('medium', 2), ('high', 3),      # lowercase names
    ('LOW', 1), ('MEDIUM', 2), ('HIGH', 3),      # uppercase names
    ('Low', 1), ('Medium', 2), ('High', 3),      # title case names
]

for input_val, expected in test_cases_severity:
    gen = Generator({'title': 'Test', 'description': 'Test', 'casetype': 'test', 'severity': input_val})
    case = gen.get_case_datamodel()
    assert case.severity == expected, f"Failed for input {input_val}: got {case.severity}"

print("✓ Severity normalization works for all formats")
```

### 8. Nonstandards Capture - Case Level

```python
# Create case with custom fields not in TheHive schema
case_dict = {
    'title': 'Test Case',
    'description': 'Testing nonstandards capture',
    'casetype': 'incident',
    'caseReporter': 'John Doe',            # Custom field
    'otrsTicket': 'OTRS-2024-001',         # Custom field
    'sourceSystem': 'SIEM',                # Custom field
    'severity': 2,
    'tlp': 2
}

gen = Generator(case_dict)
case = gen.get_case_datamodel()

# Verify standard fields parsed correctly
assert case.title == 'Test Case'
assert case.severity == 2

# Verify custom fields captured in nonstandards
assert 'caseReporter' in case.nonstandards
assert 'otrsTicket' in case.nonstandards
assert 'sourceSystem' in case.nonstandards
assert case.nonstandards['caseReporter'] == 'John Doe'
assert case.nonstandards['otrsTicket'] == 'OTRS-2024-001'

print("✓ Case-level nonstandards capture works")
```

### 9. Nonstandards Capture - Observable Level

```python
# Create observable with custom fields
obs_dict = {
    'dataType': 'ip',
    'data': '10.0.0.1',
    'tlp': 3,
    'firstSeenDate': '2024-01-15T10:00:00Z',   # Custom field
    'threatScore': 85,                         # Custom field
    'geoLocation': 'US'                        # Custom field
}

gen = Generator({'title': 'Test', 'description': 'Test', 'casetype': 'test', 'observables': [obs_dict]})
obs_list = gen.get_observables_datamodels()

# Verify standard fields
assert obs_list[0].type == 'ip'
assert obs_list[0].value == '10.0.0.1'
assert obs_list[0].tlp == 3

# Verify custom fields in nonstandards
assert 'firstSeenDate' in obs_list[0].nonstandards
assert 'threatScore' in obs_list[0].nonstandards
assert obs_list[0].nonstandards['threatScore'] == 85

print("✓ Observable-level nonstandards capture works")
```

### 10. JSON Export - dictonarize_case

```python
# Create case with nonstandards
case = CaseDatamodel(
    title='Export Test',
    description='Testing JSON export',
    casetype='malware',
    severity=3,
    nonstandards={'caseReporter': 'SIEM', 'priority': 'high'}
)

# Convert to dict
case_dict = dictonarize_case(case)

# Verify nonstandards flattened to top level
assert 'caseReporter' in case_dict
assert 'priority' in case_dict
assert 'nonstandards' not in case_dict  # Should be removed

# Verify standard fields present
assert case_dict['title'] == 'Export Test'
assert case_dict['severity'] == 3

print("✓ dictonarize_case flattens nonstandards correctly")
```

### 11. JSON Export - With Observables

```python
# Create case with observables
case = CaseDatamodel(
    title='Case with Observables',
    description='Testing observable export',
    casetype='phishing'
)

obs1 = ObservableDatamodel(type='domain', value='phish.com', ioc=True)
obs2 = ObservableDatamodel(type='ip', value='1.2.3.4', tlp=3)

case.observables = [obs1, obs2]

# Convert to dict
case_dict = dictonarize_case(case)

# Verify observables present with correct field names
assert 'observables' in case_dict
assert len(case_dict['observables']) == 2

# Verify field name mapping (type → dataType, value → data)
assert case_dict['observables'][0]['dataType'] == 'domain'
assert case_dict['observables'][0]['data'] == 'phish.com'
assert case_dict['observables'][1]['dataType'] == 'ip'
assert case_dict['observables'][1]['data'] == '1.2.3.4'

print("✓ Observable export with field name mapping works")
```

### 12. JSON Dump - File Output

```python
# Create case
case = CaseDatamodel(
    title='File Dump Test',
    description='Testing file output',
    casetype='incident',
    tags=['test']
)

# Save to file
output_file = os.path.join(TEST_DIR, 'test_case.json')
dump(case, output_file)

# Verify file exists and is valid JSON
assert os.path.exists(output_file)

with open(output_file) as f:
    loaded = json.load(f)

assert loaded['title'] == 'File Dump Test'
assert loaded['casetype'] == 'incident'

print(f"✓ JSON dump to file works: {output_file}")
```

### 13. JSON Import - Generator (Basic)

```python
# Create JSON dict
json_dict = {
    'title': 'Import Test',
    'description': 'Testing JSON import',
    'casetype': 'malware',
    'severity': 'high',  # Will be normalized to 3
    'tlp': 'red',        # Will be normalized to 3
    'tags': ['malware', 'ransomware']
}

# Import via Generator
gen = Generator(json_dict)
case = gen.get_case_datamodel()

# Verify normalization applied
assert case.severity == 3
assert case.tlp == 3
assert len(case.tags) == 2

print("✓ JSON import with normalization works")
```

### 14. JSON Import - With Observables

```python
# Create JSON dict with observables
json_dict = {
    'title': 'Import with Observables',
    'description': 'Testing observable import',
    'casetype': 'phishing',
    'observables': [
        {
            'dataType': 'domain',
            'data': 'evil.com',
            'message': 'Phishing domain',
            'tlp': 'amber',
            'ioc': True,
            'tags': ['phishing']
        },
        {
            'dataType': 'hash',
            'data': 'abc123def456',
            'tlp': 3,
            'ioc': True
        }
    ]
}

# Import via Generator
gen = Generator(json_dict)
case = gen.get_case_datamodel()
observables = gen.get_observables_datamodels()

# Attach observables to case
case.observables = observables

# Verify observable count
assert len(case.observables) == 2

# Verify field name mapping (dataType → type, data → value, message → description)
assert case.observables[0].type == 'domain'
assert case.observables[0].value == 'evil.com'
assert case.observables[0].description == 'Phishing domain'
assert case.observables[0].tlp == 2  # 'amber' normalized to 2

# Verify second observable
assert case.observables[1].type == 'hash'
assert case.observables[1].value == 'abc123def456'

print("✓ JSON import with observables works")
```

### 15. Round-Trip Test - JSON → Model → JSON

```python
# Original JSON
original = {
    'title': 'Round-trip Test',
    'description': 'Testing bidirectional conversion',
    'casetype': 'incident',
    'severity': 'medium',
    'tlp': 'green',
    'pap': 'amber',
    'tags': ['test', 'roundtrip'],
    'customFields': {'analyst': 'jane@example.com'},
    'caseReporter': 'SIEM',  # Custom field
    'observables': [
        {
            'dataType': 'ip',
            'data': '10.20.30.40',
            'message': 'Suspicious IP',
            'tlp': 'red',
            'ioc': True,
            'customObsField': 'custom_value'  # Custom observable field
        }
    ]
}

# JSON → Model
gen = Generator(original)
case = gen.get_case_datamodel()
observables = gen.get_observables_datamodels()
case.observables = observables

# Model → JSON
exported = dictonarize_case(case)

# Verify round-trip preservation
assert exported['title'] == original['title']
assert exported['severity'] == 2  # 'medium' normalized to 2
assert exported['tlp'] == 1  # 'green' normalized to 1
assert exported['pap'] == 2  # 'amber' normalized to 2
assert exported['caseReporter'] == original['caseReporter']  # Custom field preserved
assert exported['observables'][0]['dataType'] == 'ip'
assert exported['observables'][0]['data'] == '10.20.30.40'
assert exported['observables'][0]['message'] == 'Suspicious IP'
assert exported['observables'][0]['tlp'] == 3  # 'red' normalized to 3
assert exported['observables'][0]['customObsField'] == 'custom_value'  # Custom field preserved

print("✓ Round-trip conversion preserves all data")
```

### 16. Real-World Example - Building Case from Scratch

```python
# Simulate building a case for a phishing incident
case = CaseDatamodel(
    title='Phishing Campaign - Finance Department',
    description='''
Multiple employees in finance department received phishing emails
claiming to be from IT support. Emails contained malicious links
attempting to harvest credentials.
    '''.strip(),
    casetype='phishing',
    severity=3,  # HIGH
    tlp=2,       # AMBER
    pap=2,       # AMBER
    tags=['phishing', 'email', 'finance', 'credential-harvesting'],
    customFields={
        'analyst': 'soc-analyst@example.com',
        'ticketNumber': 'INC-2024-0152'
    }
)

# Add observables
observables = [
    ObservableDatamodel(
        type='domain',
        value='secure-it-portal.tk',
        description='Phishing domain in email link',
        tlp=3,  # RED - share with extreme caution
        ioc=True,
        tags=['phishing', 'domain']
    ),
    ObservableDatamodel(
        type='ip',
        value='45.67.89.123',
        description='IP address hosting phishing site',
        tlp=3,
        ioc=True,
        sighted=True,
        tags=['phishing', 'c2']
    ),
    ObservableDatamodel(
        type='mail',
        value='it-support@company-portal.tk',
        description='Sender address used in phishing emails',
        tlp=2,
        ioc=True,
        tags=['phishing', 'sender']
    ),
    ObservableDatamodel(
        type='url',
        value='http://secure-it-portal.tk/login.php',
        description='Full phishing URL from email',
        tlp=3,
        ioc=True,
        tags=['phishing', 'url']
    )
]

case.observables = observables

# Save to file
output_file = os.path.join(TEST_DIR, 'phishing_case.json')
dump(case, output_file)

print(f"✓ Real-world phishing case created: {output_file}")

# Verify by loading back
with open(output_file) as f:
    loaded = json.load(f)
    print(f"  - Case: {loaded['title']}")
    print(f"  - Severity: {loaded['severity']}")
    print(f"  - Observables: {len(loaded['observables'])}")
    for obs in loaded['observables']:
        print(f"    - {obs['dataType']}: {obs['data']}")
```

## Common Issues and Troubleshooting

### Issue 1: Mutable Default Arguments

**Problem**: Tags list is shared between instances
```python
# This should NOT happen with our implementation
case1 = CaseDatamodel(title='A', description='B', casetype='C')
case2 = CaseDatamodel(title='D', description='E', casetype='F')
case1.tags.append('test')
# case2.tags should still be [] (not ['test'])
```

**Solution**: Our implementation uses `None` pattern to avoid this issue.

### Issue 2: Field Name Confusion (Observable)

**Problem**: Mixing model field names with API field names

**Remember**:
- Model uses: `type`, `value`, `description` (intuitive)
- API uses: `dataType`, `data`, `message` (TheHive convention)
- Generator handles mapping on import (dataType → type)
- dictonarize_case handles mapping on export (type → dataType)

### Issue 3: Normalization Not Applied

**Problem**: TLP/PAP/Severity values not normalized

**Solution**: Always use Generator for JSON imports to ensure normalization:
```python
# Good
gen = Generator(json_dict)
case = gen.get_case_datamodel()

# Bad - bypasses normalization
case = CaseDatamodel(**json_dict)  # May fail if json_dict has 'tlp': 'amber'
```

## Development Observations

1. **Pure Python**: No external dependencies makes this module extremely portable
2. **Normalization**: Handles various input formats gracefully (case-insensitive, numbers/strings/names)
3. **Nonstandards**: Automatic capture ensures no data loss during round-trips
4. **Field Mapping**: Observable field name translation (dataType ↔ type) happens transparently
5. **Defaults**: Sensible defaults (severity=2, tlp=2, pap=2) match TheHive conventions
6. **Type Safety**: Type hints throughout improve IDE support and code clarity
