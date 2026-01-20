"""
Object-oriented models for TheHive case and observable data with JSON serialization

Provides Python dataclasses for programmatically constructing TheHive cases and
observables, with bidirectional JSON conversion and automatic field normalization.
Useful for building case data structures without API interaction, exchanging data
with external systems, or processing case data in memory.

Key Features:
    - OOP data models with sensible defaults (severity=2, tlp=2, pap=2)
    - Bidirectional conversion between JSON dicts and Python objects
    - TLP/PAP/Severity normalization from int, string, or color names
    - Automatic capture of custom/unknown fields in 'nonstandards' dict
    - Pure Python implementation (no external dependencies)

Basic Usage:
    >>> from thehive_case_models import CaseDatamodel, ObservableDatamodel, dump
    >>> case = CaseDatamodel(title='Phishing', description='Spam campaign', casetype='malspam')
    >>> obs = ObservableDatamodel(type='domain', value='evil.com', ioc=True)
    >>> case.observables = [obs]
    >>> dump(case, 'case.json')

Advanced Usage (JSON → Models):
    >>> from thehive_case_models import Generator
    >>> import json
    >>> with open('case.json') as f:
    ...     data = json.load(f)
    >>> gen = Generator(data)
    >>> case = gen.get_case_datamodel()
    >>> observables = gen.get_observables_datamodels()
    >>> case.observables = observables

Environment Variables:
    None

Functions:
    CaseDatamodel(...) -> CaseDatamodel
        Create case model with defaults
    ObservableDatamodel(...) -> ObservableDatamodel
        Create observable model with defaults
    Generator(dict).get_case_datamodel() -> CaseDatamodel
        Parse JSON dict to case model
    Generator(dict).get_observables_datamodels() -> List[ObservableDatamodel]
        Parse JSON observables list to models
    dictonarize_case(case_model) -> dict
        Convert case model to dict (flattens nonstandards)
    dump(case_model_or_dict, filepath) -> None
        Save case to JSON file

External Dependency:
    - No external dependencies (pure Python stdlib)

Author: Jan
Version: 1.0
"""

import json
from abc import ABC
from typing import Dict, List, Any, Set, Optional, Union

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Reserved Field Constants

# Standard TheHive case fields (from API schema)
_CASE_RESERVED_STD = [
    '_id', '_parent', '_routing', '_type', '_version',
    'caseId', 'createdAt', 'createdBy', 'customFields', 'description',
    'endDate', 'flag', 'id', 'impactStatus', 'metrics', 'observables',
    'owner', 'pap', 'resolutionStatus', 'severity', 'startDate',
    'status', 'summary', 'tags', 'tasks', 'template', 'title',
    'tlp', 'updatedAt', 'updatedBy', 'user'
]

# Extended case fields (custom but commonly used)
_CASE_RESERVED_EXT = ['casetype']

# All reserved case fields
_CASE_RESERVED_ALL = set(_CASE_RESERVED_STD + _CASE_RESERVED_EXT)

# Standard TheHive observable fields (from API schema)
_OBSERVABLE_RESERVED_STD = [
    '_id', '_parent', '_routing', '_type', '_version',
    'createdAt', 'createdBy', 'data', 'dataType', 'id', 'ioc',
    'message', 'reports', 'sighted', 'startDate', 'status',
    'tags', 'tlp', 'updatedAt', 'updatedBy'
]

# Extended observable fields (model convenience names)
_OBSERVABLE_RESERVED_EXT = ['type', 'value', 'description']

# All reserved observable fields
_OBSERVABLE_RESERVED_ALL = set(_OBSERVABLE_RESERVED_STD + _OBSERVABLE_RESERVED_EXT)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Normalization Dictionaries

# TLP normalization: 0=WHITE, 1=GREEN, 2=AMBER, 3=RED
_TLPDICT = {
    # Integer values
    0: 0, 1: 1, 2: 2, 3: 3,
    # String integer values
    '0': 0, '1': 1, '2': 2, '3': 3,
    # Color names (lowercase)
    'white': 0, 'green': 1, 'amber': 2, 'red': 3,
    # Color names (uppercase)
    'WHITE': 0, 'GREEN': 1, 'AMBER': 2, 'RED': 3,
    # Color names (title case)
    'White': 0, 'Green': 1, 'Amber': 2, 'Red': 3
}

# PAP normalization: same as TLP
_PAPDICT = {
    # Integer values
    0: 0, 1: 1, 2: 2, 3: 3,
    # String integer values
    '0': 0, '1': 1, '2': 2, '3': 3,
    # Color names (lowercase)
    'white': 0, 'green': 1, 'amber': 2, 'red': 3,
    # Color names (uppercase)
    'WHITE': 0, 'GREEN': 1, 'AMBER': 2, 'RED': 3,
    # Color names (title case)
    'White': 0, 'Green': 1, 'Amber': 2, 'Red': 3
}

# Severity normalization: 1=LOW, 2=MEDIUM, 3=HIGH
_SEVERITYDICT = {
    # Integer values
    1: 1, 2: 2, 3: 3,
    # String integer values
    '1': 1, '2': 2, '3': 3,
    # Letter codes (lowercase)
    'l': 1, 'm': 2, 'h': 3,
    # Letter codes (uppercase)
    'L': 1, 'M': 2, 'H': 3,
    # Full names (lowercase)
    'low': 1, 'medium': 2, 'high': 3,
    # Full names (uppercase)
    'LOW': 1, 'MEDIUM': 2, 'HIGH': 3,
    # Full names (title case)
    'Low': 1, 'Medium': 2, 'High': 3
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Helper Functions

def _case_get_nonreserved(case_input_dict: dict) -> Set[str]:
    """
    Returns set of non-reserved field names in case dict.

    Args:
        case_input_dict: Case dictionary from JSON

    Returns:
        Set of field names not in reserved lists
    """
    return set(case_input_dict.keys()) - _CASE_RESERVED_ALL


def _observable_get_nonreserved(observable_input_dict: dict) -> Set[str]:
    """
    Returns set of non-reserved field names in observable dict.

    Args:
        observable_input_dict: Observable dictionary from JSON

    Returns:
        Set of field names not in reserved lists
    """
    return set(observable_input_dict.keys()) - _OBSERVABLE_RESERVED_ALL


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Base Classes

class _Jsonizable(ABC):
    """Abstract base class providing JSON serialization."""

    def json(self) -> dict:
        """
        Returns shallow copy of instance __dict__.

        Returns:
            Dictionary representation of object attributes
        """
        return self.__dict__.copy()


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Data Model Classes

class CaseDatamodel(_Jsonizable):
    """
    TheHive case data model with defaults and nonstandards support.

    Args:
        title: Case title (required)
        description: Case description (required)
        casetype: Case type/template name (required)
        severity: Severity level 1-3 (default: 2=MEDIUM)
        pap: PAP level 0-3 (default: 2=AMBER)
        tlp: TLP level 0-3 (default: 2=AMBER)
        tags: List of tags (default: [])
        customFields: TheHive customFields dict (default: {})
        nonstandards: Custom fields not in TheHive schema (default: {})

    Examples:
        >>> case = CaseDatamodel(
        ...     title='Phishing',
        ...     description='Email phishing campaign',
        ...     casetype='malspam',
        ...     severity=3,
        ...     tags=['phishing', 'email']
        ... )
    """

    def __init__(
        self,
        title: str,
        description: str,
        casetype: str,
        severity: int = 2,
        pap: int = 2,
        tlp: int = 2,
        tags: Optional[List[str]] = None,
        customFields: Optional[Dict[str, Any]] = None,
        nonstandards: Optional[Dict[str, Any]] = None
    ):
        self.title = title
        self.description = description
        self.casetype = casetype
        self.severity = severity
        self.pap = pap
        self.tlp = tlp
        self.tags = tags if tags is not None else []
        self.customFields = customFields if customFields is not None else {}
        self.nonstandards = nonstandards if nonstandards is not None else {}


class ObservableDatamodel(_Jsonizable):
    """
    TheHive observable data model with defaults and nonstandards support.

    Note: Uses intuitive field names (type, value, description) instead of
    TheHive API names (dataType, data, message).

    Args:
        type: Observable dataType (e.g., 'ip', 'domain', 'hash', 'file')
        value: Observable data value
        description: Description/message (default: "")
        tlp: TLP level 0-3 (default: 2=AMBER)
        ioc: Mark as indicator of compromise (default: False)
        sighted: Mark as sighted (default: False)
        tags: List of tags (default: [])
        nonstandards: Custom fields not in TheHive schema (default: {})

    Examples:
        >>> obs = ObservableDatamodel(
        ...     type='domain',
        ...     value='evil.com',
        ...     ioc=True,
        ...     tlp=3,
        ...     tags=['malware']
        ... )
    """

    def __init__(
        self,
        type: str,
        value: str,
        description: str = "",
        tlp: int = 2,
        ioc: bool = False,
        sighted: bool = False,
        tags: Optional[List[str]] = None,
        nonstandards: Optional[Dict[str, Any]] = None
    ):
        self.type = type
        self.value = value
        self.description = description
        self.tlp = tlp
        self.ioc = ioc
        self.sighted = sighted
        self.tags = tags if tags is not None else []
        self.nonstandards = nonstandards if nonstandards is not None else {}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# JSON to Models

class Generator:
    """
    Parses JSON dictionaries into CaseDatamodel and ObservableDatamodel objects.

    Handles field normalization (TLP/PAP/severity) and captures non-reserved fields
    in the 'nonstandards' dict.

    Args:
        case_input_: Case dictionary from JSON

    Examples:
        >>> import json
        >>> with open('case.json') as f:
        ...     data = json.load(f)
        >>> gen = Generator(data)
        >>> case = gen.get_case_datamodel()
        >>> observables = gen.get_observables_datamodels()
    """

    def __init__(self, case_input_: dict):
        """Initialize with case JSON dict."""
        self.case_input = case_input_

    def get_case_datamodel(self) -> CaseDatamodel:
        """
        Parse case dict to CaseDatamodel with normalization.

        Extracts standard fields, normalizes TLP/PAP/severity, and captures
        non-reserved fields in 'nonstandards' dict.

        Returns:
            CaseDatamodel instance with normalized values

        Examples:
            >>> gen = Generator({'title': 'Test', 'description': 'Desc',
            ...                  'casetype': 'malware', 'tlp': 'amber'})
            >>> case = gen.get_case_datamodel()
            >>> case.tlp
            2
        """
        # Required fields
        title = self.case_input.get('title', '')
        description = self.case_input.get('description', '')
        casetype = self.case_input.get('casetype', '')

        # Optional fields with defaults and normalization
        severity = self.case_input.get('severity', 2)
        if severity in _SEVERITYDICT:
            severity = _SEVERITYDICT[severity]

        pap = self.case_input.get('pap', 2)
        if pap in _PAPDICT:
            pap = _PAPDICT[pap]

        tlp = self.case_input.get('tlp', 2)
        if tlp in _TLPDICT:
            tlp = _TLPDICT[tlp]

        tags = self.case_input.get('tags', [])
        customFields = self.case_input.get('customFields', {})

        # Capture non-reserved fields
        nonreserved_keys = _case_get_nonreserved(self.case_input)
        nonstandards = {key: self.case_input[key] for key in nonreserved_keys}

        return CaseDatamodel(
            title=title,
            description=description,
            casetype=casetype,
            severity=severity,
            pap=pap,
            tlp=tlp,
            tags=tags,
            customFields=customFields,
            nonstandards=nonstandards
        )

    def get_observables_datamodels(self) -> List[ObservableDatamodel]:
        """
        Parse observables list to ObservableDatamodel list.

        Returns empty list if no observables found. Normalizes TLP and captures
        non-reserved fields in 'nonstandards' dict.

        Returns:
            List of ObservableDatamodel instances

        Examples:
            >>> gen = Generator({'observables': [
            ...     {'dataType': 'ip', 'data': '1.2.3.4', 'tlp': 'red'}
            ... ]})
            >>> obs_list = gen.get_observables_datamodels()
            >>> obs_list[0].tlp
            3
        """
        observables_input = self.case_input.get('observables', [])
        if not observables_input:
            return []

        result = []
        for obs_dict in observables_input:
            # Required fields (with API field name mapping)
            obs_type = obs_dict.get('dataType', obs_dict.get('type', ''))
            obs_value = obs_dict.get('data', obs_dict.get('value', ''))

            # Optional fields with defaults
            obs_description = obs_dict.get('message', obs_dict.get('description', ''))

            tlp = obs_dict.get('tlp', 2)
            if tlp in _TLPDICT:
                tlp = _TLPDICT[tlp]

            ioc = obs_dict.get('ioc', False)
            sighted = obs_dict.get('sighted', False)
            tags = obs_dict.get('tags', [])

            # Capture non-reserved fields
            nonreserved_keys = _observable_get_nonreserved(obs_dict)
            nonstandards = {key: obs_dict[key] for key in nonreserved_keys}

            obs_model = ObservableDatamodel(
                type=obs_type,
                value=obs_value,
                description=obs_description,
                tlp=tlp,
                ioc=ioc,
                sighted=sighted,
                tags=tags,
                nonstandards=nonstandards
            )
            result.append(obs_model)

        return result


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Models to JSON

def dictonarize_case(case: CaseDatamodel) -> dict:
    """
    Convert CaseDatamodel to dict, flattening nonstandards.

    Processes attached observables if present, converting them to dicts
    with TheHive API field names (dataType, data, message).

    Args:
        case: CaseDatamodel instance (may have .observables attribute)

    Returns:
        Dict with nonstandards fields flattened to top level, ready for JSON

    Examples:
        >>> case = CaseDatamodel(
        ...     title='Test', description='Desc', casetype='malware',
        ...     nonstandards={'customField': 'value'}
        ... )
        >>> result = dictonarize_case(case)
        >>> 'customField' in result
        True
        >>> 'nonstandards' in result
        False
    """
    # Get base dict from model
    result = case.json()

    # Flatten nonstandards dict to top level
    if 'nonstandards' in result:
        nonstandards = result.pop('nonstandards')
        result.update(nonstandards)

    # Process observables if present
    if hasattr(case, 'observables') and case.observables:
        obs_list = []
        for obs in case.observables:
            obs_dict = obs.json()

            # Map model field names to TheHive API field names
            if 'type' in obs_dict:
                obs_dict['dataType'] = obs_dict.pop('type')
            if 'value' in obs_dict:
                obs_dict['data'] = obs_dict.pop('value')
            if 'description' in obs_dict:
                obs_dict['message'] = obs_dict.pop('description')

            # Flatten observable nonstandards
            if 'nonstandards' in obs_dict:
                obs_nonstandards = obs_dict.pop('nonstandards')
                obs_dict.update(obs_nonstandards)

            obs_list.append(obs_dict)

        result['observables'] = obs_list

    return result


def dump(caseinput: Union[CaseDatamodel, dict], fileoutput: str) -> None:
    """
    Save case model or dict to JSON file.

    Converts CaseDatamodel to dict if needed, then writes to file with
    pretty-printing (indent=2).

    Args:
        caseinput: CaseDatamodel instance or dict
        fileoutput: Output file path

    Examples:
        >>> case = CaseDatamodel(title='Test', description='Desc', casetype='malware')
        >>> dump(case, 'case.json')
    """
    # Convert model to dict if needed
    if isinstance(caseinput, CaseDatamodel):
        case_dict = dictonarize_case(caseinput)
    else:
        case_dict = caseinput

    # Write to file with pretty-printing
    with open(fileoutput, 'w') as f:
        json.dump(case_dict, f, indent=2)
