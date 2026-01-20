"""
Extended TheHive API Operations - Access endpoints not covered by thehive4py

This module extends thehive4py functionality by providing direct access to TheHive API
endpoints that aren't exposed in the library's public interface. Designed for TheHive v3.4.0
environments where thehive4py==1.6.0 doesn't cover all available endpoints.

The module provides three categories of operations: server metadata queries (status, custom
fields, connectors), case manipulation (tag appending, TLP updates, description updates),
and observable operations (CRUD, tag management, search by type/data).

Key Features:
    - Server metadata access (status, connectors, custom fields, data types)
    - Case manipulation (append tags without replace, append descriptions, update TLP/fields)
    - Observable operations (get by ID, update with field filtering, tag management)
    - Observable search (find by dataType + data pair for deduplication)
    - Hybrid API pattern (accept API object OR url/key params for maximum flexibility)
    - Environment variable support with explicit parameter override
    - Intelligent error handling (ValueError for config, ConnectionError for infrastructure)

Basic Usage:
    >>> from thehive_extended_api import case_append_tags, get_observable, obsfind_dupes_by_id
    >>>
    >>> # Using environment variables (THEHIVE_URL, THEHIVE_API_KEY)
    >>> case_append_tags('12345', ['malware', 'phishing'])
    >>> obs = get_observable('abc123def456')
    >>> print(obs['dataType'], obs['data'])
    >>>
    >>> # Find duplicates
    >>> dupes = obsfind_dupes_by_id('abc123def456')
    >>> print(f"Found {len(dupes)} duplicates")

Advanced Usage:
    >>> from thehive4py.api import TheHiveApi
    >>> from thehive_extended_api import (
    ...     case_append_tags, case_append_description,
    ...     obs_append_tags, obsfind_any_by_type_data,
    ...     obsfind_dupes_by_id, get_custom_fields
    ... )
    >>>
    >>> # Option 1: Pass existing API object
    >>> api = TheHiveApi('https://thehive.local:9000', 'your-api-key')
    >>> case_append_tags('12345', ['incident'], api=api)
    >>>
    >>> # Option 2: Explicit credentials
    >>> case_append_description(
    ...     '12345',
    ...     'Investigation notes here',
    ...     title='SIEM Analysis',
    ...     thehive_url='https://thehive.local:9000',
    ...     api_key='your-api-key'
    ... )
    >>>
    >>> # Observable operations
    >>> obs_append_tags('abc123', ['suspicious', 'external'])
    >>>
    >>> # Search by type + data (name-based for files)
    >>> duplicates = obsfind_any_by_type_data('ip', '192.168.1.100')
    >>> print(f"Found {len(duplicates)} IPs with same value")
    >>>
    >>> # Find true duplicates by content (hash-based for files)
    >>> obs_id = 'abc123def456'  # A file observable
    >>> similars = obsfind_dupes_by_id(obs_id)
    >>> print(f"Found {len(similars)} files with same hash")
    >>>
    >>> # Server metadata
    >>> custom_fields = get_custom_fields()
    >>> for field in custom_fields:
    ...     print(f"{field['name']}: {field['type']}")

Environment Variables:
    THEHIVE_URL - TheHive instance URL (e.g., https://thehive.example.com:9000)
    THEHIVE_API_KEY - API key for authentication

Functions:
    Server Operations:
        get_status(api, thehive_url, api_key, logger) -> Dict[str, Any]
            Get TheHive server status and version information

        get_connectors(api, thehive_url, api_key, logger) -> Dict[str, List[Dict]]
            Get connector availability info parsed from status endpoint

        get_custom_fields(api, thehive_url, api_key, logger) -> List[Dict[str, Any]]
            Get custom field definitions for the instance

        get_list_artifactDataType(api, thehive_url, api_key, logger) -> List[str]
            Get list of available observable data types

        get_describe_model(model, api, thehive_url, api_key, logger) -> Dict[str, Any]
            Get model schema description (e.g., 'case', 'case_artifact')

    Case Operations:
        case_append_tags(case_id, tags, api, thehive_url, api_key, logger) -> Dict[str, Any]
            Append tags to case (merges with existing, deduplicates automatically)

        case_update_tlp(case_id, tlp, api, thehive_url, api_key, logger) -> Dict[str, Any]
            Update case TLP level (0=WHITE, 1=GREEN, 2=AMBER, 3=RED)

        case_append_description(case_id, content, title, api, thehive_url, api_key, logger) -> Dict[str, Any]
            Append content to case description with optional titled separator

        case_update_anyfield(case_id, field_dict, api, thehive_url, api_key, logger) -> Dict[str, Any]
            Update arbitrary case field (e.g., {'status': 'Resolved', 'severity': 3})

        get_linked_cases(case_id, api, thehive_url, api_key, logger) -> List[Dict[str, Any]]
            Get list of cases linked to specified case

    Observable Operations:
        get_observable(obs_id, api, thehive_url, api_key, logger) -> Optional[Dict[str, Any]]
            Get observable by ID (returns None if not found)

        update_observable(obs_json, fields, api, thehive_url, api_key, logger) -> Dict[str, Any]
            Update observable with optional field filtering

        obs_append_tags(obs_id, tags, api, thehive_url, api_key, logger) -> Dict[str, Any]
            Append tags to observable (merges with existing)

        obs_update_tlp(obs_id, tlp, api, thehive_url, api_key, logger) -> Dict[str, Any]
            Update observable TLP level (0=WHITE, 1=GREEN, 2=AMBER, 3=RED)

        obsfind_any_by_type_data(dataType, data, api, thehive_url, api_key, logger) -> List[Dict[str, Any]]
            Search for observables by dataType + data pair (files by name, non-files by value)

        obsfind_dupes_by_id(obs_id, api, thehive_url, api_key, logger) -> List[Dict[str, Any]]
            Find observables similar to given ID (files by hash, non-files by value, excludes original)

External Dependency:
    - Requires 'thehive4py' library: pip install thehive4py
    - Requires 'requests' library: pip install requests (usually bundled with thehive4py)
    - Install both: pip install thehive4py requests
    - Docs: https://github.com/TheHive-Project/TheHive4py

Author: Jan
Version: 1.0
"""

try:
    from thehive4py.api import TheHiveApi
    from thehive4py.query import String, And, Eq
    from thehive4py.exceptions import TheHiveException, CaseException, CaseObservableException
except ImportError:
    raise ImportError(
        "thehive_extended_api.py requires 'thehive4py' library\n"
        "Install: pip install thehive4py\n"
        "Docs: https://github.com/TheHive-Project/TheHive4py"
    )

try:
    import requests
except ImportError:
    raise ImportError(
        "thehive_extended_api.py requires 'requests' library\n"
        "Install: pip install requests\n"
        "Usually installed automatically with thehive4py"
    )

import os
import logging
from typing import Optional, Dict, List, Any, Union

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Private helper functions

def _get_api(
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> TheHiveApi:
    """
    Establish TheHive API connection with env var fallback.

    Args:
        thehive_url: TheHive instance URL
        api_key: API key for authentication
        logger: Optional logger instance

    Returns:
        TheHiveApi instance

    Raises:
        ValueError: If credentials are missing
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    thehive_url = thehive_url or os.getenv('THEHIVE_URL')
    api_key = api_key or os.getenv('THEHIVE_API_KEY')

    if not thehive_url:
        raise ValueError(
            "TheHive URL not provided. Set THEHIVE_URL env var or pass thehive_url parameter"
        )
    if not api_key:
        raise ValueError(
            "API key not provided. Set THEHIVE_API_KEY env var or pass api_key parameter"
        )

    logger.debug(f"Creating TheHive API connection to {thehive_url}")
    return TheHiveApi(thehive_url, api_key, cert=True)


def _make_request(
    api: TheHiveApi,
    method: str,
    endpoint: str,
    logger: Any,
    **kwargs
) -> requests.Response:
    """
    Make HTTP request using API object's connection details.

    Extracts url, auth, proxies, and cert settings from the API object
    and uses requests library directly for endpoints not exposed by thehive4py.

    Args:
        api: TheHiveApi instance (used as connection detail donor)
        method: HTTP method (GET, POST, PATCH, etc.)
        endpoint: API endpoint path (e.g., '/api/case/12345/links')
        logger: Logger instance
        **kwargs: Additional arguments passed to requests.request()

    Returns:
        requests.Response object

    Raises:
        ConnectionError: If request fails
    """
    url = api.url + endpoint
    logger.debug(f"{method} {url}")

    try:
        return requests.request(
            method=method,
            url=url,
            auth=api.auth,
            proxies=api.proxies,
            verify=api.cert,
            **kwargs
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        raise ConnectionError(f"Failed to {method} {endpoint}: {e}") from e


def _format_description_append(content: str, title: Optional[str] = None) -> str:
    """
    Format description appendage with separator bar and optional title.

    Args:
        content: Content to append
        title: Optional title for the separator bar

    Returns:
        Formatted string with separator and content

    Examples:
        >>> _format_description_append("New info", "Update")
        '\\n\\n--- [Update] ------------...\\n\\nNew info'

        >>> _format_description_append("No title")
        '\\n\\n-----------------------...\\n\\nNo title'
    """
    bar_prefix = '-' * 3
    bar_suffix = '-' * 120

    if title:
        bar = f'{bar_prefix} [{title}] {bar_suffix}'
    else:
        bar = f'{bar_prefix}{bar_suffix}'

    return f'\n\n{bar}\n\n{content}'


def _findrows_observables(api: TheHiveApi, logger: Any, **attributes) -> List[Dict[str, Any]]:
    """
    Low-level observable searcher using thehive4py's internal search method.

    Args:
        api: TheHiveApi instance
        logger: Logger instance
        **attributes: Search parameters (query, range, sort, etc.)

    Returns:
        List of matching observable dicts

    Raises:
        ConnectionError: If search fails
    """
    try:
        results = api._TheHiveApi__find_rows('/api/case/artifact/_search', **attributes)
        if results.status_code == 200:
            return results.json()
        else:
            raise ConnectionError(f"Observable search failed ({results.status_code}): {results.text}")
    except Exception as e:
        logger.error(f"Observable search failed: {e}")
        raise ConnectionError(f"Failed to search observables: {e}") from e


def _searchfor_similar_files__hash(api: TheHiveApi, file_hash: str, logger: Any) -> List[Dict[str, Any]]:
    """
    Search for file observables by hash (true content-based duplicates).

    Uses String query (fuzzy) then filters to exact hash matches.

    Args:
        api: TheHiveApi instance
        file_hash: File hash to search for
        logger: Logger instance

    Returns:
        List of file observables with matching hash
    """
    logger.debug(f"Searching for files with hash: {file_hash}")
    query = And(Eq('dataType', 'file'), String(file_hash))
    suspected = _findrows_observables(api, logger, query=query, range='all', sort='-createdAt')

    # Filter to exact hash matches
    files = []
    for suspect in suspected:
        if 'attachment' in suspect and file_hash in suspect['attachment'].get('hashes', []):
            files.append(suspect)

    logger.debug(f"Found {len(files)} files with matching hash")
    return files


def _searchfor_similar_files__name(api: TheHiveApi, filename: str, logger: Any) -> List[Dict[str, Any]]:
    """
    Search for file observables by filename.

    Uses String query (fuzzy) then filters to exact name matches.

    Args:
        api: TheHiveApi instance
        filename: Filename to search for
        logger: Logger instance

    Returns:
        List of file observables with matching filename
    """
    logger.debug(f"Searching for files named: {filename}")
    query = And(Eq('dataType', 'file'), String(filename))
    suspected = _findrows_observables(api, logger, query=query, range='all', sort='-createdAt')

    # Filter to exact name matches
    files = []
    for suspect in suspected:
        if 'attachment' in suspect and suspect['attachment'].get('name') == filename:
            files.append(suspect)

    logger.debug(f"Found {len(files)} files with matching name")
    return files


def _searchfor_similar_nonfiles(api: TheHiveApi, dataType: str, data: str, logger: Any) -> List[Dict[str, Any]]:
    """
    Search for non-file observables by dataType + data.

    Args:
        api: TheHiveApi instance
        dataType: Observable data type (ip, domain, hash, etc.)
        data: Observable data value
        logger: Logger instance

    Returns:
        List of matching non-file observables
    """
    logger.debug(f"Searching for non-files: {dataType}={data}")
    query = And(Eq('dataType', dataType), Eq('data', data))
    results = _findrows_observables(api, logger, query=query, range='all', sort='-createdAt')
    logger.debug(f"Found {len(results)} matching non-file observables")
    return results


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Server Operations

def get_status(
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Get TheHive server status and version information.

    Args:
        api: Optional TheHiveApi instance (if not provided, will create from url/key)
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Dict containing server status with keys like 'versions', 'connectors'

    Raises:
        ValueError: If credentials invalid
        ConnectionError: If server unreachable

    Examples:
        >>> status = get_status()
        >>> print(status['versions']['TheHive'])
        '3.4.0-1'
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info("Fetching TheHive server status")
    response = _make_request(api, 'GET', '/api/status', logger)

    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectionError(f"Status fetch failed ({response.status_code}): {response.text}")


def get_connectors(
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, List[Dict[str, str]]]:
    """
    Get connector availability information.

    Fetches server status and parses connector information by type.

    Args:
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Dict mapping connector types to lists of connector info dicts
        Example: {'cortex': [{'name': 'Cortex1', 'status': 'OK'}]}

    Raises:
        ValueError: If credentials invalid
        ConnectionError: If server unreachable

    Examples:
        >>> connectors = get_connectors()
        >>> for ctype, servers in connectors.items():
        ...     print(f"{ctype}: {len(servers)} servers")
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    logger.info("Fetching connector information")
    status = get_status(api, thehive_url, api_key, logger)

    connectors_raw = status.get('connectors', {})
    connectors = {}

    for conn_kind in connectors_raw:
        connectors[conn_kind] = []
        servers = connectors_raw[conn_kind].get('servers', [])
        for srv in servers:
            srv_info = {
                'name': srv.get('name', 'unknown'),
                'status': srv.get('status', 'unknown')
            }
            connectors[conn_kind].append(srv_info)

    logger.debug(f"Found {len(connectors)} connector types")
    return connectors


def get_custom_fields(
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """
    Get custom field definitions for the TheHive instance.

    Args:
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        List of custom field definition dicts

    Raises:
        ValueError: If credentials invalid
        ConnectionError: If server unreachable

    Examples:
        >>> fields = get_custom_fields()
        >>> for field in fields:
        ...     print(f"{field['name']}: {field['type']}")
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info("Fetching custom field definitions")
    response = _make_request(api, 'GET', '/api/list/custom_fields', logger)

    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectionError(f"Custom fields fetch failed ({response.status_code}): {response.text}")


def get_list_artifactDataType(
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> List[str]:
    """
    Get list of available observable data types.

    Args:
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        List of data type strings (e.g., ['ip', 'domain', 'hash', 'file', ...])

    Raises:
        ValueError: If credentials invalid
        ConnectionError: If server unreachable

    Examples:
        >>> data_types = get_list_artifactDataType()
        >>> print('ip' in data_types)
        True
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info("Fetching artifact data types")
    response = _make_request(api, 'GET', '/api/list/list_artifactDataType', logger)

    if response.status_code == 200:
        return response.json()
    else:
        raise ConnectionError(f"Artifact data types fetch failed ({response.status_code}): {response.text}")


def get_describe_model(
    model: str,
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Get model schema description.

    Args:
        model: Model name (e.g., 'case', 'case_artifact', 'case_task')
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Dict containing model schema information

    Raises:
        ValueError: If credentials invalid or model name invalid
        ConnectionError: If server unreachable

    Examples:
        >>> schema = get_describe_model('case')
        >>> print(schema.keys())
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info(f"Fetching model description for '{model}'")
    response = _make_request(api, 'GET', f'/api/describe/{model}', logger)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        raise ValueError(f"Model '{model}' not found")
    else:
        raise ConnectionError(f"Model description fetch failed ({response.status_code}): {response.text}")


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Case Operations

def case_append_tags(
    case_id: Union[str, int],
    tags: List[str],
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Append tags to a case (merges with existing tags, deduplicates automatically).

    Unlike direct update operations that replace all tags, this function fetches
    the current tags, merges them with the new tags, and deduplicates before updating.

    Args:
        case_id: Case identifier (ID or case number)
        tags: List of tag strings to append
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Updated case object dict

    Raises:
        ValueError: If case not found or credentials invalid
        ConnectionError: If server unreachable

    Examples:
        >>> case = case_append_tags('12345', ['malware', 'phishing'])
        >>> print(case['tags'])
        ['existing-tag', 'malware', 'phishing']
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info(f"Appending tags to case {case_id}: {tags}")

    # Fetch current case to get existing tags
    case_resp = api.get_case(case_id)
    if case_resp.status_code == 404:
        raise ValueError(f"Case not found: {case_id}")
    elif case_resp.status_code != 200:
        raise ConnectionError(f"Failed to fetch case ({case_resp.status_code}): {case_resp.text}")

    case_json = case_resp.json()
    old_tags = case_json.get('tags', [])

    # Merge and deduplicate tags
    new_tags = list(set(old_tags + tags))
    logger.debug(f"Merging tags: {old_tags} + {tags} = {new_tags}")

    # Update case with merged tags
    try:
        result = api.case.update(case_id, tags=new_tags)
        logger.info(f"Successfully updated case {case_id} tags")
        return result.__dict__ if hasattr(result, '__dict__') else result
    except TheHiveException as e:
        logger.error(f"Tag update failed: {e}")
        raise ConnectionError(f"Failed to update case tags: {e}") from e


def case_update_tlp(
    case_id: Union[str, int],
    tlp: int,
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Update case TLP level.

    Args:
        case_id: Case identifier
        tlp: TLP level (0=WHITE, 1=GREEN, 2=AMBER, 3=RED)
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Updated case object dict

    Raises:
        ValueError: If TLP invalid or case not found
        ConnectionError: If server unreachable

    Examples:
        >>> case = case_update_tlp('12345', 2)  # Set to AMBER
        >>> print(case['tlp'])
        2
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    if tlp not in [0, 1, 2, 3]:
        raise ValueError(f"Invalid TLP level: {tlp}. Must be 0-3 (WHITE, GREEN, AMBER, RED)")

    logger.info(f"Updating case {case_id} TLP to {tlp}")

    try:
        result = api.case.update(case_id, tlp=int(tlp))
        logger.info(f"Successfully updated case {case_id} TLP")
        return result.__dict__ if hasattr(result, '__dict__') else result
    except TheHiveException as e:
        logger.error(f"TLP update failed: {e}")
        raise ConnectionError(f"Failed to update case TLP: {e}") from e


def case_append_description(
    case_id: Union[str, int],
    content: str,
    title: Optional[str] = None,
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Append content to case description with optional titled separator.

    Preserves existing description and appends new content with a visual separator.

    Args:
        case_id: Case identifier
        content: Content to append to description
        title: Optional title for the separator bar
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Updated case object dict

    Raises:
        ValueError: If case not found
        ConnectionError: If server unreachable

    Examples:
        >>> case = case_append_description(
        ...     '12345',
        ...     'Additional investigation findings',
        ...     title='SIEM Analysis'
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info(f"Appending description to case {case_id}")

    # Fetch current case to get existing description
    case_resp = api.get_case(case_id)
    if case_resp.status_code == 404:
        raise ValueError(f"Case not found: {case_id}")
    elif case_resp.status_code != 200:
        raise ConnectionError(f"Failed to fetch case ({case_resp.status_code}): {case_resp.text}")

    case_json = case_resp.json()
    old_desc = case_json.get('description', '')

    # Format appendage with separator
    appendage = _format_description_append(content, title)
    new_desc = old_desc + appendage

    # Update case with new description
    try:
        result = api.case.update(case_id, description=new_desc)
        logger.info(f"Successfully updated case {case_id} description")
        return result.__dict__ if hasattr(result, '__dict__') else result
    except TheHiveException as e:
        logger.error(f"Description update failed: {e}")
        raise ConnectionError(f"Failed to update case description: {e}") from e


def case_update_anyfield(
    case_id: Union[str, int],
    field_dict: Dict[str, Any],
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Update arbitrary case field(s).

    Generic updater that accepts any valid case fields as a dictionary.

    Args:
        case_id: Case identifier
        field_dict: Dict of field names to values (e.g., {'status': 'Resolved', 'severity': 3})
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Updated case object dict

    Raises:
        ValueError: If case not found or field invalid
        ConnectionError: If server unreachable

    Examples:
        >>> case = case_update_anyfield('12345', {'status': 'Resolved', 'severity': 3})
        >>> case = case_update_anyfield('12345', {'customFields': {'priority': {'string': 'High'}}})
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info(f"Updating case {case_id} fields: {list(field_dict.keys())}")

    try:
        result = api.case.update(case_id, **field_dict)
        logger.info(f"Successfully updated case {case_id}")
        return result.__dict__ if hasattr(result, '__dict__') else result
    except TheHiveException as e:
        logger.error(f"Field update failed: {e}")
        raise ConnectionError(f"Failed to update case fields: {e}") from e


def get_linked_cases(
    case_id: Union[str, int],
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """
    Get list of cases linked to the specified case.

    Args:
        case_id: Case identifier
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        List of linked case dicts

    Raises:
        ValueError: If case not found
        ConnectionError: If server unreachable

    Examples:
        >>> linked = get_linked_cases('12345')
        >>> print(f"Found {len(linked)} linked cases")
        >>> for case in linked:
        ...     print(f"  Case #{case['caseId']}: {case['title']}")
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info(f"Fetching linked cases for case {case_id}")
    response = _make_request(api, 'GET', f'/api/case/{case_id}/links', logger)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        raise ValueError(f"Case not found: {case_id}")
    else:
        raise ConnectionError(f"Linked cases fetch failed ({response.status_code}): {response.text}")


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Observable Operations

def get_observable(
    obs_id: str,
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Optional[Dict[str, Any]]:
    """
    Get observable by ID.

    Args:
        obs_id: Observable identifier (hex string)
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Observable dict, or None if not found

    Raises:
        ConnectionError: If server unreachable

    Examples:
        >>> obs = get_observable('abc123def456')
        >>> if obs:
        ...     print(f"{obs['dataType']}: {obs['data']}")
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info(f"Fetching observable {obs_id}")
    response = _make_request(api, 'GET', f'/api/case/artifact/{obs_id}', logger)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        logger.warning(f"Observable {obs_id} not found")
        return None
    else:
        raise ConnectionError(f"Observable fetch failed ({response.status_code}): {response.text}")


def update_observable(
    obs_json: Dict[str, Any],
    fields: Optional[List[str]] = None,
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Update observable with optional field filtering.

    The observable's 'id' field determines which observable to update.
    If fields list is provided, only those fields will be sent in the update.

    Args:
        obs_json: Observable dict (must contain 'id' field)
        fields: Optional list of field names to update (if empty, updates all standard fields)
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Updated observable dict

    Raises:
        ValueError: If 'id' field missing
        ConnectionError: If server unreachable

    Examples:
        >>> obs = get_observable('abc123')
        >>> obs['tags'].append('analyzed')
        >>> update_observable(obs, fields=['tags'])
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    obs_id = obs_json.get('id')
    if not obs_id:
        raise ValueError("Observable dict must contain 'id' field")

    logger.info(f"Updating observable {obs_id}")

    # Define standard updatable fields
    update_keys = [
        'data', 'dataType', 'ioc', 'message', 'reports',
        'sighted', 'startDate', 'status', 'tags', 'tlp'
    ]

    # Filter data based on fields parameter
    if fields:
        data = {k: v for k, v in obs_json.items() if k in fields}
    else:
        data = {k: v for k, v in obs_json.items() if k in update_keys}

    logger.debug(f"Updating fields: {list(data.keys())}")

    response = _make_request(
        api, 'PATCH', f'/api/case/artifact/{obs_id}', logger,
        headers={'Content-Type': 'application/json'},
        json=data
    )

    if response.status_code == 200:
        logger.info(f"Successfully updated observable {obs_id}")
        return response.json()
    elif response.status_code == 404:
        raise ValueError(f"Observable not found: {obs_id}")
    else:
        raise ConnectionError(f"Observable update failed ({response.status_code}): {response.text}")


def obs_append_tags(
    obs_id: str,
    tags: List[str],
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Append tags to observable (merges with existing tags).

    Args:
        obs_id: Observable identifier
        tags: List of tag strings to append
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Updated observable dict

    Raises:
        ValueError: If observable not found
        ConnectionError: If server unreachable

    Examples:
        >>> obs = obs_append_tags('abc123', ['suspicious', 'external'])
        >>> print(obs['tags'])
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    logger.info(f"Appending tags to observable {obs_id}: {tags}")

    # Get current observable
    obs_json = get_observable(obs_id, api, thehive_url, api_key, logger)
    if obs_json is None:
        raise ValueError(f"Observable not found: {obs_id}")

    # Merge tags
    old_tags = obs_json.get('tags', [])
    obs_json['tags'] = old_tags + tags  # Note: not deduping here to match original behavior

    # Update with new tags
    return update_observable(obs_json, fields=['tags'], api=api, thehive_url=thehive_url,
                           api_key=api_key, logger=logger)


def obs_update_tlp(
    obs_id: str,
    tlp: int,
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Update observable TLP level.

    Args:
        obs_id: Observable identifier
        tlp: TLP level (0=WHITE, 1=GREEN, 2=AMBER, 3=RED)
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        Updated observable dict

    Raises:
        ValueError: If TLP invalid or observable not found
        ConnectionError: If server unreachable

    Examples:
        >>> obs = obs_update_tlp('abc123', 3)  # Set to RED
        >>> print(obs['tlp'])
        3
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if tlp not in [0, 1, 2, 3]:
        raise ValueError(f"Invalid TLP level: {tlp}. Must be 0-3 (WHITE, GREEN, AMBER, RED)")

    logger.info(f"Updating observable {obs_id} TLP to {tlp}")

    # Get current observable
    obs_json = get_observable(obs_id, api, thehive_url, api_key, logger)
    if obs_json is None:
        raise ValueError(f"Observable not found: {obs_id}")

    # Update TLP
    obs_json['tlp'] = int(tlp)

    # Update with new TLP
    return update_observable(obs_json, fields=['tlp'], api=api, thehive_url=thehive_url,
                           api_key=api_key, logger=logger)


def obsfind_any_by_type_data(
    dataType: str,
    data: str,
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """
    Search for observables by dataType + data pair.

    Useful for finding duplicate observables or checking if an IOC already exists.
    For file observables, searches by filename (not hash).

    Args:
        dataType: Observable data type (e.g., 'ip', 'domain', 'hash', 'file')
        data: Observable data value (e.g., '192.168.1.100', 'evil.com')
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        List of matching observable dicts

    Raises:
        ConnectionError: If search fails

    Examples:
        >>> # Check for duplicate IPs
        >>> duplicates = obsfind_any_by_type_data('ip', '192.168.1.100')
        >>> print(f"Found {len(duplicates)} existing observables")
        >>>
        >>> # Find all observables for a domain
        >>> obs_list = obsfind_any_by_type_data('domain', 'evil.com')
        >>> for obs in obs_list:
        ...     print(f"  Case #{obs.get('_parent')}: {obs['data']}")
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info(f"Searching for observables: {dataType}={data}")

    # Use appropriate helper based on type
    if dataType == 'file':
        return _searchfor_similar_files__name(api, data, logger)
    else:
        return _searchfor_similar_nonfiles(api, dataType, data, logger)


def obsfind_dupes_by_id(
    obs_id: str,
    api: Optional[TheHiveApi] = None,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """
    Find duplicate observables by existing observable ID, excluding the original.

    This is the primary duplicate finder. For files, searches by hash (content-based,
    finds true duplicates regardless of filename). For non-files, searches by
    dataType + data pair.

    Args:
        obs_id: Observable ID to find duplicates of
        api: Optional TheHiveApi instance
        thehive_url: TheHive URL (used if api not provided)
        api_key: API key (used if api not provided)
        logger: Optional logger instance

    Returns:
        List of duplicate observable dicts (excluding the original observable)

    Raises:
        ValueError: If observable not found
        ConnectionError: If search fails

    Examples:
        >>> # Find duplicate files by hash (same content, any filename)
        >>> obs_id = 'abc123def456'  # A file observable
        >>> duplicates = obsfind_dupes_by_id(obs_id)
        >>> print(f"Found {len(duplicates)} files with same hash")
        >>>
        >>> # Find duplicate IPs
        >>> obs_id = 'xyz789'  # An IP observable
        >>> duplicates = obsfind_dupes_by_id(obs_id)
        >>> for dup in duplicates:
        ...     print(f"  Found in case: {dup['_parent']}")
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if api is None:
        api = _get_api(thehive_url, api_key, logger)

    logger.info(f"Searching for observables similar to {obs_id}")

    # Fetch the observable to determine type and value
    obs_json = get_observable(obs_id, api, thehive_url, api_key, logger)
    if obs_json is None:
        raise ValueError(f"Observable not found: {obs_id}")

    dataType = obs_json['dataType']

    # Search based on type
    if dataType == 'file':
        # For files: search by hash (content-based duplicate detection)
        file_hash = obs_json['attachment']['id']  # The hash is stored in attachment.id
        logger.debug(f"Searching for files with hash: {file_hash}")
        similars = _searchfor_similar_files__hash(api, file_hash, logger)
    else:
        # For non-files: search by dataType + data
        data = obs_json['data']
        logger.debug(f"Searching for {dataType}: {data}")
        similars = _searchfor_similar_nonfiles(api, dataType, data, logger)

    # Exclude the original observable from results
    filtered = [x for x in similars if x['id'] != obs_id]
    logger.info(f"Found {len(filtered)} similar observables (excluding original)")

    return filtered
