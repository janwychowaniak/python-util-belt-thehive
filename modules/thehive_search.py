"""
TheHive Case Search - Search TheHive cases with flexible filters

This module provides a simple, flexible interface for searching cases in
TheHive. It wraps the thehive4py API with convenient filtering options,
pagination support, and proper error handling for common scenarios.

Key Features:
    - Flexible case search with multiple filter criteria
    - Support for status, severity, tags, date ranges
    - Automatic pagination handling
    - Environment-based authentication
    - Configurable logging (stdlib, loguru, or custom)
    - Returns clean dictionaries for easy processing

Basic Usage:
    >>> from thehive_search import search_cases
    >>> cases = search_cases(status='Open')
    >>> len(cases)
    15

Advanced Usage:
    >>> cases = search_cases(
    ...     status='Open',
    ...     severity=[2, 3],
    ...     tags=['phishing', 'malware'],
    ...     max_results=50
    ... )
    >>> for case in cases:
    ...     print(f"Case #{case['caseId']}: {case['title']}")

Custom Authentication:
    >>> cases = search_cases(
    ...     status='Open',
    ...     thehive_url='https://thehive.local',
    ...     api_key='your-api-key-here'
    ... )

Environment Variables:
    THEHIVE_URL - TheHive instance URL (e.g., https://thehive.example.com)
    THEHIVE_API_KEY - API key for authentication

Functions:
    search_cases(status=None, severity=None, tags=None, **kwargs) -> List[Dict]
        Search cases with flexible criteria

    get_case_by_id(case_id, **kwargs) -> Optional[Dict]
        Retrieve a single case by ID

External Dependency:
    - Requires 'thehive4py' library: pip install thehive4py
    - TheHive 4.x or later required

Author: Jan
Version: 1.0
"""

try:
    from thehive4py.api import TheHiveApi
    from thehive4py.query import *
except ImportError:
    raise ImportError(
        "thehive_search.py requires 'thehive4py' library\n"
        "Install: pip install thehive4py\n"
        "Docs: https://github.com/TheHive-Project/TheHive4py"
    )

import os
import logging
from typing import Optional, Dict, List, Any, Union

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def _get_api(
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
        raise ValueError(
            "TheHive URL not provided. Set THEHIVE_URL env var or pass thehive_url parameter"
        )
    if not api_key:
        raise ValueError(
            "API key not provided. Set THEHIVE_API_KEY env var or pass api_key parameter"
        )

    logger.info(f"Connecting to TheHive at {thehive_url}")

    try:
        return TheHiveApi(thehive_url, api_key, cert=True)
    except Exception as e:
        logger.error(f"Failed to connect to TheHive: {e}")
        raise ConnectionError(f"Cannot connect to TheHive at {thehive_url}: {e}")

def _build_query(
    status: Optional[str] = None,
    severity: Optional[Union[int, List[int]]] = None,
    tags: Optional[List[str]] = None
) -> Any:
    """Build TheHive query from filter criteria."""
    filters = []

    if status:
        filters.append(Eq('status', status))

    if severity is not None:
        if isinstance(severity, int):
            filters.append(Eq('severity', severity))
        else:
            filters.append(In('severity', severity))

    if tags:
        # Each tag gets its own In() filter; combined with And() for AND logic
        for tag in tags:
            filters.append(In('tags', [tag]))

    return And(*filters) if filters else None

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

def search_cases(
    status: Optional[str] = None,
    severity: Optional[Union[int, List[int]]] = None,
    tags: Optional[List[str]] = None,
    max_results: int = 100,
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """
    Search TheHive cases with flexible filter criteria.

    Args:
        status: Case status ('New', 'Open', 'Resolved', 'Closed')
        severity: Single severity (int) or list of severities (1=Low, 2=Medium, 3=High, 4=Critical)
        tags: List of tags to filter by (AND logic - case must have all tags)
        max_results: Maximum number of results to return (default: 100)
        thehive_url: Optional TheHive URL (defaults to THEHIVE_URL env var)
        api_key: Optional API key (defaults to THEHIVE_API_KEY env var)
        logger: Optional logger instance (defaults to stdlib logging)

    Returns:
        List of case dictionaries with keys: caseId, title, description, status,
        severity, startDate, tags, owner, etc.

    Raises:
        ValueError: If authentication credentials not provided
        ConnectionError: If TheHive API is unreachable

    Examples:
        # Find all open cases
        >>> cases = search_cases(status='Open')

        # Find high-severity phishing cases
        >>> cases = search_cases(severity=3, tags=['phishing'])

        # Find critical or high-severity open cases
        >>> cases = search_cases(status='Open', severity=[3, 4])
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        api = _get_api(thehive_url, api_key, logger)
        query = _build_query(status, severity, tags)

        logger.info(f"Searching cases with filters: status={status}, severity={severity}, tags={tags}")

        # Only pass query parameter if filters are specified (TheHive API rejects query=None)
        if query is not None:
            response = api.find_cases(
                query=query,
                range=f'0-{max_results}',
                sort='-startDate'
            )
        else:
            response = api.find_cases(
                range=f'0-{max_results}',
                sort='-startDate'
            )

        if response.status_code == 200:
            cases = response.json()
            logger.info(f"Found {len(cases)} cases")
            return cases
        else:
            logger.error(f"Search failed with status {response.status_code}: {response.text}")
            return []

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise
    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during case search: {e}")
        return []

def get_case_by_id(
    case_id: Union[str, int],
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single case by ID.

    Args:
        case_id: TheHive case ID in the format required by your TheHive version
                 (TheHive v3: alphanumeric string like 'AZox3NEoutgTU9OdgZOz',
                  TheHive v4: prefixed numeric like '~123456')
        thehive_url: Optional TheHive URL (defaults to THEHIVE_URL env var)
        api_key: Optional API key (defaults to THEHIVE_API_KEY env var)
        logger: Optional logger instance (defaults to stdlib logging)

    Returns:
        Case dictionary if found, None if not found

    Examples:
        >>> # TheHive v3
        >>> case = get_case_by_id('AZox3NEoutgTU9OdgZOz')
        >>> # TheHive v4
        >>> case = get_case_by_id('~123456')
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        api = _get_api(thehive_url, api_key, logger)

        logger.info(f"Fetching case {case_id}")
        response = api.get_case(case_id)

        if response.status_code == 200:
            case = response.json()
            logger.info(f"Retrieved case: {case.get('title', 'Untitled')}")
            return case
        elif response.status_code == 404:
            logger.warning(f"Case {case_id} not found")
            return None
        else:
            logger.error(f"Failed to fetch case {case_id}: {response.status_code} - {response.text}")
            return None

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise
    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error fetching case {case_id}: {e}")
        return None
