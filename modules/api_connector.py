"""
API Connector - Bulletproof connection establishment and health checking for TheHive and Cortex

This module provides reliable, health-checked API connections to TheHive and Cortex with
intelligent error categorization. Each connection is immediately verified with a probe call
to distinguish between configuration errors (bad credentials) and infrastructure problems
(bad host/port, network issues).

Key Features:
    - Automatic health checking for both TheHive and Cortex connections
    - Intelligent error categorization (ValueError for config, ConnectionError for infrastructure)
    - Environment variable support with explicit parameter override
    - Detailed error messages with actionable hints
    - Flexible logging (stdlib, loguru, or custom)
    - No explicit timeout parameters (relies on library defaults)

Basic Usage:
    >>> from api_connector import get_thehive_api, get_cortex_api
    >>> thehive_api = get_thehive_api()
    >>> cortex_api = get_cortex_api()

Advanced Usage:
    >>> # Explicit credentials
    >>> thehive_api = get_thehive_api(
    ...     thehive_url='https://thehive.local:9000',
    ...     api_key='your-thehive-key'
    ... )
    >>>
    >>> cortex_api = get_cortex_api(
    ...     cortex_url='https://cortex.local:9001',
    ...     api_key='your-cortex-key'
    ... )
    >>>
    >>> # Custom logger
    >>> from loguru import logger
    >>> api = get_thehive_api(logger=logger)
    >>>
    >>> # Error handling
    >>> try:
    ...     api = get_thehive_api()
    ... except ValueError as e:
    ...     print(f"Configuration error: {e}")
    ... except ConnectionError as e:
    ...     print(f"Connection failed: {e}")

Environment Variables:
    THEHIVE_URL - TheHive instance URL (e.g., https://thehive.example.com:9000)
    THEHIVE_API_KEY - TheHive API key for authentication
    CORTEX_URL - Cortex instance URL (e.g., https://cortex.example.com:9001)
    CORTEX_API_KEY - Cortex API key for authentication

Functions:
    get_thehive_api(thehive_url=None, api_key=None, logger=None) -> TheHiveApi
        Establish and health-check TheHive API connection

    get_cortex_api(cortex_url=None, api_key=None, logger=None) -> CortexApi
        Establish and health-check Cortex API connection

External Dependency:
    - Requires 'thehive4py' library: pip install thehive4py
    - Requires 'cortex4py' library: pip install cortex4py
    - Both libraries are required even if you only use one API

Author: Jan
Version: 1.0
"""

try:
    from thehive4py.api import TheHiveApi
    from thehive4py.exceptions import TheHiveException
except ImportError:
    raise ImportError(
        "api_connector.py requires 'thehive4py' library\n"
        "Install: pip install thehive4py\n"
        "Docs: https://github.com/TheHive-Project/TheHive4py"
    )

try:
    from cortex4py.api import Api as CortexApi
    from cortex4py.exceptions import (
        AuthenticationError,
        InvalidInputError,
        ServiceUnavailableError,
        CortexException
    )
except ImportError:
    raise ImportError(
        "api_connector.py requires 'cortex4py' library\n"
        "Install: pip install cortex4py\n"
        "Docs: https://github.com/TheHive-Project/Cortex4py"
    )

import os
import logging
from typing import Optional, Any

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Private helper functions

def _validate_credentials(
    url: Optional[str],
    api_key: Optional[str],
    url_env_var: str,
    key_env_var: str,
    service_name: str
) -> tuple[str, str]:
    """
    Validate and retrieve credentials with env var fallback.

    Args:
        url: Explicit URL parameter
        api_key: Explicit API key parameter
        url_env_var: Environment variable name for URL
        key_env_var: Environment variable name for API key
        service_name: Service name for error messages ('TheHive' or 'Cortex')

    Returns:
        Tuple of (url, api_key) with values from params or env vars

    Raises:
        ValueError: If URL or API key not provided and env vars not set
    """
    url = url or os.getenv(url_env_var)
    api_key = api_key or os.getenv(key_env_var)

    if not url:
        raise ValueError(
            f"{service_name} URL not provided. "
            f"Set {url_env_var} env var or pass url parameter"
        )
    if not api_key:
        raise ValueError(
            f"{service_name} API key not provided. "
            f"Set {key_env_var} env var or pass api_key parameter"
        )

    return url, api_key

def _health_check_thehive(api: TheHiveApi, url: str, logger: Any) -> None:
    """
    Perform health check on TheHive API connection.

    Calls api.get_current_user() and categorizes errors based on response.

    Args:
        api: TheHiveApi instance to check
        url: TheHive URL for error messages
        logger: Logger instance

    Raises:
        ValueError: If authentication fails (401)
        ConnectionError: If infrastructure error (502, TheHiveException, other)
    """
    try:
        response = api.get_current_user()
    except TheHiveException as e:
        logger.error(f"TheHive connection failed: {e}")
        raise ConnectionError(
            f"Cannot connect to TheHive at {url}. "
            f"Check port number and network connectivity."
        ) from e

    if response.status_code == 200:
        logger.info(f"Successfully connected to TheHive at {url}")
        return
    elif response.status_code == 401:
        raise ValueError(
            f"Invalid API key for TheHive at {url}. "
            f"Check THEHIVE_API_KEY env var or api_key parameter."
        )
    elif response.status_code == 502:
        raise ConnectionError(
            f"Bad Gateway error connecting to TheHive at {url}. "
            f"Check hostname/IP address."
        )
    else:
        raise ConnectionError(
            f"TheHive API error ({response.status_code}): {response.reason}. "
            f"Check TheHive instance health."
        )

def _health_check_cortex(api: CortexApi, url: str, logger: Any) -> None:
    """
    Perform health check on Cortex API connection.

    Calls api.analyzers.find_all({}) and categorizes errors by exception type.

    Args:
        api: CortexApi instance to check
        url: Cortex URL for error messages
        logger: Logger instance

    Raises:
        ValueError: If authentication fails (AuthenticationError)
        ConnectionError: If infrastructure error (InvalidInputError, ServiceUnavailableError, other)
    """
    try:
        api.analyzers.find_all({})
    except AuthenticationError as e:
        logger.error(f"Cortex authentication failed: {e}")
        raise ValueError(
            f"Invalid API key for Cortex at {url}. "
            f"Check CORTEX_API_KEY env var or api_key parameter."
        ) from e
    except InvalidInputError as e:
        logger.error(f"Cortex invalid input: {e}")
        raise ConnectionError(
            f"Invalid hostname or network error connecting to Cortex at {url}. "
            f"Check hostname/IP address."
        ) from e
    except ServiceUnavailableError as e:
        logger.error(f"Cortex service unavailable: {e}")
        raise ConnectionError(
            f"Cannot connect to Cortex at {url}. "
            f"Check port number and service availability."
        ) from e
    except CortexException as e:
        logger.error(f"Cortex connection error: {e}")
        raise ConnectionError(
            f"Cortex API error: {e}. Check Cortex instance health."
        ) from e

    logger.info(f"Successfully connected to Cortex at {url}")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Public API functions

def get_thehive_api(
    thehive_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> TheHiveApi:
    """
    Establish and health-check TheHive API connection.

    Creates TheHive API client and performs health check by calling
    get_current_user(). Categorizes errors to distinguish between
    configuration issues (bad credentials) and infrastructure problems
    (bad host/port, network failures).

    Args:
        thehive_url: TheHive instance URL (e.g., https://thehive.example.com:9000)
                     Defaults to THEHIVE_URL environment variable
        api_key: API key for authentication
                 Defaults to THEHIVE_API_KEY environment variable
        logger: Optional logger instance (defaults to stdlib logging)

    Returns:
        TheHiveApi instance, verified as healthy

    Raises:
        ValueError: Configuration error (missing credentials, invalid API key)
        ConnectionError: Infrastructure error (bad host, bad port, network unreachable)

    Examples:
        >>> api = get_thehive_api()  # Uses env vars
        >>> user = api.get_current_user()

        >>> api = get_thehive_api(
        ...     thehive_url='https://thehive.local:9000',
        ...     api_key='your-key-here'
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    logger.info("Attempting to connect to TheHive")

    # Validate credentials
    url, key = _validate_credentials(
        thehive_url, api_key,
        'THEHIVE_URL', 'THEHIVE_API_KEY',
        'TheHive'
    )

    logger.debug(f"Creating TheHive API client for {url}")

    # Create API client
    api = TheHiveApi(url, key, cert=True)

    # Perform health check
    _health_check_thehive(api, url, logger)

    return api

def get_cortex_api(
    cortex_url: Optional[str] = None,
    api_key: Optional[str] = None,
    logger: Optional[Any] = None
) -> CortexApi:
    """
    Establish and health-check Cortex API connection.

    Creates Cortex API client and performs health check by calling
    analyzers.find_all({}). Categorizes errors to distinguish between
    configuration issues (bad credentials) and infrastructure problems
    (bad host/port, network failures).

    Args:
        cortex_url: Cortex instance URL (e.g., https://cortex.example.com:9001)
                    Defaults to CORTEX_URL environment variable
        api_key: API key for authentication
                 Defaults to CORTEX_API_KEY environment variable
        logger: Optional logger instance (defaults to stdlib logging)

    Returns:
        CortexApi instance, verified as healthy

    Raises:
        ValueError: Configuration error (missing credentials, invalid API key)
        ConnectionError: Infrastructure error (bad host, bad port, network unreachable)

    Examples:
        >>> api = get_cortex_api()  # Uses env vars
        >>> analyzers = api.analyzers.find_all({})

        >>> api = get_cortex_api(
        ...     cortex_url='https://cortex.local:9001',
        ...     api_key='your-key-here'
        ... )
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    logger.info("Attempting to connect to Cortex")

    # Validate credentials
    url, key = _validate_credentials(
        cortex_url, api_key,
        'CORTEX_URL', 'CORTEX_API_KEY',
        'Cortex'
    )

    logger.debug(f"Creating Cortex API client for {url}")

    # Create API client
    api = CortexApi(url, key)

    # Perform health check
    _health_check_cortex(api, url, logger)

    return api
