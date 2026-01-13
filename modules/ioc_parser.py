"""
IOC Parser - Extract and normalize Indicators of Compromise from text

This module provides utilities for extracting and normalizing common IOC types
(IP addresses, domains, URLs, file hashes) from unstructured text. Useful for
parsing threat intelligence reports, email bodies, or log files before adding
observables to TheHive.

Key Features:
    - Extract IPs (IPv4/IPv6), domains, URLs, file hashes (MD5, SHA1, SHA256)
    - Normalize IOC formats (lowercase domains, strip whitespace, etc.)
    - Deduplicate extracted IOCs
    - Defang/refang support (hxxp -> http, [.] -> .)
    - Returns structured data ready for TheHive observable creation
    - Zero external dependencies (pure stdlib)

Basic Usage:
    >>> from ioc_parser import extract_iocs
    >>> text = "Malware contacted 192.168.1.100 and evil[.]com"
    >>> iocs = extract_iocs(text)
    >>> iocs['ip']
    ['192.168.1.100']
    >>> iocs['domain']
    ['evil.com']

Advanced Usage:
    >>> iocs = extract_iocs(
    ...     text,
    ...     refang=True,
    ...     deduplicate=True,
    ...     normalize=True
    ... )
    >>> for ioc_type, values in iocs.items():
    ...     print(f"{ioc_type}: {len(values)} found")

Format for TheHive:
    >>> from ioc_parser import extract_iocs, format_for_thehive
    >>> text = "Contacted 8.8.8.8 and malware.com"
    >>> iocs = extract_iocs(text)
    >>> observables = format_for_thehive(iocs, tlp=2, tags=['malware'])
    >>> observables[0]
    {'dataType': 'ip', 'data': '8.8.8.8', 'tlp': 2, 'tags': ['malware'], 'message': 'Extracted from report'}

Environment Variables:
    None

Functions:
    extract_iocs(text, refang=True, deduplicate=True, normalize=True) -> Dict[str, List[str]]
        Extract IOCs from text with optional processing

    format_for_thehive(iocs, tlp=2, tags=None, message='') -> List[Dict]
        Convert extracted IOCs to TheHive observable format

External Dependency:
    No external dependencies - pure Python stdlib

Author: Jan
Version: 1.0
"""

import re
from typing import Dict, List, Set, Optional
from collections import defaultdict

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# IOC Regex Patterns (compiled for performance)

IPv4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
    re.IGNORECASE
)

URL_PATTERN = re.compile(
    r'(?:https?|ftp|hxxps?|ftps?)://[^\s<>"{}|\\^`\[\]]+',
    re.IGNORECASE
)

MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Private helper functions

def _refang(text: str) -> str:
    """
    Convert defanged IOCs back to normal format.

    Examples:
        hxxp -> http
        hxxps -> https
        [.] -> .
        (.) -> .
    """
    text = re.sub(r'hxxps?', lambda m: m.group(0).replace('xx', 'tt'), text, flags=re.IGNORECASE)
    text = re.sub(r'\[\.\]|\(\.\)', '.', text)
    return text

def _normalize_domain(domain: str) -> str:
    """Normalize domain: lowercase, strip whitespace."""
    return domain.lower().strip()

def _normalize_ip(ip: str) -> str:
    """Normalize IP: strip whitespace."""
    return ip.strip()

def _normalize_hash(hash_value: str) -> str:
    """Normalize hash: lowercase."""
    return hash_value.lower()

def _normalize_url(url: str) -> str:
    """Normalize URL: strip whitespace."""
    return url.strip()

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Public API

def extract_iocs(
    text: str,
    refang: bool = True,
    deduplicate: bool = True,
    normalize: bool = True
) -> Dict[str, List[str]]:
    """
    Extract IOCs from unstructured text.

    Args:
        text: Input text to parse for IOCs
        refang: Convert defanged IOCs (hxxp, [.]) to normal format (default: True)
        deduplicate: Remove duplicate IOCs (default: True)
        normalize: Normalize IOC formats (lowercase, strip whitespace) (default: True)

    Returns:
        Dictionary with keys: 'ip', 'domain', 'url', 'md5', 'sha1', 'sha256'
        Each key maps to a list of extracted IOCs of that type

    Examples:
        >>> text = "Contacted 192.168.1.1 and evil.com"
        >>> iocs = extract_iocs(text)
        >>> iocs['ip']
        ['192.168.1.1']
        >>> iocs['domain']
        ['evil.com']

        >>> text = "Hash: ABCD1234... and hxxp://evil[.]com"
        >>> iocs = extract_iocs(text, refang=True)
        >>> iocs['url']
        ['http://evil.com']
    """
    if refang:
        text = _refang(text)

    # Extract all IOC types - use list if not deduplicating
    if deduplicate:
        results: Dict[str, any] = {
            'ip': set(IPv4_PATTERN.findall(text)),
            'domain': set(DOMAIN_PATTERN.findall(text)),
            'url': set(URL_PATTERN.findall(text)),
            'md5': set(MD5_PATTERN.findall(text)),
            'sha1': set(SHA1_PATTERN.findall(text)),
            'sha256': set(SHA256_PATTERN.findall(text)),
        }
    else:
        results = {
            'ip': IPv4_PATTERN.findall(text),
            'domain': DOMAIN_PATTERN.findall(text),
            'url': URL_PATTERN.findall(text),
            'md5': MD5_PATTERN.findall(text),
            'sha1': SHA1_PATTERN.findall(text),
            'sha256': SHA256_PATTERN.findall(text),
        }

    # Normalize if requested
    if normalize:
        if deduplicate:
            results['ip'] = {_normalize_ip(ip) for ip in results['ip']}
            results['domain'] = {_normalize_domain(d) for d in results['domain']}
            results['url'] = {_normalize_url(u) for u in results['url']}
            results['md5'] = {_normalize_hash(h) for h in results['md5']}
            results['sha1'] = {_normalize_hash(h) for h in results['sha1']}
            results['sha256'] = {_normalize_hash(h) for h in results['sha256']}
        else:
            results['ip'] = [_normalize_ip(ip) for ip in results['ip']]
            results['domain'] = [_normalize_domain(d) for d in results['domain']]
            results['url'] = [_normalize_url(u) for u in results['url']]
            results['md5'] = [_normalize_hash(h) for h in results['md5']]
            results['sha1'] = [_normalize_hash(h) for h in results['sha1']]
            results['sha256'] = [_normalize_hash(h) for h in results['sha256']]

    # Convert to lists (sorted if deduplicated)
    output: Dict[str, List[str]] = {
        key: sorted(list(values)) if deduplicate else values
        for key, values in results.items()
    }

    return output

def format_for_thehive(
    iocs: Dict[str, List[str]],
    tlp: int = 2,
    tags: Optional[List[str]] = None,
    message: str = ''
) -> List[Dict[str, any]]:
    """
    Convert extracted IOCs to TheHive observable format.

    Args:
        iocs: Dictionary from extract_iocs() with IOC lists
        tlp: TLP level (0=WHITE, 1=GREEN, 2=AMBER, 3=RED) (default: 2/AMBER)
        tags: List of tags to add to all observables (default: [])
        message: Message to attach to all observables (default: '')

    Returns:
        List of observable dictionaries ready for TheHive API

    Examples:
        >>> iocs = {'ip': ['1.2.3.4'], 'domain': ['evil.com']}
        >>> obs = format_for_thehive(iocs, tlp=2, tags=['phishing'])
        >>> obs[0]
        {'dataType': 'ip', 'data': '1.2.3.4', 'tlp': 2, 'tags': ['phishing'], 'message': ''}
    """
    if tags is None:
        tags = []

    observables = []

    # Map IOC types to TheHive dataTypes
    type_mapping = {
        'ip': 'ip',
        'domain': 'domain',
        'url': 'url',
        'md5': 'hash',
        'sha1': 'hash',
        'sha256': 'hash',
    }

    for ioc_type, ioc_list in iocs.items():
        data_type = type_mapping.get(ioc_type, 'other')
        for ioc_value in ioc_list:
            observables.append({
                'dataType': data_type,
                'data': ioc_value,
                'tlp': tlp,
                'tags': tags.copy(),  # Copy to avoid mutation
                'message': message,
                'ioc': True,
                'sighted': False
            })

    return observables
