"""
IOC (Indicator of Compromise) extractor for STIX pattern strings.

Extracts actionable IOC values from STIX 2.1 pattern expressions using
regex matching. Supports the following IOC types:

- IPv4 addresses:  [ipv4-addr:value = '1.2.3.4']
- IPv6 addresses:  [ipv6-addr:value = '::1']
- Domains:         [domain-name:value = 'evil.com']
- URLs:            [url:value = 'http://evil.com/path']
- Hashes:          [file:hashes.'SHA-256' = 'abc123...']

Both IPv4 and IPv6 addresses are normalized to type 'ip'.
"""

import re
from typing import Optional
from app.utils.logger import get_logger

logger = get_logger(__name__)


class IOCExtractor:
    """
    Regex-based IOC extractor for STIX pattern strings.

    Each STIX indicator contains a pattern like:
        [ipv4-addr:value = '185.220.101.5']

    This class extracts the IOC value and determines its type.
    """

    # Regex patterns for STIX pattern string extraction
    _IPV4_PATTERN = re.compile(
        r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE
    )
    _IPV6_PATTERN = re.compile(
        r"\[ipv6-addr:value\s*=\s*'([^']+)'\]", re.IGNORECASE
    )
    _DOMAIN_PATTERN = re.compile(
        r"\[domain-name:value\s*=\s*'([^']+)'\]", re.IGNORECASE
    )
    _URL_PATTERN = re.compile(
        r"\[url:value\s*=\s*'([^']+)'\]", re.IGNORECASE
    )
    _HASH_PATTERN = re.compile(
        r"\[file:hashes\.'[^']+'\s*=\s*'([^']+)'\]", re.IGNORECASE
    )

    def extract(self, pattern: str) -> Optional[tuple[str, str]]:
        """
        Extract an IOC value and type from a STIX pattern string.

        Args:
            pattern: STIX 2.1 pattern string (e.g. "[ipv4-addr:value = '1.2.3.4']")

        Returns:
            Tuple of (value, type) where type is one of: ip, domain, url, hash.
            Returns None if no IOC can be extracted from the pattern.
        """
        if not pattern:
            return None

        # Try each extractor in order of specificity
        extractors = [
            (self._extract_ipv4, "ip"),
            (self._extract_ipv6, "ip"),
            (self._extract_url, "url"),      # URL before domain (URLs contain domains)
            (self._extract_domain, "domain"),
            (self._extract_hash, "hash"),
        ]

        for extractor_fn, ioc_type in extractors:
            value = extractor_fn(pattern)
            if value:
                return (value, ioc_type)

        logger.debug(f"No IOC extracted from pattern: {pattern}")
        return None

    def _extract_ipv4(self, pattern: str) -> Optional[str]:
        """Extract an IPv4 address from a STIX pattern."""
        match = self._IPV4_PATTERN.search(pattern)
        return match.group(1) if match else None

    def _extract_ipv6(self, pattern: str) -> Optional[str]:
        """Extract an IPv6 address from a STIX pattern. Mapped to type 'ip'."""
        match = self._IPV6_PATTERN.search(pattern)
        return match.group(1) if match else None

    def _extract_domain(self, pattern: str) -> Optional[str]:
        """Extract a domain name from a STIX pattern."""
        match = self._DOMAIN_PATTERN.search(pattern)
        return match.group(1) if match else None

    def _extract_url(self, pattern: str) -> Optional[str]:
        """Extract a URL from a STIX pattern."""
        match = self._URL_PATTERN.search(pattern)
        return match.group(1) if match else None

    def _extract_hash(self, pattern: str) -> Optional[str]:
        """Extract a file hash from a STIX pattern (any hash algorithm)."""
        match = self._HASH_PATTERN.search(pattern)
        return match.group(1) if match else None
