"""Security guards for PhishGuard.

Provides:
- SSRF protection (blocks private IPs, localhost, cloud metadata)
- URL validation and sanitization
- DNS resolution safety checks
- Redirect chain validation

Every submitted URL is treated as UNTRUSTED INPUT.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from backend.app.core.config import get_settings


@dataclass
class URLValidationResult:
    """Result of URL validation.

    Attributes:
        is_valid: Whether the URL passed all security checks.
        url: The validated/normalized URL.
        errors: List of validation errors if invalid.
        warnings: List of non-blocking warnings.
    """

    is_valid: bool
    url: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class SSRFProtector:
    """Server-Side Request Forgery protection.

    Validates URLs against known-dangerous targets before
    allowing any network request. This is the first line of
    defense against SSRF attacks.

    The protector checks:
    1. URL scheme (only http/https allowed)
    2. Hostname against blocklist
    3. Resolved IP against private/reserved ranges
    4. Port against common sensitive ports
    """

    # Ports that should never be accessed
    DANGEROUS_PORTS = {
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        110,   # POP3
        143,   # IMAP
        445,   # SMB
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        27017, # MongoDB
        9200,  # Elasticsearch
        2379,  # etcd
    }

    def __init__(self) -> None:
        settings = get_settings()
        self._blocked_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in settings.security.blocked_ip_ranges:
            try:
                self._blocked_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass  # Skip invalid CIDR entries

        self._blocked_hostnames = set(
            h.lower() for h in settings.security.blocked_hostnames
        )
        self._allowed_schemes = set(
            s.lower() for s in settings.security.allowed_schemes
        )
        self._max_redirects = settings.security.max_redirects

    def validate_url(self, url: str) -> URLValidationResult:
        """Validate a URL for safe access.

        Performs comprehensive security checks including:
        - Scheme validation
        - Hostname blocklist check
        - DNS resolution to detect private IPs
        - Port safety check

        Args:
            url: The URL to validate.

        Returns:
            URLValidationResult with validation status and any errors.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # Normalize
        url = url.strip()
        if not url:
            return URLValidationResult(
                is_valid=False, url=url, errors=["Empty URL"]
            )

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception:
            return URLValidationResult(
                is_valid=False, url=url, errors=["Malformed URL"]
            )

        # Check scheme
        scheme = (parsed.scheme or "").lower()
        if scheme not in self._allowed_schemes:
            errors.append(
                f"Blocked scheme: '{scheme}'. Allowed: {self._allowed_schemes}"
            )

        # Check for credentials in URL (user:pass@host)
        if parsed.username or parsed.password:
            errors.append("URLs with embedded credentials are not allowed")

        # Extract hostname
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            errors.append("No hostname in URL")
            return URLValidationResult(
                is_valid=False, url=url, errors=errors
            )

        # Check hostname blocklist
        if hostname in self._blocked_hostnames:
            errors.append(f"Blocked hostname: '{hostname}'")

        # Check for IP address in hostname
        if self._is_ip_blocked(hostname):
            errors.append(f"Blocked IP address: '{hostname}'")

        # DNS resolution check (resolve hostname to IP and verify)
        if not errors:  # Only do DNS if no errors yet
            dns_errors = self._check_dns_resolution(hostname)
            errors.extend(dns_errors)

        # Port check
        port = parsed.port
        if port and port in self.DANGEROUS_PORTS:
            errors.append(f"Blocked port: {port}")

        # Check for suspicious URL patterns
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            warnings.append("URL contains @ symbol which may indicate URL obfuscation")

        return URLValidationResult(
            is_valid=len(errors) == 0,
            url=url,
            errors=errors,
            warnings=warnings,
        )

    def _is_ip_blocked(self, hostname: str) -> bool:
        """Check if a hostname is a blocked IP address.

        Args:
            hostname: The hostname to check.

        Returns:
            True if the hostname is a blocked IP.
        """
        try:
            ip = ipaddress.ip_address(hostname)
            return self._is_ip_in_blocked_range(ip)
        except ValueError:
            return False  # Not an IP address

    def _is_ip_in_blocked_range(
        self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        """Check if an IP address falls within any blocked range.

        Args:
            ip: The IP address to check.

        Returns:
            True if the IP is in a blocked range.
        """
        # Check private/reserved
        if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            return True

        # Check configured blocked ranges
        for network in self._blocked_networks:
            try:
                if ip in network:
                    return True
            except TypeError:
                continue  # IPv4/IPv6 mismatch
        return False

    def _check_dns_resolution(self, hostname: str) -> list[str]:
        """Resolve hostname and verify the IP is not blocked.

        This prevents DNS rebinding attacks where a hostname
        resolves to a private IP.

        Args:
            hostname: The hostname to resolve.

        Returns:
            List of error messages (empty if safe).
        """
        errors: list[str] = []
        try:
            # Use getaddrinfo for both IPv4 and IPv6
            results = socket.getaddrinfo(
                hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            for family, _, _, _, sockaddr in results:
                ip_str = sockaddr[0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if self._is_ip_in_blocked_range(ip):
                        errors.append(
                            f"Hostname '{hostname}' resolves to blocked IP: {ip_str}"
                        )
                except ValueError:
                    continue
        except socket.gaierror:
            # DNS resolution failed — this is acceptable for analysis
            # (the URL might be dead, which is information itself)
            pass
        return errors

    def validate_redirect(self, original_url: str, redirect_url: str, redirect_count: int) -> URLValidationResult:
        """Validate a redirect target.

        Ensures redirect chains don't escape to blocked resources.

        Args:
            original_url: The original requested URL.
            redirect_url: The redirect target URL.
            redirect_count: Current number of redirects followed.

        Returns:
            URLValidationResult for the redirect target.
        """
        if redirect_count >= self._max_redirects:
            return URLValidationResult(
                is_valid=False,
                url=redirect_url,
                errors=[f"Maximum redirects ({self._max_redirects}) exceeded"],
            )

        result = self.validate_url(redirect_url)
        if not result.is_valid:
            result.errors.insert(
                0,
                f"Redirect from {original_url} to blocked target",
            )
        return result


def sanitize_url(url: str) -> str:
    """Basic URL sanitization.

    Strips whitespace, removes null bytes, normalizes scheme.

    Args:
        url: Raw URL input.

    Returns:
        Sanitized URL string.
    """
    # Remove null bytes and control characters
    url = re.sub(r'[\x00-\x1f\x7f]', '', url)
    # Strip whitespace
    url = url.strip()
    # Add scheme if missing
    if url and not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url
