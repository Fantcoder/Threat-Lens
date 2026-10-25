"""IoC Type Detection, Validation, and Normalization."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

import tldextract

from threatlens.errors import InvalidIoCError
from threatlens.models import IoCType


def _replace_http_scheme(m: re.Match[str]) -> str:
    return "https://" if "s" in m.group(0).lower() else "http://"


# Regular expressions for refanging defanged inputs
_DEFANG_PATTERNS: list[tuple[re.Pattern[str], Any]] = [
    (re.compile(r"hxxps?://", re.IGNORECASE), _replace_http_scheme),
    (re.compile(r"h_ttps?://", re.IGNORECASE), _replace_http_scheme),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\(:\)", re.IGNORECASE), ":"),
]

# Hashes: MD5 (32), SHA1 (40), SHA256 (64) hexadecimal strings
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# Domain label regex (RFC 1035 / RFC 1123)
_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Extract without downloading PSL on the fly (use bundled cache)
_extractor = tldextract.TLDExtract(cache_dir=None)


def refang(value: str) -> str:
    """Refang common defanged threat-intel inputs.

    Examples:
        hxxp://example[.]com -> http://example.com
        1[.]1[.]1[.]1 -> 1.1.1.1
        bad[dot]com[:]8080 -> bad.com:8080
    """
    result = value.strip()
    for pattern, repl in _DEFANG_PATTERNS:
        result = pattern.sub(repl, result)
    return result.strip()


def _check_ip_address(value: str) -> tuple[IoCType, str] | None:
    """Validate and normalize IPv4 and IPv6 addresses."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    ):
        raise InvalidIoCError(
            value,
            f"Private, loopback, or reserved IP address ({value}) cannot be queried",
        )

    if isinstance(ip, ipaddress.IPv4Address):
        return IoCType.IPV4, str(ip)
    return IoCType.IPV6, str(ip)


def _check_hash(value: str) -> tuple[IoCType, str] | None:
    """Validate and normalize cryptographic hashes."""
    if _MD5_RE.match(value):
        return IoCType.MD5, value.lower()
    if _SHA1_RE.match(value):
        return IoCType.SHA1, value.lower()
    if _SHA256_RE.match(value):
        return IoCType.SHA256, value.lower()
    return None


def _check_url(value: str) -> tuple[IoCType, str] | None:
    """Validate and normalize web URLs."""
    lower_val = value.lower()
    if not (lower_val.startswith("http://") or lower_val.startswith("https://")):
        return None

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None

    hostname = parsed.hostname
    if not hostname:
        return None

    # If the URL hostname is an IP, reject private/reserved IPs
    try:
        ip = ipaddress.ip_address(hostname)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise InvalidIoCError(
                value,
                f"URL contains a private, loopback, or reserved IP address ({hostname})",
            )
    except ValueError:
        pass  # Hostname is a domain, not an IP address

    # Normalize: scheme and netloc lowercased, retain exact path/query/params
    netloc = parsed.netloc.lower()
    scheme = parsed.scheme.lower()
    path = parsed.path or "/"

    normalized = urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))
    return IoCType.URL, normalized


def _check_domain(value: str) -> tuple[IoCType, str] | None:
    """Validate and normalize domain names."""
    # Disqualify URLs, hashes, IPs, or invalid domain strings
    if "/" in value or ":" in value or " " in value or "@" in value:
        return None

    cleaned = value.rstrip(".")
    if not cleaned or len(cleaned) > 253:
        return None

    # Handle Internationalized Domain Names (IDNA / punycode)
    try:
        ascii_domain = cleaned.encode("idna").decode("ascii").lower()
    except Exception:
        return None

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        return None

    for label in labels:
        if not _DOMAIN_LABEL_RE.match(label):
            return None

    # Check Public Suffix using tldextract
    extracted = _extractor(ascii_domain)
    if not extracted.suffix or not extracted.domain:
        return None

    return IoCType.DOMAIN, ascii_domain


def detect_ioc(raw_value: str) -> tuple[IoCType, str]:
    """Auto-detect IoC type, validate strictly, refang, and normalize.

    Args:
        raw_value: Raw input string (may be defanged, uppercase, have whitespace).

    Returns:
        tuple[IoCType, str]: The detected IoCType and the normalized value.

    Raises:
        InvalidIoCError: If the input cannot be identified or is an invalid IoC.
    """
    if not raw_value or not raw_value.strip():
        raise InvalidIoCError(raw_value, "Input string is empty or whitespace")

    refanged = refang(raw_value)

    # 1. Hashes (MD5, SHA1, SHA256)
    hash_match = _check_hash(refanged)
    if hash_match:
        return hash_match

    # 2. IP Addresses (IPv4, IPv6)
    ip_match = _check_ip_address(refanged)
    if ip_match:
        return ip_match

    # 3. URLs (starts with http:// or https://)
    url_match = _check_url(refanged)
    if url_match:
        return url_match

    # 4. Domains (FQDNs)
    domain_match = _check_domain(refanged)
    if domain_match:
        return domain_match

    raise InvalidIoCError(raw_value, "Could not determine IoC type")
