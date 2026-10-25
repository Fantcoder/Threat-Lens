"""Tests for IoC detector, validation, refanging, and normalization."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from threatlens.detector import (
    _check_domain,
    _check_hash,
    _check_ip_address,
    _check_url,
    detect_ioc,
    refang,
)
from threatlens.errors import InvalidIoCError
from threatlens.models import IoCType

# ==============================================================================
# Refanging Tests
# ==============================================================================


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("hxxp://example[.]com", "http://example.com"),
        ("hxxps://malicious(.)site[dot]org/path", "https://malicious.site.org/path"),
        ("h_ttp://bad.com", "http://bad.com"),
        ("h_ttps://bad.com", "https://bad.com"),
        ("1[.]1[.]1[.]1", "1.1.1.1"),
        ("8(.)8(.)8(.)8", "8.8.8.8"),
        ("phish[dot]com[:]8080", "phish.com:8080"),
        ("evil(dot)net(:)443", "evil.net:443"),
        ("http://clean.com", "http://clean.com"),
    ],
)
def test_refang_examples(defanged: str, expected: str) -> None:
    assert refang(defanged) == expected


# ==============================================================================
# Example-Based Detection Tests (>= 40 cases)
# ==============================================================================


@pytest.mark.parametrize(
    ("input_val", "expected_type", "expected_normalized"),
    [
        # --- Public IPv4 (7 cases) ---
        ("8.8.8.8", IoCType.IPV4, "8.8.8.8"),
        ("1.1.1.1", IoCType.IPV4, "1.1.1.1"),
        ("9.9.9.9", IoCType.IPV4, "9.9.9.9"),
        ("1[.]1[.]1[.]1", IoCType.IPV4, "1.1.1.1"),
        ("8(.)8(.)8(.)8", IoCType.IPV4, "8.8.8.8"),
        (" 208.67.222.222 ", IoCType.IPV4, "208.67.222.222"),
        ("142.250.190.46", IoCType.IPV4, "142.250.190.46"),
        # --- Public IPv6 (5 cases) ---
        ("2001:4860:4860::8888", IoCType.IPV6, "2001:4860:4860::8888"),
        ("2606:4700:4700::1111", IoCType.IPV6, "2606:4700:4700::1111"),
        ("2600:1400:1::1", IoCType.IPV6, "2600:1400:1::1"),
        ("2a00:1450:4009:815::200e", IoCType.IPV6, "2a00:1450:4009:815::200e"),
        (" 2001:4860:4860::8844 ", IoCType.IPV6, "2001:4860:4860::8844"),
        # --- MD5 Hashes (5 cases) ---
        ("44d88612fea8a8f36de82e1278abb02f", IoCType.MD5, "44d88612fea8a8f36de82e1278abb02f"),
        ("44D88612FEA8A8F36DE82E1278ABB02F", IoCType.MD5, "44d88612fea8a8f36de82e1278abb02f"),
        ("d41d8cd98f00b204e9800998ecf8427e", IoCType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        ("D41D8CD98F00B204E9800998ECF8427E", IoCType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        (" 098f6bcd4621d373cade4e832627b4f6 ", IoCType.MD5, "098f6bcd4621d373cade4e832627b4f6"),
        # --- SHA1 Hashes (4 cases) ---
        (
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            IoCType.SHA1,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
            IoCType.SHA1,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            "356a192b7913b04c54574d18c28d46e6395428ab",
            IoCType.SHA1,
            "356a192b7913b04c54574d18c28d46e6395428ab",
        ),
        (
            " 356A192B7913B04C54574D18C28D46E6395428AB ",
            IoCType.SHA1,
            "356a192b7913b04c54574d18c28d46e6395428ab",
        ),
        # --- SHA256 Hashes (5 cases) ---
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IoCType.SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            IoCType.SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            IoCType.SHA256,
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        ),
        (
            " 2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE ",
            IoCType.SHA256,
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        ),
        (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            IoCType.SHA256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        # --- Domains (8 cases) ---
        ("example.com", IoCType.DOMAIN, "example.com"),
        ("EXAMPLE.COM", IoCType.DOMAIN, "example.com"),
        ("sub.domain.co.uk", IoCType.DOMAIN, "sub.domain.co.uk"),
        ("example.com.", IoCType.DOMAIN, "example.com"),
        ("phish[.]site[.]org", IoCType.DOMAIN, "phish.site.org"),
        ("evil(.)malware(dot)net", IoCType.DOMAIN, "evil.malware.net"),
        ("münchen.de", IoCType.DOMAIN, "xn--mnchen-3ya.de"),
        ("test-domain.org", IoCType.DOMAIN, "test-domain.org"),
        # --- URLs (8 cases) ---
        ("http://example.com", IoCType.URL, "http://example.com/"),
        ("https://example.com/malware.exe", IoCType.URL, "https://example.com/malware.exe"),
        ("hxxp://evil[.]com/drop.sh", IoCType.URL, "http://evil.com/drop.sh"),
        ("hxxps://phish(.)org/login?ref=1#now", IoCType.URL, "https://phish.org/login?ref=1#now"),
        ("http://8.8.8.8:8080/c2", IoCType.URL, "http://8.8.8.8:8080/c2"),
        ("HTTPS://EXAMPLE.COM/Path", IoCType.URL, "https://example.com/Path"),
        ("http://test.domain.co.uk/", IoCType.URL, "http://test.domain.co.uk/"),
        ("https://secure.bank.com/account", IoCType.URL, "https://secure.bank.com/account"),
    ],
)
def test_detect_ioc_valid_examples(
    input_val: str, expected_type: IoCType, expected_normalized: str
) -> None:
    ioc_type, normalized = detect_ioc(input_val)
    assert ioc_type == expected_type
    assert normalized == expected_normalized


# ==============================================================================
# Private / Loopback / Reserved IP Rejection Tests
# ==============================================================================


@pytest.mark.parametrize(
    "private_ip",
    [
        "127.0.0.1",
        "127.0.0.53",
        "10.0.0.1",
        "10.255.255.255",
        "192.168.1.1",
        "192.168.0.254",
        "172.16.0.1",
        "172.31.255.255",
        "169.254.169.254",  # AWS link-local metadata
        "0.0.0.0",  # Unspecified
        "224.0.0.1",  # Multicast
        "::1",  # IPv6 loopback
        "::",  # IPv6 unspecified
        "fc00::1",  # IPv6 unique local
        "fe80::1",  # IPv6 link-local
        "ff02::1",  # IPv6 multicast
    ],
)
def test_detect_ioc_rejects_private_ips(private_ip: str) -> None:
    with pytest.raises(InvalidIoCError) as exc_info:
        detect_ioc(private_ip)
    assert "private" in str(exc_info.value).lower() or "reserved" in str(exc_info.value).lower()


def test_detect_ioc_rejects_url_with_private_ip() -> None:
    with pytest.raises(InvalidIoCError) as exc_info:
        detect_ioc("http://192.168.1.1/admin")
    assert "private" in str(exc_info.value).lower()


# ==============================================================================
# Edge Cases & Invalid Inputs
# ==============================================================================


@pytest.mark.parametrize(
    "invalid_input",
    [
        "",
        "   ",
        "\t\n",
        "not an ioc",
        "http://",
        "ftp://example.com/file",
        "example",
        "localhost",
        "bad_domain_with_underscores_in_suffix.c_om",
        "999.999.999.999",
        "-leading-hyphen.com",
        "trailing-hyphen-.com",
        "domain with spaces.com",
        "user@password:domain.com",
        "a" * 31,  # 31 hex chars (not MD5)
        "g" * 32,  # 32 non-hex chars
        "a" * 39,  # 39 hex chars (not SHA1)
        "z" * 40,  # 40 non-hex chars
        "a" * 63,  # 63 hex chars (not SHA256)
        "x" * 64,  # 64 non-hex chars
        "a" * 65,  # 65 hex chars
        "a" * 254 + ".com",  # domain > 253 chars
        "a." + ("b" * 64) + ".com",  # label > 63 chars
        "invalid..double-dot.com",
    ],
)
def test_detect_ioc_invalid_inputs(invalid_input: str) -> None:
    with pytest.raises(InvalidIoCError):
        detect_ioc(invalid_input)


# ==============================================================================
# Internal Helper Direct Unit Tests (for 100% Branch Coverage)
# ==============================================================================


def test_internal_helpers_edge_cases() -> None:
    # _check_hash with non-hex length 32
    assert _check_hash("z" * 32) is None
    # _check_ip_address with invalid IP
    assert _check_ip_address("not.an.ip") is None
    # _check_url without scheme
    assert _check_url("ftp://example.com") is None
    # _check_url with empty netloc or hostname
    assert _check_url("http://") is None
    assert _check_url("http://:8080") is None
    # _check_domain with illegal characters
    assert _check_domain("bad/domain.com") is None
    assert _check_domain("bad:domain.com") is None
    assert _check_domain("bad domain.com") is None
    assert _check_domain("bad@domain.com") is None
    assert _check_domain("") is None
    assert _check_domain("a" * 254) is None
    assert _check_domain("no-tld") is None
    assert _check_domain("label..empty.com") is None
    assert _check_domain("valid.unknownsuffix12345xyz") is None
    assert _check_domain(("b" * 64) + ".com") is None
    # IDNA encode error trigger (unpaired surrogate)
    assert _check_domain("bad\ud800.com") is None


# ==============================================================================
# Hypothesis Property-Based Tests
# ==============================================================================


@given(
    st.integers(min_value=1, max_value=223),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=1, max_value=254),
)
def test_hypothesis_valid_public_ipv4(o1: int, o2: int, o3: int, o4: int) -> None:
    """Hypothesis test: valid public IPv4 must detect as IPV4 or be rejected if private."""
    ip_str = f"{o1}.{o2}.{o3}.{o4}"
    try:
        ioc_type, normalized = detect_ioc(ip_str)
        assert ioc_type == IoCType.IPV4
        assert normalized == ip_str
    except InvalidIoCError as e:
        # Must be because it is private, loopback, or reserved
        assert "private" in str(e).lower() or "reserved" in str(e).lower()


@given(st.from_regex(r"^[0-9a-fA-F]{32}$"))
def test_hypothesis_md5(hex_str: str) -> None:
    ioc_type, normalized = detect_ioc(hex_str)
    assert ioc_type == IoCType.MD5
    assert normalized == hex_str.strip().lower()


@given(st.from_regex(r"^[0-9a-fA-F]{40}$"))
def test_hypothesis_sha1(hex_str: str) -> None:
    ioc_type, normalized = detect_ioc(hex_str)
    assert ioc_type == IoCType.SHA1
    assert normalized == hex_str.strip().lower()


@given(st.from_regex(r"^[0-9a-fA-F]{64}$"))
def test_hypothesis_sha256(hex_str: str) -> None:
    ioc_type, normalized = detect_ioc(hex_str)
    assert ioc_type == IoCType.SHA256
    assert normalized == hex_str.strip().lower()


@given(st.from_regex(r"^[a-z0-9]{3,15}\.(com|net|org)$"))
def test_hypothesis_simple_domains(domain: str) -> None:
    ioc_type, normalized = detect_ioc(domain)
    assert ioc_type == IoCType.DOMAIN
    assert normalized == domain.strip()
