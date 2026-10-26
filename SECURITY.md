# Security Policy

The ThreatLens project prioritizes defensive cybersecurity, robust data protection, and secure coding practices.

---

## 1. Supported Versions

Only the latest release of ThreatLens receives security patches.

| Version | Supported |
| :--- | :--- |
| `1.0.x` | :white_check_mark: |
| `< 1.0.0` | :x: |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability or potential risk (e.g., input validation bypass, timing attacks in authentication, or credential leaks in logs), please do **NOT** open a public issue on GitHub.

Instead, please report vulnerabilities privately:
- **Email**: `security@threatlens.dev` (or via GitHub Private Vulnerability Reporting on the repository).
- **GPG Key**: Available upon request.

Please include:
1. Description of the vulnerability.
2. Step-by-step reproduction instructions or proof of concept.
3. Potential impact on ThreatLens deployments or credential confidentiality.

### Response Timeline:
- **Initial Acknowledgment**: Within 48 hours.
- **Triage & Status Assessment**: Within 5 business days.
- **Patch Release**: Within 14 business days depending on severity.

---

## 3. ThreatLens Built-in Security Architecture

ThreatLens is engineered with intrinsic security guardrails:

1. **RFC Non-Routable Address Rejection (Input Hygiene)**:
   - The IoC detector strictly rejects queries against private, loopback, link-local, multicast, and cloud metadata ranges (RFC 1918, RFC 3927, RFC 4291, `169.254.169.254`).
   - Ensures input hygiene by filtering non-public indicators before dispatching upstream queries (note: input validation is not a complete SSRF defense against DNS rebinding, IPv6-mapped IPv4, or downstream redirects).
2. **Timing-Safe Authentication**:
   - Service API key comparisons use constant-time `hmac.compare_digest` to prevent side-channel timing attacks.
3. **Automated Secret Redaction**:
   - All configured API keys (VirusTotal, AlienVault OTX, AbuseIPDB, service keys) are registered with the logging subsystem.
   - The `SecretRedactionFilter` scrubs credentials and replaces them with `***REDACTED***` across all emitted JSON log streams.
4. **Hardened Container Runtime**:
   - Docker container runs as an unprivileged system user (`threatlens`, UID 10001) with non-login shell (`/sbin/nologin`).
   - Read-only root filesystem compatible with isolated volume mount for `/app/data`.
5. **Static Analysis & SAST Gates**:
   - CI workflows enforce automated Bandit AST scanning and `pip-audit` CVE checks on every commit.
