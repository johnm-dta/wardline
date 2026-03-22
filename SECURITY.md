# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Wardline, please report it
responsibly.

**Do not open a public issue.** Instead, email security concerns to
the maintainers via GitHub's
[private vulnerability reporting](https://github.com/tachyon-beep/wardline/security/advisories/new).

You can expect:

- **Acknowledgement** within 48 hours.
- **Status update** within 7 days with an assessment and remediation timeline.
- **Credit** in the release notes (unless you prefer otherwise).

## Scope

Wardline is a static analysis and boundary enforcement tool. Security issues
of particular interest include:

- Arbitrary code execution via crafted YAML manifests or corpus files.
- Path traversal in file discovery or manifest loading.
- Unsafe deserialization (e.g., YAML `!!python/object` injection).
- Scanner rule bypasses that allow policy violations to go undetected.
