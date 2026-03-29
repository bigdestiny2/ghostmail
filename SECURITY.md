# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in GhostMail, please report it responsibly.

**Do NOT open a public GitHub issue.**

Email: security@ghostmail.dev

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < 1.0   | No        |

## Scope

The following are in scope:
- Authentication bypass
- Encryption key leakage
- Plaintext exposure of encrypted messages
- Session hijacking
- SQL injection
- Remote code execution
- Privilege escalation
- SMTP relay abuse

The following are out of scope:
- Denial of service (rate limiting is configurable)
- Social engineering
- Issues in third-party dependencies (report upstream)

## Disclosure

We follow coordinated disclosure. We will:
1. Acknowledge your report within 48 hours
2. Confirm the vulnerability and determine impact
3. Develop and test a fix
4. Release a patched version
5. Credit you in the release notes (unless you prefer anonymity)

We ask that you give us 90 days to resolve the issue before public disclosure.
