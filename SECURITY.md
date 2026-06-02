# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Previous release | ✅ (critical fixes only) |
| Older versions | ❌ |

## Reporting a vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Specter Scanner, please report it responsibly:

**Email:** security@spectersystems.ai

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your name and contact details (optional, for acknowledgement)

We will acknowledge your report within 48 hours and provide a detailed response within 5 business days. We will keep you informed of our progress and notify you when the issue is resolved.

## Disclosure policy

- We ask that you give us reasonable time to fix the issue before public disclosure
- We will credit reporters in the release notes unless you request anonymity
- We do not offer a bug bounty program at this time

## Security design principles

Specter Scanner is designed with security as a first-class concern:

**Read-only by design.** The scanner only requires read-only IAM permissions. It never writes to, modifies, or deletes any resource in the scanned account.

**No credential storage.** The scanner reads credentials from environment variables and the standard AWS credential chain. It never stores credentials to disk or transmits them to the platform.

**ExternalId for cross-account access.** Cross-account IAM role assumption uses a unique ExternalId to prevent confused deputy attacks.

**HMAC-signed ingest payloads.** When posting results to the Specter Platform, the payload is signed with HMAC-SHA256. The platform rejects unsigned or tampered payloads.

**Standalone mode.** Users who do not trust the platform connection can run in `--no-platform` mode. No data leaves the local environment.

**Open source.** The scanner is fully open source under Apache 2.0. Every line of code that runs in your environment is publicly auditable.
