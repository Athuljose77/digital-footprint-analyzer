# Security Policy

## Supported versions

Security fixes are applied to the `main` branch and the latest tagged release.
Older releases may not receive fixes.

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a
vulnerability** flow on the repository's Security tab, or contact the
maintainer through GitHub if private reporting is unavailable.

Please do not open a public issue containing exploit details or personal data.
Include:

- A description of the issue and its impact.
- Steps to reproduce it.
- The affected platform and version/commit.
- Any suggested mitigation, if you have one.

## Scope

Relevant areas include:

- Local data handling and history storage.
- Browser profile and extension parsing.
- Username/email lookup validation and SSRF protections.
- Report export sanitization.
- Path handling for selected files.
- Any accidental network access from a module that should be local-only.

## Out of scope

This is not a hosted service and does not provide a bug bounty. The project is
also not a substitute for a professional security audit. Reports about missing
coverage or unsupported platforms are welcome as ordinary issues rather than
security vulnerabilities unless they expose data or enable unintended access.

## Response

Reports are reviewed on a best-effort basis. Please allow time for a fix and
coordinate disclosure before publishing details.
