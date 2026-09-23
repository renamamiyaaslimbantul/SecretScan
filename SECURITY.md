# Security policy

## Supported versions

Only the latest version on the `main` branch and the latest published release receive security fixes during this early project phase.

## Reporting a vulnerability

Do not open a public issue for an undisclosed vulnerability.

Report security issues privately through the repository's GitHub **Security** tab using **Report a vulnerability**. Include:

- affected version or commit
- Windows and Go versions
- reproduction steps that do not contain real credentials
- impact and proposed mitigation, if known

Never include live credentials in an issue, pull request, email, or reproduction archive. Revoke exposed credentials immediately through the affected provider.

SecretScan is local-only and does not receive scanned source or telemetry. Reports should focus on the executable, detection logic, configuration parsing, Git hook behavior, or release artifacts.

## Disclosure

Maintainers will acknowledge valid reports, investigate privately, and coordinate a fix and public disclosure timeline with the reporter.
