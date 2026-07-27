# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security** tab using
a private vulnerability report. Do not open a public issue for an unpatched
security problem and do not include credentials, API keys, tokens, or production
configuration in any report.

Include the affected component (stdio package or Worker), reproduction steps,
impact, and any suggested mitigation. Maintainers will acknowledge the report
and coordinate remediation and disclosure through the private report.

## Operator responsibility

This repository contains deployable source, not a hosted Taskboi account or
managed service. Self-hosting operators are responsible for securely configuring
their Taskboi API endpoint, OAuth issuer, encryption secret, client policy,
Cloudflare account, monitoring, and incident response. See
[workers/README.md](workers/README.md) for required runtime bindings.
