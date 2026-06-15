# Security Policy

## Supported versions

crudauth is pre-1.0. During this phase only the latest release receives security fixes.
Always run the latest version.

| Version        | Supported     |
| -------------- | ------------- |
| Latest release | Yes           |
| Older releases | No            |

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue for a vulnerability.

Use either channel:

- Email: **igor@benav.io**
- GitHub Security Advisory: https://github.com/benavlabs/crudauth/security/advisories/new

Include whatever you have: a description, steps to reproduce, the impact, the affected
version, and a suggested fix if you have one.

## What to expect

- Acknowledgment within 48 hours.
- A status update within a week.
- A fix timeline based on severity, critical issues first.
- Coordinated disclosure once a fix is released, with credit if you want it.

## Scope

crudauth is an authentication library, so its security behavior is the product. Reports
about the auth surface are especially welcome:

- session and CSRF handling
- bearer-token signing, scope handling, and revocation
- login lockout and rate limiting
- OAuth `state` handling and redirect safety
- password storage and verification
- registration field gating (mass-assignment)
- timing and user-enumeration properties of the login path

Some properties are documented as irreducible by design (for example, a holder of a correct
password can still infer that an account is disabled). If you are unsure whether something
counts, report it anyway.
