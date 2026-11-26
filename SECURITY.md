# Security Policy

## Supported versions

Security fixes are applied to the `main` branch. There are currently no long-term support release lines.

| Version | Supported |
|---------|-----------|
| `main`  | Yes       |
| releases before `0.1.0` | No |

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability.

Use a [private GitHub Security Advisory](https://github.com/batu3384/frostwall-beam/security/advisories/new) when possible. If advisory creation is unavailable, contact the maintainer through the contact information on the [GitHub profile](https://github.com/batu3384).

Include:

- affected commit or version;
- reproduction steps or proof of concept;
- impact and attack surface;
- relevant logs, packet captures, or screenshots;
- whether the issue requires LAN access, Remote mode, mailbox access, or local filesystem access.

The maintainer aims to acknowledge reports within 7 days. Do not disclose the issue publicly until a fix is available and coordinated disclosure has been agreed.

## Security model

The technical threat model, cryptographic design, trust boundaries, and implemented hardening are documented in [docs/wiki/Security.md](docs/wiki/Security.md).
