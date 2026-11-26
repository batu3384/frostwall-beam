# Adversarial Review Hardening — Archive

> Archived historical summary. This document is kept for audit context only; it is not an implementation plan and does not describe the current repository workflow.

## Scope

The July 2026 adversarial review covered the internet-mode foundation and the original LAN transfer implementation. Findings focused on session lifecycle races, mailbox registration trust, control-plane confidentiality, transfer cancellation, filesystem confinement, and localized UI state.

## Result

The findings were addressed on `main` in a series of focused fixes. Current behavior is documented in the canonical pages:

- [Architecture](../wiki/Architecture.md)
- [Security](../wiki/Security.md)
- [Troubleshooting](../wiki/Troubleshooting.md)

## Historical context

The original implementation artifact contained step-by-step agent instructions and branch-based workflow notes. Those instructions are obsolete because the upstream repository now intentionally keeps only the protected `main` branch. The full historical text remains available in git history when audit detail is required.
