# Roadmap

This roadmap tracks maintained, realistic work only. Items move based on user impact and security risk; dates are intentionally not promised.

Track bugs and feature requests in [Issues](https://github.com/batu3384/frostwall-beam/issues). Report vulnerabilities through the private process in [SECURITY.md](https://github.com/batu3384/frostwall-beam/blob/main/SECURITY.md).

## Current priorities

| Item | Goal |
|------|------|
| Signed Windows installers | Reduce SmartScreen friction with Authenticode signing |
| Release packaging | Publish reproducible macOS and Windows artifacts |
| Dependency maintenance | Review and apply compatible updates manually in the branchless upstream workflow |

## Next

| Item | Goal |
|------|------|
| Optional hosted mailbox reference deployment | Make six-digit Remote pairing easier to evaluate without self-hosting |
| QR representation of Remote invites | Reduce copy/paste friction while preserving the existing ticket format |
| Multi-peer Remote sessions | Extend the existing one-to-one internet session model |
| Advisory scanning in CI | Add deterministic dependency audit gates without creating upstream bot branches |

## Later

| Item | Goal |
|------|------|
| Automated tag releases | Build and sign `.dmg` / `.msi` artifacts in CI |
| Linux desktop target | Evaluate Linux as a supported platform after release packaging is stable |

## Completed

| Item | Result |
|------|--------|
| LAN transfer foundation | mDNS discovery, direct socket, SPAKE2, AEAD chunks, Blake3 verification |
| Internet mode foundation | iroh transport, invite format, optional mailbox crate |
| Adversarial hardening | Encrypted control plane, mailbox token auth, bounded pairing, filesystem protections |
| Invite-first Remote pairing | No mandatory server; copy/paste invite with relay and address hints |
| Cross-platform CI | Rust tests and Clippy on Linux, macOS, Windows; frontend test/build |
| Repository hygiene | Single upstream `main` branch, canonical documentation under `docs/` |

## Priority rules

1. Security regressions and data-loss risks come first.
2. Reliability and transfer correctness come before new features.
3. UX improvements must preserve explicit verification and receiver consent.
4. Features that require new trusted infrastructure are avoided unless the trust boundary is documented.
