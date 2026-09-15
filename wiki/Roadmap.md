# Roadmap

> Milestones grounded in shipped work (README, adversarial audit plan, main branch). No speculative features.

**Status legend:** `Done` · `Now` · `Next` · `Later`

Track bugs and requests: [Issues](https://github.com/batu3384/frostwall-beam/issues) · Security: [Security advisories](https://github.com/batu3384/frostwall-beam/security/advisories)

## Now

| Item | Status | Notes |
|------|--------|-------|
| Wiki + operator docs | Now | This wiki; mailbox TLS deploy still documented |
| Signed Windows installers | Now | Authenticode for SmartScreen-friendly releases |

## Next

| Item | Status | Notes |
|------|--------|-------|
| Hosted mailbox (optional 6-digit Remote) | Next | Convenience only — invite path is the default |
| QR for Remote invite | Next | README backlog — copy/paste the ticket works today |
| Multi-peer Remote sessions | Next | README backlog — LAN multi-host exists; internet is 1:1 today |
| Advisory CI gate (`cargo deny`) | Next | Dependabot covers updates; deny/audit still optional |

## Later

| Item | Status | Notes |
|------|--------|-------|
| Automated release artifacts | Later | CI-built `.dmg` / `.msi` on tag |
| Linux desktop target | Later | Not in current platform matrix |

## Completed (Done)

| Item | Status | Notes |
|------|--------|-------|
| Tauri 2 app + LAN transfer | Done | mDNS, SPAKE2, AEAD chunks, Blake3 |
| Internet mode foundation | Done | `iroh`, mailbox workspace, host/join commands |
| Adversarial review hardening | Done | Control-plane AEAD, mailbox token auth, pairing bounds |
| Invite-based Remote (no mailbox) | Done | iroh `EndpointTicket` + SPAKE2 digits; legacy `fwb2-` / `fwb1-`; mailbox optional |
| Theme tokens + settings UX | Done | System/dark/light, mailbox URL is optional HTTPS |
| CI: test + clippy + frontend | Done | Linux / macOS / Windows rust jobs; `pnpm test` + `pnpm build` |
| Dependabot | Done | Weekly cargo / npm / GitHub Actions PRs |

## Timeline (approximate)

```mermaid
gantt
    title Frostwall Beam milestones
    dateFormat YYYY-MM-DD
    section Foundation
    LAN transfer + pairing           :done, lan, 2026-06-30, 2026-07-15
    Internet mode (iroh + mailbox)   :done, inet, 2026-07-01, 2026-07-20
    section Hardening
    Adversarial review fixes         :done, audit, 2026-07-11, 2026-08-09
    Wiki + remote release path         :active, wiki, 2026-08-09, 2026-09-15
    section Next
    QR / link pairing                :qr, 2026-10-01, 2026-12-15
    Multi-peer Remote                :multi, 2027-01-01, 2027-06-30
```

## How priorities change

1. Open an [issue](https://github.com/batu3384/frostwall-beam/issues/new) with use case and impact.
2. Security regressions jump the queue — use [private advisory](https://github.com/batu3384/frostwall-beam/security/advisories/new).
3. `Now` items should fit in ~1–2 release cycles; `Next` when `Now` clears.
