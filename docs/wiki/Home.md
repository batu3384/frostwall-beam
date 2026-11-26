# Frostwall Beam

**Encrypted file transfer** for the same Wi‑Fi — or across the internet with a copy-paste invite. Pair two devices, verify with a rotating check digit, send files or folders end-to-end encrypted. No cloud account, no tracking.

| | |
|---|---|
| **Repo** | [github.com/batu3384/frostwall-beam](https://github.com/batu3384/frostwall-beam) |
| **License** | [MIT](https://github.com/batu3384/frostwall-beam/blob/main/LICENSE) |
| **Stack** | Tauri 2 · Rust · React |
| **Platforms** | macOS · Windows |

## Highlights

| Area | What you get |
|------|----------------|
| **Same Wi‑Fi** | Zero-config mDNS discovery, direct LAN socket, multi-host picker |
| **Remote** | NAT traversal via `iroh` (QUIC). Default: share an iroh ticket invite (relay + IPs). Optional mailbox for 6-digit lookup |
| **Pairing** | 6-digit code + key-confirmation MAC + 30s rotating verification code |
| **Transfer** | Files & folders, drag-and-drop, live speed/ETA, collision-safe renames |
| **Control** | Accept/decline manifests; cancel in-flight without disconnecting |
| **UX** | TR/EN UI, system/dark/light theme, transfer history |

## Wiki pages

| Page | Description |
|------|-------------|
| [Getting Started](Getting-Started) | Prerequisites, build, first transfer |
| [Architecture](Architecture) | Crates, modules, data flow |
| [Security](Security) | Threat model, crypto, trust boundaries |
| [Troubleshooting](Troubleshooting) | Common errors and fixes |
| [FAQ](FAQ) | Short answers |
| [Roadmap](Roadmap) | Now / Next / Later milestones |

## Quick links

- [Report a bug](https://github.com/batu3384/frostwall-beam/issues/new)
- [Security disclosure](Security#reporting-vulnerabilities)
- [CI status](https://github.com/batu3384/frostwall-beam/actions/workflows/ci.yml)
