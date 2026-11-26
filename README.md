<p align="center">
  <img src="src-tauri/icons/128x128.png" width="96" alt="Frostwall Beam" />
</p>

<h1 align="center">Frostwall Beam</h1>

<p align="center">
  <strong>Encrypted file transfer for your local network — or across the internet.</strong><br />
  Pair two devices, verify a rotating code, and send files or folders end-to-end encrypted. No cloud account, no tracking.
</p>

<p align="center">
  <a href="https://github.com/batu3384/frostwall-beam/actions/workflows/ci.yml"><img src="https://github.com/batu3384/frostwall-beam/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey" alt="Platform" />
  <img src="https://img.shields.io/badge/stack-Tauri%202%20%7C%20Rust%20%7C%20React-0891b2" alt="Stack" />
</p>

---

## Overview

Frostwall Beam is a cross-platform desktop app for private file transfer. It works without a cloud service on the same network and can traverse NATs over the internet using `iroh`. The Rust core provides SPAKE2 pairing, per-chunk AEAD encryption, Blake3 integrity verification, explicit receiver approval, and strict path confinement.

## Features

- **LAN transfer:** zero-config mDNS discovery, direct socket, multi-host selection.
- **Internet transfer:** copy-paste invite by default; optional self-hosted mailbox for six-digit lookup.
- **Verified pairing:** six-digit SPAKE2 code plus a rotating human-verification code before sending.
- **End-to-end encryption:** XChaCha20-Poly1305 chunks and an encrypted control plane.
- **Safe receiving:** manifest review, accept/decline, collision-safe renames, partial-file cleanup.
- **Path hardening:** traversal, symlinks, Windows junctions, dangerous Unicode, system paths, and device names rejected.
- **Desktop UX:** drag-and-drop files/folders, speed and ETA, transfer history, Turkish/English UI, system/dark/light theme.

## Quick start

### Prerequisites

- Node.js 22.12+ and pnpm 10
- Rust stable
- Platform tooling from the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)

### Run from source

```bash
git clone https://github.com/batu3384/frostwall-beam.git
cd frostwall-beam
pnpm install
pnpm tauri dev
```

### Build installers

```bash
pnpm tauri build
```

| Platform | Output |
|----------|--------|
| macOS | `.app` / `.dmg` under `src-tauri/target/release/bundle/` |
| Windows | `.msi` / `.exe` under the same bundle directory |

Unsigned Windows builds may trigger SmartScreen. Release builds should be Authenticode-signed.

## First transfer

1. On the host device, choose **Host a session**. On the same network, share the six-digit code. In Remote mode, copy the invite instead.
2. On the joining device, choose the same network mode, enter the code or paste the invite, then connect.
3. Confirm that both screens show the same rotating six-digit verification code.
4. Drag files or folders into the sender window.
5. On the receiver, review the manifest and choose **Accept** or **Decline**.

Files are saved to `~/Downloads/Frostwall Beam` unless another download folder is configured.

## Internet mode

```text
Same network:       mDNS discovery → direct LAN socket
Different networks: invite or optional mailbox → iroh QUIC (direct or relayed)
                                   ↓
              SPAKE2 → AEAD control/payload → Blake3 verification
```

The invite is the default remote flow and requires no server. The optional [`mailbox/`](mailbox/) service only maps a short-lived pairing code to an endpoint and never sees file contents or session keys. See [Architecture](docs/wiki/Architecture.md) and [Security](docs/wiki/Security.md) for details.

## Repository layout

```text
src/          React frontend
src-tauri/    Tauri desktop shell and Rust application core
mailbox/      Optional rendezvous service for internet pairing
docs/wiki/    Documentation source and GitHub Wiki pages
docs/archive/ Historical implementation notes
scripts/      Maintenance scripts
```

## Development

```bash
pnpm test
pnpm build
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

CI runs Rust tests and Clippy on Linux, macOS, and Windows, plus frontend tests and a production build. The repository intentionally keeps a single upstream branch, `main`; contributors should work from forks rather than pushing feature branches to this repository.

## Documentation

| Document | Contents |
|----------|----------|
| [Getting Started](docs/wiki/Getting-Started.md) | Install, build, first transfer, Remote field test |
| [Architecture](docs/wiki/Architecture.md) | Components, network paths, session coordination, mailbox API |
| [Security](docs/wiki/Security.md) | Threat model, cryptography, trust boundaries, hardening |
| [Troubleshooting](docs/wiki/Troubleshooting.md) | Pairing, Remote, transfer, and build fixes |
| [FAQ](docs/wiki/FAQ.md) | Common questions |
| [Roadmap](docs/wiki/Roadmap.md) | Current and planned work |

## Security

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md) for private disclosure. The technical security model is documented in [docs/wiki/Security.md](docs/wiki/Security.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run the frontend and Rust verification commands above before submitting changes.

## License

[MIT](LICENSE) © [batu3384](https://github.com/batu3384)
