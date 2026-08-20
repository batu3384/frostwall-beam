# Getting Started

## Prerequisites

- [Node.js](https://nodejs.org/) 20+ and [pnpm](https://pnpm.io/)
- [Rust](https://rustup.rs/) stable
- [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) (Xcode CLT on macOS, MSVC on Windows)

## Clone and run

```bash
git clone https://github.com/batu3384/frostwall-beam.git
cd frostwall-beam
pnpm install
pnpm tauri dev
```

## Build installers

```bash
pnpm tauri build
```

| Platform | Output |
|----------|--------|
| macOS | `.app` / `.dmg` under `src-tauri/target/release/bundle/` |
| Windows | `.msi` / `.exe` under the same bundle directory |

> **Windows:** Unsigned builds may trigger SmartScreen. For distribution, Authenticode-sign with `signtool`.

## First transfer (two devices)

1. **Host (Device A)** — *Host a session* → create the 6-digit code → share it.
2. **Join (Device B)** — *Join a session* → enter the code → *Connect* (pick a host if several appear on the LAN).
3. **Verify** — confirm the **rotating 6-digit code** matches on both screens.
4. **Send** — drag files/folders or use the file picker.
5. **Receive** — review the manifest → **Accept** or **Decline**.
6. Files land in `~/Downloads/Frostwall Beam` by default, or your folder in **Settings**.

**Single-machine smoke test:** run two app instances after `pnpm tauri build` — one hosts, one joins.

## Remote mode (different networks)

Remote pairing appears in the UI only when a **real rendezvous URL** is configured:

- User setting: mailbox URL in config (HTTPS in release builds), or
- Release build with compile-time `FROSTWALL_MAILBOX_URL=https://…`

Both devices must pick **Remote** and use the same code. Deploy the mailbox service:

```bash
cargo run --release -p frostwall-mailbox
# default bind: 0.0.0.0:8787 — put TLS in front (Caddy, Nginx, Fly.io, etc.)
```

See [Architecture](Architecture#network-paths) for how mailbox + `iroh` fit together.

## Development checks

```bash
pnpm build
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

CI runs on every push to `main` — Rust tests + clippy + `pnpm build`.
