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

1. **Host (Device A)** — *Host a session*. Same Wi‑Fi: share the 6-digit code. **Remote:** copy the invite (same Wi‑Fi not required).
2. **Join (Device B)** — same network mode → *Join a session* → enter the code **or paste the invite** → *Connect*.
3. **Verify** — both screens show the same **rotating 6-digit code**. Confirm **codes match** (or **Kodlar aynı**) before sending; a mismatch disconnects.
4. **Send** — drag files/folders or use the file picker.
5. **Receive** — review the manifest → **Accept** or **Decline**.
6. Files land in `~/Downloads/Frostwall Beam` by default, or your folder in **Settings**.

**Single-machine smoke test:** run two app instances after `pnpm tauri build` — one hosts, one joins.

## Remote mode (different networks)

Pick **Remote** on both devices. The host copies an invite (iroh ticket with relay/IP hints); the joiner pastes it. `iroh` dials by public key over QUIC. **No mailbox required.** The host keeps waiting until **Cancel** — sharing the invite does not have a 5-minute deadline. If the host later toasts that a relay was found, copy the invite again before the joiner pastes.

Optional: deploy a mailbox so joiners can type only the 6-digit code:

```bash
cargo run --release -p frostwall-mailbox
# default: 127.0.0.1:8787. Public: MAILBOX_BIND=0.0.0.0 PORT=8787 — put TLS in front.
```

Then set **Settings → Pairing server** (HTTPS in release) or build with `FROSTWALL_MAILBOX_URL=https://…`.

See [Architecture](Architecture#network-paths) for invite vs mailbox vs `iroh`.

## Development checks

```bash
pnpm test
pnpm build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

CI on every push to `main`: Rust test+clippy on Linux, macOS, and Windows; frontend `pnpm test` + `pnpm build`.

## Two-network Remote (field proof)

CI cannot prove two-NAT. On two machines, two networks (phone hotspot vs home):

1. Both pick **Remote**. Host: wait until the relay toast, copy the invite.
2. Joiner: **paste the invite** (not the 6-digit mailbox code).
3. Confirm rotating codes match. Send one small file.

Need outbound HTTPS 443 to n0 relays. If this fails, see [Troubleshooting](Troubleshooting#remote-mode).
