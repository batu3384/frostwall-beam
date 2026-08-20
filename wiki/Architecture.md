# Architecture

Frostwall Beam is a **Tauri 2** desktop app: Rust backend (`src-tauri`) + React frontend (`src/`). Internet rendezvous lives in a separate **`mailbox/`** crate in the same Cargo workspace.

## Network paths

```
Same Wi‑Fi:   mDNS discovery  →  direct LAN TCP socket
Remote:       mailbox (code → EndpointId)  →  iroh QUIC (hole-punch, relay fallback)
                                                    ↓
                              SPAKE2 pairing → AEAD frames → Blake3 (unchanged)
```

| Component | Role |
|-----------|------|
| **mDNS** (`discovery.rs`) | Advertise / browse hosts on LAN; multi-host picker in UI |
| **Mailbox** (`mailbox/`) | In-memory map `code → iroh EndpointId`, ~10 min TTL; no file data |
| **iroh** (`internet.rs`) | QUIC dial by public key; direct path or relay fallback |
| **Transport** (`transport.rs`) | Length-delimited framing over any duplex byte stream |

## Backend modules (`src-tauri/src/`)

| Module | Responsibility |
|--------|----------------|
| `crypto.rs` | HKDF, XChaCha20-Poly1305, HMAC |
| `pairing.rs` | SPAKE2 + key-confirmation |
| `liveness.rs` | 30s rotating verification code |
| `discovery.rs` | mDNS advertise / browse |
| `internet.rs` | iroh endpoint + mailbox HTTP client |
| `transport.rs` | Framing over TCP or iroh duplex |
| `protocol.rs` | Manifest · Accept · Reject · Cancel · Chunk · FileEnd · Done |
| `transfer.rs` | Encrypt/decrypt, Blake3, path confinement |
| `session.rs` | Handshake orchestration |
| `config.rs` | Download dir, device name, mailbox URL |
| `commands.rs` | Tauri API + session coordinator |
| `mailbox_sidecar.rs` | Embedded localhost mailbox (dev / no remote URL) |

## Frontend (`src/`)

| File | Role |
|------|------|
| `App.tsx` | Pairing, transfer, settings, modals |
| `i18n.tsx` | Turkish / English strings |
| `errors.ts` | Backend error → localized message |
| `history.ts` | Local transfer log (last 50) |
| `theme.ts` | System / dark / light |

## Session coordinator

One encrypted session at a time per app instance:

- Pairing task owns accept/connect until handshake succeeds.
- Coordinator serializes send vs receive (`in_flight` gate).
- Incoming transfers require explicit user accept before disk write.
- Disconnect aborts pairing, cancels in-flight transfer, clears state.

## Mailbox HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Liveness (`ok`) |
| `POST` | `/register` | Host publishes `code`, `endpoint_id`, optional `device_name` → `token` |
| `GET` | `/lookup/{code}` | Joiner resolves `endpoint_id` |
| `DELETE` | `/register/{code}` | Host unregisters (requires `Authorization: Bearer {token}`) |

Rate limits and six-digit code validation are enforced server-side. See [Security](Security).
