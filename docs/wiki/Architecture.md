# Architecture

Frostwall Beam is a **Tauri 2** desktop application with a React frontend (`src/`) and a Rust backend (`src-tauri/`). Internet rendezvous is isolated in the optional `mailbox/` crate. Both Rust crates belong to the root Cargo workspace.

## Network paths

```text
Same network:       mDNS discovery → direct LAN TCP socket
Different networks: invite or optional mailbox → iroh QUIC
                                   ↓
              SPAKE2 pairing → AEAD frames → Blake3 verification
```

| Component | Responsibility |
|-----------|----------------|
| mDNS (`discovery.rs`) | Advertise and browse LAN hosts; supports multiple advertised peers |
| Invite (`internet.rs`) | Carries an iroh endpoint ticket, SPAKE2 digits, optional device name, relay URL, and shareable address hints |
| iroh (`internet.rs`) | Dials by endpoint public key, attempts NAT traversal, and falls back to an HTTPS relay |
| Mailbox (`mailbox/`) | Optional short-lived `code → EndpointId + dial hints` rendezvous service; never handles file data |
| Transport (`transport.rs`) | Length-delimited frames over either LAN TCP or an iroh duplex stream |

The cryptographic and transfer layers are identical on LAN and Remote paths. Transport selection does not change trust or encryption boundaries.

## Backend modules

| Module | Responsibility |
|--------|----------------|
| `crypto.rs` | HKDF, XChaCha20-Poly1305, HMAC |
| `pairing.rs` | SPAKE2 and key confirmation |
| `liveness.rs` | Rotating human-verification code |
| `discovery.rs` | mDNS advertise/browse |
| `internet.rs` | iroh endpoint, invites, mailbox client |
| `transport.rs` | Frame encoding and duplex I/O |
| `protocol.rs` | Manifest, Accept, Reject, Cancel, Chunk, FileEnd, Done, Hello |
| `transfer.rs` | File encryption/decryption, Blake3, path confinement, atomic commit |
| `session.rs` | Handshake orchestration |
| `config.rs` | Persisted settings |
| `commands.rs` | Tauri commands and session coordinator |

## Frontend modules

| File | Responsibility |
|------|----------------|
| `App.tsx` | Pairing, transfer, settings, and dialogs |
| `i18n.tsx` | Turkish and English strings |
| `errors.ts` | Backend error localization |
| `history.ts` | Local transfer history |
| `theme.ts` | System/dark/light theme preference |

## Session coordinator

One encrypted session is active per application instance.

### Pairing and session lifetime

- The pairing task owns accept/connect until the handshake completes.
- The UI enters a verification state as soon as the transport connects, so a host invite is not presented as if pairing were already complete.
- After SPAKE2, both sides exchange an encrypted Hello and compare the rotating verification code before sending is enabled.
- Disconnect aborts pending pairing, cancels active transfer work, unregisters mailbox state when present, and clears session state.
- A monotonically increasing session epoch prevents stale tasks or events from modifying a newer session.

### Send/receive serialization

- An atomic in-flight gate permits one transfer direction at a time.
- Simultaneous sends are reported as local collisions without tearing down the encrypted session.
- Folder expansion runs on a blocking thread, honors cancellation, and rejects oversized trees before a manifest is emitted.
- Empty directories are represented explicitly as trailing-slash, size-zero manifest entries.
- A manifest is sent as one encrypted control frame bounded by `MAX_FRAME` (8 MiB); oversized manifests fail during preparation.

### Receiver approval and failure behavior

- Incoming transfers require explicit receiver approval before payload data is written.
- Manifest review and verification-code confirmation share a bounded decision window.
- A malformed manifest is rejected without exposing attacker-controlled paths in the UI.
- Cancel, integrity failure, size mismatch, and accept timeout abort the transfer but preserve the encrypted session where possible.
- Only peer disconnect or explicit user disconnect ends the session.

## Filesystem pipeline

1. Sender expands files/folders without following symlinks or junctions.
2. Manifest entries are validated for count, size, path shape, duplicate names, and reserved device names.
3. Receiver validates the manifest again before accepting it.
4. File bytes are encrypted in chunks and verified with Blake3.
5. Data is written to `.frostwallpart` files, synchronized, then atomically renamed only after verification.
6. Name collisions are resolved as `file (1).txt`, `file (2).txt`, and so on; existing files are never silently overwritten.
7. Stale partial files are cleaned before later receives without following links or junctions.

## Mailbox HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Liveness check |
| `POST` | `/register` | Publish `code`, `endpoint_id`, optional `device_name`, `relays`, and `ips`; returns a bearer token |
| `POST` | `/register/{code}/refresh` | Extend TTL; requires `Authorization: Bearer <token>` |
| `GET` | `/lookup/{code}` | Resolve endpoint and dial hints for a joiner |
| `DELETE` | `/register/{code}` | Remove registration; requires the registration token |

The service validates six-digit codes, caps request bodies, rate-limits lookups, applies first-write-wins registration, and expires entries automatically. See [Security](Security) for trust boundaries and hardening details.
