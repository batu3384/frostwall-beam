# Architecture

Frostwall Beam is a **Tauri 2** desktop app: Rust backend (`src-tauri`) + React frontend (`src/`). Internet rendezvous lives in a separate **`mailbox/`** crate in the same Cargo workspace.

## Network paths

```
Same Wi‑Fi:   mDNS discovery  →  direct LAN TCP socket (IPv4 or IPv6)
Remote:       iroh ticket invite or optional mailbox (code → EndpointId + dial hints)
                    → iroh QUIC (hole-punch, relay fallback)
                                                    ↓
                              SPAKE2 pairing → AEAD frames → Blake3 (unchanged)
```

| Component | Role |
|-----------|------|
| **mDNS** (`discovery.rs`) | Advertise / browse hosts on LAN (IPv4 preferred, IPv6-only LAN works); multi-host picker in UI |
| **Invite** (`internet.rs`) | iroh `EndpointTicket` + SPAKE2 digits + optional device name; loopback/private relay URLs omitted; legacy `fwb2` / `fwb1` still parse |
| **Mailbox** (`mailbox/`) | Optional self-hosted map `code → iroh EndpointId` + relay/IP hints, ~10 min TTL (host refreshes while waiting); no file data. App does not embed a localhost mailbox |
| **iroh** (`internet.rs`) | Dial by public key; hole-punch then n0 HTTPS websocket relay. OS `getaddrinfo` DNS (not Google UDP fallback). Default suite: loopback + local-relay e2e |
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
| `protocol.rs` | Manifest · Accept · Reject · Cancel · Chunk · FileEnd · Done · Hello |
| `transfer.rs` | Encrypt/decrypt, Blake3, path confinement (Windows device names, junctions, dest remaps) |
| `session.rs` | Handshake orchestration |
| `config.rs` | Download dir, device name, mailbox URL |
| `commands.rs` | Tauri API + session coordinator |

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

- Pairing task owns accept/connect until handshake succeeds. A Remote host invite may refresh once (mailbox token included) after a home HTTPS relay appears.
- Coordinator serializes send vs receive (`in_flight` gate). Folder expansion for send runs on a blocking thread and honors the cancel flag so a large tree cannot stall the session loop. That walk records each file size once (and rejects oversize trees before a Manifest goes on the wire). Empty directories are first-class: a trailing-slash, size-0 Manifest entry plus an empty `FileEnd` (no wire version bump). The Manifest is one AEAD control frame (`MAX_FRAME` 8 MiB) so 50 000 short paths fit; a list that would not encode is rejected during prepare, not as a codec error mid-send. It races the socket: a dropped peer ends the session immediately, and a Manifest from the other side is a send collision (session stays up). Simultaneous send from both peers fails locally (`peer started a transfer at the same time`); the encrypted session stays up. After Accept, a vanished or symlink-swapped file makes the sender emit `Cancel` so the receiver does not wait forever; send opens with `O_NOFOLLOW` and does not re-stat 50k files on the coordinator.
- Incoming transfers require explicit user accept before disk write (6-minute decision window: SAS confirm + file-list review, shown in the UI). The wait races the socket: a dropped peer or sender `Cancel` closes the prompt immediately instead of sitting on the timer. `in_flight` is held for that window so a local send cannot collide. A malformed manifest is rejected in place (no attacker path in the UI); the encrypted session stays up. The download directory is resolved at accept time (Settings can change mid-session) and is refused if it is a system path or contains a symlink. The UI lists a short name preview (`file_count` / total size stay exact) so a 50k-file manifest cannot freeze the webview. After the receiver Accepts, the sender emits a 0-byte progress tick so the card leaves “waiting for accept” even when the payload is empty directories or 0-byte files.
- After the TCP/QUIC pipe is up, the UI switches from invite/wait to “verifying the peer” for SPAKE2 + Hello so the host does not keep offering a copyable invite mid-handshake.
- Transfer abort (cancel, integrity fail, size mismatch, accept timeout) keeps the encrypted session; leftover Accept/Reject/Done/Hello/Cancel frames are ignored so a late reply cannot tear the session down. Only peer disconnect ends it. The UI surfaces a recoverable fail as a toast (`frostwall://notice`), not a session-end banner.
- After pairing, both sides exchange an encrypted device-name Hello. A dead pipe here fails pairing (no fake connected). Timeout / old peer without Hello still pairs, name stays empty. Then the UI blocks send until the user confirms the rotating verification codes match.
- Disconnect aborts pairing, cancels in-flight transfer, clears state. A `session_epoch` bump makes Cancel during iroh bind / mailbox register drop the leftover host instead of spawning a zombie session. Invite / paired / pairing / error / disconnect / transfer / notice / received events carry that epoch so a stale event cannot overwrite a new session. A dying coordinator `clear()`s only if it still owns that epoch, and must not touch a newer session’s `in_flight`, cancel flag, incoming-decision slot, or mailbox token. LAN `discover_peers` watches the same epoch so Cancel ends the 5s mDNS browse.

## Mailbox HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Liveness (`ok`) |
| `POST` | `/register` | Host publishes `code`, `endpoint_id`, optional `device_name`, `relays`, `ips` → `token` |
| `POST` | `/register/{code}/refresh` | Host extends TTL (`Authorization: Bearer {token}`) |
| `GET` | `/lookup/{code}` | Joiner resolves `endpoint_id` + dial hints |
| `DELETE` | `/register/{code}` | Host unregisters (requires `Authorization: Bearer {token}`) |

Rate limits and six-digit code validation are enforced server-side. See [Security](Security).
