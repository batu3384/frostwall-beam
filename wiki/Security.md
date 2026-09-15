# Security

## Threat model (summary)

Frostwall Beam assumes:

- **Pairing code** is shared over an out-of-band channel (voice, message) and may be guessed if left active too long → bounded failed-handshake attempts; after pairing, rotating liveness code (user confirm). Host waits until Cancel — invite is a bearer secret.
- **LAN adversary** may sniff or inject on the local network → control plane encrypted with session-derived `control_key`; payload chunks AEAD-encrypted.
- **Internet path** may include untrusted NAT, relay, or (optional) mailbox operator → mailbox sees `code → EndpointId` plus relay/IP location hints; the invite (iroh ticket + SPAKE2 digits, or legacy `fwb2`) is a bearer secret (EndpointId, SPAKE2 code, relay URLs, public IPs — loopback, RFC1918, CGNAT, IPv4-mapped private omitted); SPAKE2 + AEAD protect content; QUIC adds transport encryption.
- **Receiver** is the trust anchor for what gets written to disk → manifest review + explicit accept.

## Crypto stack

```
Pairing code (SPAKE2)  →  session keys (HKDF)  →  encrypted frames (AEAD)
                              ↓
                    rotating liveness code (user confirms match before send)
                              ↓
              manifest validation  →  user approval  →  chunked transfer + Blake3
```

| Layer | Mechanism |
|-------|-----------|
| Pairing | SPAKE2 + ephemeral X25519, key-confirmation MAC |
| Payload | XChaCha20-Poly1305 per chunk |
| Control | AEAD-encrypted manifest / accept / reject / cancel / hello |
| Integrity | Blake3 per file; `fsync` then atomic rename after verify |
| Forward secrecy | Fresh session keys each pairing |

## Trust boundaries

| Component | Sees | Does not see |
|-----------|------|----------------|
| Mailbox | `code`, `EndpointId`, optional device name, relay/IP hints, TTL | Files, keys, SPAKE2 material |
| iroh relay | Encrypted QUIC packets | Plaintext payloads |
| Host / joiner | Decrypted data after pairing | N/A |

**Transport is not trust** — LAN TCP and iroh QUIC use the same pairing and encryption above.

## Hardening (implemented)

- Wire protocol versioned; incompatible peers fail fast.
- Pairing codes: six digits; max failed handshakes before host aborts.
- After pairing, both sides show a rotating 6-digit verification code; send and incoming-file prompts stay blocked until the user confirms the codes match (mismatch disconnects).
- Handshake reads bounded (`HANDSHAKE_TIMEOUT`, stall attempt limits).
- Session teardown is epoch-scoped: a dying coordinator cannot `clear()` a newer host/join, cannot drop a newer transfer gate/cancel flag, and error/disconnect/transfer/notice events carry the same epoch the UI already filters.
- Mailbox: HTTPS required in release (localhost HTTP debug-only); register token for unregister and TTL refresh; first register wins per code; `EndpointId` must be 64 hex; loopback / RFC1918 / CGNAT IPs and loopback/private HTTPS relay URLs are not stored as dial hints; device names are capped like the invite (48 chars, no controls). Joiners sanitize mailbox lookup JSON the same way so a hostile mailbox cannot plant a huge/control device name or private relay URL. Client HTTP bodies are capped at 64 KiB even without `Content-Length` (chunked); the mailbox server uses the same request-body cap. The standalone binary binds `127.0.0.1` unless `MAILBOX_BIND` is an explicit IP (`0.0.0.0` behind TLS). Settings reject mailbox URLs with empty host, userinfo (`user:pass@`), or a debug HTTP prefix that is not exact loopback (`http://127.0.0.1.evil.com`).
- Path hardening: traversal, symlinks, Windows junctions, dangerous Unicode, system dirs rejected. Collect never follows symlinks or junctions; send re-opens with `O_NOFOLLOW` so a file swapped for a symlink after the walk cannot leak. Send paths must be UTF-8 (lossy names would collide on the Manifest). Receive mkdir/create uses `O_NOFOLLOW` so a symlink already inside the download dir cannot redirect a Manifest path outside it; that prefix is remapped beside the symlink (`leak (1)/…`). Windows directory junctions (`IO_REPARSE_TAG_MOUNT_POINT`) are treated like symlinks — Rust's `is_symlink()` misses them. The download directory itself is created component-wise (no `create_dir_all`) and any symlink in its path is rejected — `link/out` with `link → /etc` cannot become `/etc/out`. Windows system folders (`Windows`, `Program Files`, …) are refused on **any** volume, including the `\\?\` path `canonicalize` returns — not only `C:\WINDOWS`. Windows device names (`CON`, `NUL`, `COM1`, …) are rejected in every path component so a Manifest cannot open a device on a Windows receiver. Empty directories are mkdir’d from trailing-slash size-0 entries (not written as files). Malformed manifests are rejected in place; the session stays up and peer path strings are not shown in the UI. Control frames are capped at 8 MiB (`MAX_FRAME`); a Manifest that would not encode is rejected during prepare, not as a codec error mid-send.
- Temp files use `.frostwallpart`; `fsync` then rename only after hash OK. Stale `*.frostwallpart` leftovers from a crash are swept at the start of the next receive (bounded dest walk; symlinks/junctions skipped).
- Name collisions → `file (1).txt`, never silent overwrite. Promote uses `RENAME_EXCL` / `RENAME_NOREPLACE` so a name that appears after the unique-dest check cannot be clobbered. Dangling dest-dir symlinks count as occupied. If a Manifest needs a directory where a file or symlink already sits (`photos/a.txt` vs dest file `photos`), the incoming tree is remapped (`photos (1)/a.txt`) instead of failing or writing through the name.
- Config file: refuse a symlinked config path or parent (Unix); create the config dir without following links.

## Reporting vulnerabilities

**Do not** open public issues for security bugs.

1. Open a [GitHub Security Advisory](https://github.com/batu3384/frostwall-beam/security/advisories/new) (preferred), or
2. Email the maintainer via GitHub profile contact if advisory is unavailable.

Include: affected version, reproduction steps, impact assessment. We aim to acknowledge within 7 days.

For general bugs (non-security), use [Issues](https://github.com/batu3384/frostwall-beam/issues).
