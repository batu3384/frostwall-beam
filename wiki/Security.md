# Security

## Threat model (summary)

Frostwall Beam assumes:

- **Pairing code** is shared over an out-of-band channel (voice, message) and may be guessed if left active too long → bounded attempts, rotating liveness code, session timeout.
- **LAN adversary** may sniff or inject on the local network → control plane encrypted with session-derived `control_key`; payload chunks AEAD-encrypted.
- **Internet path** may include untrusted NAT, relay, or mailbox operator → mailbox sees only `code → EndpointId`; SPAKE2 + AEAD protect content; QUIC adds transport encryption.
- **Receiver** is the trust anchor for what gets written to disk → manifest review + explicit accept.

## Crypto stack

```
Pairing code (SPAKE2)  →  session keys (HKDF)  →  encrypted frames (AEAD)
                              ↓
                    rotating liveness code (human check)
                              ↓
              manifest validation  →  user approval  →  chunked transfer + Blake3
```

| Layer | Mechanism |
|-------|-----------|
| Pairing | SPAKE2 + ephemeral X25519, key-confirmation MAC |
| Payload | XChaCha20-Poly1305 per chunk |
| Control | AEAD-encrypted manifest / accept / reject / cancel |
| Integrity | Blake3 per file; atomic rename after verify |
| Forward secrecy | Fresh session keys each pairing |

## Trust boundaries

| Component | Sees | Does not see |
|-----------|------|----------------|
| Mailbox | `code`, `EndpointId`, optional device name, TTL | Files, keys, SPAKE2 material |
| iroh relay | Encrypted QUIC packets | Plaintext payloads |
| Host / joiner | Decrypted data after pairing | N/A |

**Transport is not trust** — LAN TCP and iroh QUIC use the same pairing and encryption above.

## Hardening (implemented)

- Wire protocol versioned; incompatible peers fail fast.
- Pairing codes: six digits; max failed handshakes before host aborts.
- Handshake reads bounded (`HANDSHAKE_TIMEOUT`, stall attempt limits).
- Mailbox: HTTPS required in release (localhost HTTP debug-only); register token for unregister; first register wins per code.
- Path hardening: traversal, symlinks, dangerous Unicode, system dirs rejected.
- Temp files use `.frostwallpart`; rename only after hash OK.
- Name collisions → `file (1).txt`, never silent overwrite.
- Config file: refuse symlinked config path (Unix).

## Reporting vulnerabilities

**Do not** open public issues for security bugs.

1. Open a [GitHub Security Advisory](https://github.com/batu3384/frostwall-beam/security/advisories/new) (preferred), or
2. Email the maintainer via GitHub profile contact if advisory is unavailable.

Include: affected version, reproduction steps, impact assessment. We aim to acknowledge within 7 days.

For general bugs (non-security), use [Issues](https://github.com/batu3384/frostwall-beam/issues).
