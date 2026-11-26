# Security

This page describes the security model implemented by Frostwall Beam. For vulnerability disclosure, use the private process in [the repository security policy](https://github.com/batu3384/frostwall-beam/blob/main/SECURITY.md).

## Threat model

Frostwall Beam assumes the following adversaries and trust boundaries:

- A LAN adversary may observe or inject traffic on the local network.
- A Remote-path adversary may control NAT infrastructure, a relay, or the optional mailbox service.
- A malicious peer may send malformed manifests, paths, control frames, or corrupted payload bytes.
- The receiver is the final trust anchor for data written to disk.
- Pairing invites and six-digit codes are bearer secrets until the session is established or cancelled.

The mailbox is only a rendezvous convenience. It is not trusted with plaintext, payload bytes, session keys, or final transfer authority.

## Cryptographic design

```text
pairing code (SPAKE2)
        ↓
session keys (HKDF)
        ↓
AEAD control and payload frames (XChaCha20-Poly1305)
        ↓
rotating human-verification code + manifest approval
        ↓
chunked transfer + Blake3 integrity verification
```

| Layer | Mechanism |
|-------|-----------|
| Pairing | SPAKE2 with ephemeral X25519 and key-confirmation MAC |
| Payload confidentiality/integrity | XChaCha20-Poly1305 per chunk |
| Control-plane protection | AEAD-encrypted manifest, accept/reject, cancel, and hello frames |
| File integrity | Blake3 per file before atomic rename |
| Forward secrecy | Fresh keys for every pairing |
| Human verification | Rotating six-digit code confirmed before sending |

## Trust boundaries

| Component | Can observe | Cannot observe |
|-----------|-------------|----------------|
| Mailbox | Pairing code, endpoint ID, optional device name, relay/IP hints, TTL metadata | File bytes, plaintext control frames, session keys, handshake transcript |
| iroh relay | Encrypted QUIC traffic and network metadata | Plaintext payload or control frames |
| LAN peer/network | Encrypted frames and network metadata | Plaintext payload or control frames |
| Receiver endpoint | Approved plaintext after decryption | Not applicable |

Transport is not trust. LAN TCP and iroh QUIC use the same pairing, encryption, validation, and approval layers.

## Pairing and session hardening

- Six-digit pairing codes are validated strictly.
- Failed handshakes are bounded to reduce online guessing.
- Handshake reads use timeouts and stall limits.
- The rotating verification code must be confirmed before sending is enabled.
- Session teardown is epoch-scoped so stale tasks cannot clear or mutate a newer session.
- Leftover control frames after an aborted transfer are ignored instead of tearing down the session.
- Mailbox registration uses a one-time bearer token for refresh and unregister operations.
- First successful registration wins for a code; a later registrant cannot overwrite it.
- Release builds require HTTPS mailbox URLs, with plain HTTP accepted only for exact loopback development addresses.
- Mailbox endpoints validate endpoint IDs, cap names and request bodies, reject private or loopback dial hints, and rate-limit lookups.

## Filesystem hardening

- Manifest paths reject traversal, absolute paths, backslashes, NUL bytes, dangerous Unicode, and Windows device names.
- Symlinks and Windows junctions are never followed during collection or receive-side creation.
- Sender-side files are reopened with no-follow semantics so a post-scan symlink swap cannot redirect reads.
- Receive-side directories and files are created with no-follow semantics; unsafe prefixes are remapped instead of written through.
- Download directories containing links or system locations are rejected.
- Windows system directories are rejected across volumes and canonical path forms.
- Manifest count, total size, path length, control-frame size, and duplicate entries are capped.
- Malformed manifests are rejected before disk writes begin.

## Integrity and overwrite protection

- Payload chunks are AEAD-protected.
- Each file is verified with Blake3 before commit.
- Partial files use the `.frostwallpart` suffix, are synchronized, and are atomically renamed only after verification.
- Crash leftovers are swept before later receives without following links or junctions.
- Existing files are never silently overwritten; collisions become `file (1).txt`, `file (2).txt`, and so on.
- Rename operations use no-replace semantics so a race cannot clobber a file created after the collision check.
- Directory/file conflicts are remapped to a safe sibling name instead of writing through an attacker-controlled path.

## Configuration hardening

- Configuration paths and parents that are symlinks are rejected where the platform permits detection.
- Configuration directories are created without following links.
- Mailbox URLs with userinfo, empty hosts, or deceptive loopback prefixes are rejected.

## Operational guidance

- Prefer copy-paste invites over digit-only mailbox lookup when possible.
- Treat invites and pairing codes as secrets and cancel waiting sessions when they are no longer needed.
- Put a public mailbox behind TLS and keep its bind address explicit.
- Confirm the rotating verification code on both devices before every first send.
- Keep both endpoints on current builds; incompatible protocol versions fail closed.

## Reporting vulnerabilities

Do **not** open public issues for security bugs. Use a [private GitHub Security Advisory](https://github.com/batu3384/frostwall-beam/security/advisories/new) and include the affected version, reproduction steps, and impact assessment. The maintainer aims to acknowledge reports within 7 days.
