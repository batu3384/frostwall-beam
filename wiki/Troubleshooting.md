# Troubleshooting

## Pairing

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Key confirmation failed | Wrong code or MITM | Re-check 6-digit code; compare rotating liveness on both devices |
| Too many failed pairing attempts | Brute-force bound hit | Host: generate a new code |
| Handshake timed out | Network stall / firewall | Retry; check LAN or remote connectivity |
| No peer found on the LAN | Different network / mDNS blocked | Same Wi‑Fi; disable AP isolation; try again |
| No LAN interface found | No active interface | Connect to Wi‑Fi/Ethernet |

## Remote mode

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Remote tab not visible | No rendezvous URL configured | Set `FROSTWALL_MAILBOX_URL` at build time or mailbox URL in config (HTTPS) |
| Remote pairing not available | Embedded mailbox only (localhost) | Deploy public mailbox; both devices need reachable rendezvous |
| Could not reach pairing server | Mailbox down / wrong URL / TLS | Verify `GET /healthz` returns `ok`; check URL and firewall |
| No peer for this code | Expired or host not registered | Host must start Remote session first; codes expire ~10 min |
| Could not reach peer | NAT / firewall / iroh relay | Retry; ensure outbound UDP/QUIC not blocked |

## Transfer

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Transfer rejected | Receiver declined | Sender: retry after accept |
| Integrity check failed | Corruption or tampering | Retry transfer; verify stable network |
| Download directory errors | Symlink or system path | Settings → pick a normal folder |
| Transfer cancelled | User or disconnect | Re-send if session still connected |

## Build / dev

| Symptom | Fix |
|---------|-----|
| `cargo test` network tests ignored | Expected — mDNS / iroh relay tests need real network (`#[ignore]`) |
| Clippy failures | `cargo clippy --workspace -- -D warnings` locally before push |
| Tauri build missing deps | Follow [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) |

## Logs

Run from terminal for Rust tracing:

```bash
RUST_LOG=info pnpm tauri dev
```

Mailbox service:

```bash
RUST_LOG=info cargo run -p frostwall-mailbox
```
