# Troubleshooting

## Pairing

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Key confirmation failed | Wrong code or MITM | Re-check 6-digit code; compare rotating liveness on both devices |
| Codes mismatch / session dropped at verify | Different rotating codes (or MITM) | Confirm **codes match** only if both screens show the same 6 digits; mismatch disconnects — start a new session |
| Too many failed pairing attempts | Brute-force bound hit | Host: generate a new code |
| Handshake timed out | Network stall / firewall | Retry; check LAN or remote connectivity |
| No peer found on the LAN | Different network / mDNS blocked | Same Wi‑Fi; disable AP isolation; try again |
| No LAN interface found | No active interface | Connect to Wi‑Fi/Ethernet |

## Remote mode

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Invite not accepted | Typo / truncated paste | Copy the full invite; whitespace is ignored |
| Timed out starting internet endpoint | Bind / network | Retry; check firewall. Remote uses HTTPS to n0 relays (`*.relay.n0.iroh.link`) |
| Could not reach pairing server | Optional mailbox down | Use the invite instead; or check `GET /healthz` |
| Mailbox reachable from the LAN unexpectedly | Bind was `0.0.0.0` | Current default is `127.0.0.1`. Public deploy: `MAILBOX_BIND=0.0.0.0` behind TLS |
| No peer for this code | Mailbox lookup, host not registered | Host must start Remote first; or paste the invite |
| Could not reach peer | NAT / firewall / iroh relay | Retry; allow outbound **HTTPS 443** to n0. UDP/QUIC holepunch is optional — relayed path is websocket |
| Host drops while waiting | Old builds ended Remote host after 5 minutes, or after one failed joiner dial / stream pair | Current: host keeps the invite until **Cancel**. A failed join does not reset the host. Joiner retries. Optional mailbox TTL is refreshed while hosting; if refresh fails, paste the invite |
| Host shows relay warning | No home HTTPS relay yet | App keeps hunting ~25s after the first invite and rewrites it when a relay homes — copy again after the toast. A public IP (not RFC1918/CGNAT) may still work. If neither appears: DNS or HTTPS 443 to n0 blocked. |
| Two devices, two different NATs / ISPs | Field proof — CI cannot manufacture this | Two machines on two networks (phone hotspot vs home Wi‑Fi). Both pick **Remote**. Host: wait for relay toast, copy invite. Joiner: paste invite (not 6-digit mailbox). Confirm rotating codes, send one file. Outbound **HTTPS 443** to `*.relay.n0.iroh.link`. Loopback / same-LAN / `#[ignore]` n0 tests are not this proof. |

## Transfer

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Transfer rejected | Receiver declined | Sender: retry after accept. Session stays up |
| Integrity check failed | Corruption or tampering | Retry transfer; session stays connected. Verify stable network |
| Download directory errors | Symlink or system path | Settings → pick a normal folder |
| Transfer cancelled | User or disconnect | Re-send if session still connected. Cancel mid-transfer now keeps the encrypted session (old builds reset the receiver). |

## Build / dev

| Symptom | Fix |
|---------|-----|
| `cargo test` some iroh tests ignored | Expected — 4 network tests (`#[ignore]`): mDNS + 3 live n0 iroh. Default suite includes loopback + local-relay e2e. `host_and_join_via_n0_relay_only --ignored` is IPv4-only SPAKE2+file over n0 HTTPS relay (no IPv6 bind) |
| Clippy failures | `cargo clippy --workspace --all-targets -- -D warnings` locally before push |
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
