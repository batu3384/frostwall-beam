# FAQ

## General

**What is Frostwall Beam?**  
A desktop app for encrypted file transfer between two devices — same Wi‑Fi or remote (copy-paste invite; mailbox optional).

**Do I need an account?**  
No. Pairing uses a short code; no cloud login.

**What platforms are supported?**  
macOS and Windows. Linux is not a current target.

## Security

**Is it end-to-end encrypted?**  
Yes. SPAKE2 pairing derives session keys; every chunk is XChaCha20-Poly1305; files verified with Blake3.

**What is the rotating code for?**  
Human verification against MITM — both screens must show the same 6-digit liveness code. Confirm **codes match** before sending; a mismatch disconnects.

**Can the mailbox read my files?**  
No. It stores `pairing code → EndpointId` plus relay/IP location hints briefly. File bytes never pass through it.

## Networking

**Same Wi‑Fi vs Remote?**  
Same Wi‑Fi uses mDNS + direct LAN socket. Remote uses an iroh ticket invite (or optional mailbox) plus `iroh` for NAT traversal.

**Do I need a pairing server for Remote?**  
No. Copy the invite from the host and paste it on the joiner. A mailbox is optional so joiners can type six digits instead. If the host later says a relay was found, copy the invite again.

**How long does the host wait?**  
Until **Cancel**. A failed join does not drop the invite. Treat the invite as a secret. While the host waits, an optional pairing server entry is refreshed so the 6-digit code stays valid; if refresh fails, paste the invite.

**Do I need to open ports?**  
Same Wi‑Fi: usually no. Remote: outbound connectivity; `iroh` hole-punches when possible, else relay.

## Usage

**Where do downloads go?**  
Default: `~/Downloads/Frostwall Beam`. Change in Settings.

**Can I send folders?**  
Yes. Structure is preserved.

**Can I cancel mid-transfer?**  
Yes. Cancel keeps the encrypted session; disconnect ends it.

**Languages?**  
Turkish and English in Settings.

## Project

**License?**  
[MIT](https://github.com/batu3384/frostwall-beam/blob/main/LICENSE)

**How to contribute?**  
Issues and PRs welcome. Run `cargo test --workspace` and `pnpm build` before submitting.

**Roadmap?**  
See [Roadmap](Roadmap).
