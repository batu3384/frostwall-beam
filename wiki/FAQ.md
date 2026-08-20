# FAQ

## General

**What is Frostwall Beam?**  
A desktop app for encrypted file transfer between two devices — same Wi‑Fi or remote (with a rendezvous server).

**Do I need an account?**  
No. Pairing uses a short code; no cloud login.

**What platforms are supported?**  
macOS and Windows. Linux is not a current target.

## Security

**Is it end-to-end encrypted?**  
Yes. SPAKE2 pairing derives session keys; every chunk is XChaCha20-Poly1305; files verified with Blake3.

**What is the rotating code for?**  
Human verification against MITM — both screens must show the same 6-digit liveness code.

**Can the mailbox read my files?**  
No. It only stores `pairing code → iroh EndpointId` briefly. File bytes never pass through it.

## Networking

**Same Wi‑Fi vs Remote?**  
Same Wi‑Fi uses mDNS + direct LAN socket. Remote uses a mailbox for discovery and `iroh` for NAT traversal.

**Why don't I see Remote mode?**  
The UI hides Remote until a real rendezvous URL exists (build-time `FROSTWALL_MAILBOX_URL` or user HTTPS config).

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
