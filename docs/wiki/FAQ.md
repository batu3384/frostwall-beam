# FAQ

## General

**What is Frostwall Beam?**

A desktop app for encrypted file transfer between two devices — on the same Wi‑Fi or remotely through a copy-paste invite. A mailbox is optional.

**Do I need an account?**

No. Pairing uses a short code; there is no cloud login.

**What platforms are supported?**

macOS and Windows. Linux is not a current supported desktop target.

## Security

**Is it end-to-end encrypted?**

Yes. SPAKE2 pairing derives session keys; every chunk uses XChaCha20-Poly1305; files are verified with Blake3.

**What is the rotating code for?**

It is the human verification backstop against man-in-the-middle attacks. Both screens must show the same six-digit code. Confirm **codes match** before sending; a mismatch disconnects.

**Can the mailbox read my files?**

No. It briefly stores `pairing code → EndpointId` plus relay/IP location hints. File bytes never pass through it. The pairing code is the SPAKE2 password, so a mailbox operator can observe that code while it is registered.

**Is six-digit Remote join as safe as pasting the invite?**

Prefer pasting the invite. Digit-only join asks the pairing server for an endpoint ID. A malicious server could return its own ID; SPAKE2 still requires the shared code, and the rotating verification code is the human backstop.

## Networking

**Same Wi‑Fi or Remote?**

Same Wi‑Fi uses mDNS and a direct LAN socket. Remote uses an iroh ticket invite, or the optional mailbox, plus `iroh` for NAT traversal.

**Do I need a pairing server for Remote?**

No. Copy the invite from the host and paste it on the joiner. A mailbox is optional so joiners can type six digits instead. If the host later reports that a relay was found, copy the invite again.

**How long does the host wait?**

Until **Cancel**. A failed join does not consume the invite. Treat the invite as a secret. While the host waits, an optional mailbox entry is refreshed so the six-digit code stays valid; if refresh fails, paste the invite.

**Do I need to open ports?**

Usually no. Same-network transfer uses the LAN directly. Remote transfer needs outbound connectivity; `iroh` hole-punches when possible and otherwise uses a relay.

## Usage

**Where do downloads go?**

By default, `~/Downloads/Frostwall Beam`. This can be changed in Settings.

**Can I send folders?**

Yes. Folder structure is preserved.

**Can I cancel mid-transfer?**

Yes. Cancel stops the transfer but keeps the encrypted session. Disconnect ends the session.

**Which languages are available?**

Turkish and English.

## Project

**What is the license?**

[MIT](https://github.com/batu3384/frostwall-beam/blob/main/LICENSE)

**How do I contribute?**

Fork the repository and open a pull request. Follow [CONTRIBUTING.md](https://github.com/batu3384/frostwall-beam/blob/main/CONTRIBUTING.md) and run the full verification commands before submitting.

**Where is the roadmap?**

See [Roadmap](Roadmap).
