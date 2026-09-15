//! Internet transport: NAT-traversing P2P connections via `iroh` (QUIC,
//! hole-punching, relay fallback). The default Remote path is a shareable
//! iroh `EndpointTicket` plus the SPAKE2 digits. An optional mailbox can
//! still map a 6-digit code to an `EndpointId` when you want joiners to type
//! digits instead of pasting.
//!
//! # Wire model
//!
//! Each side opens one outbound iroh uni-directional stream and accepts one
//! inbound uni-directional stream; joined together (`tokio::io::join`) they
//! form the same duplex byte pipe [`transport::Connection`] expects. This
//! deliberately avoids a single bi-directional stream: iroh only makes the
//! *receiver* aware of a stream once the sender writes to it, and our
//! handshake (`session::host_handshake`/`joiner_handshake`) has the host
//! speak first while the joiner reads first — two independent uni streams
//! let each direction proceed without waiting on the other. After `open_uni`
//! each side writes a one-byte preamble so the peer's `accept_uni` can
//! return; without that write both sides wait forever.
//!
//! Everything above this layer (SPAKE2 pairing, AEAD encryption, Blake3
//! integrity, manifest validation) is unchanged: `session.rs`/`transfer.rs`
//! only ever call `Connection::send`/`recv` and have no idea whether the
//! bytes travelled over LAN TCP or an iroh relay.
//!
//! # Invite (default Remote path)
//!
//! Host shares `endpoint…-<6 digits>` — official iroh `EndpointTicket`
//! (id + shareable relay/IP hints) plus the SPAKE2 secret, optional
//! `-hex(name)`. Loopback, RFC1918, CGNAT omitted. Legacy `fwb2-` / `fwb1-`
//! still parse.
//!
//! # Mailbox (optional)
//!
//! The mailbox (see the sibling `mailbox` crate) stores
//! `code -> EndpointId` plus relay/IP dial hints for a few minutes so a joiner
//! can type six digits instead of pasting the invite. It never sees file
//! contents, encryption keys, or the SPAKE2 handshake itself.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver};
use iroh::endpoint::presets;
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{
    Endpoint, EndpointAddr, NetReportConfig, PublicKey, RelayConfig, RelayMap, RelayMode, RelayUrl,
};
use iroh_tickets::endpoint::EndpointTicket;
use iroh_tickets::Ticket;
use serde::{Deserialize, Serialize};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::protocol;
use crate::transport::Connection;

/// QUIC ALPN identifying the Frostwall Beam wire protocol.
pub const ALPN: &[u8] = b"frostwall-beam/1";
/// Compact invite length cap — keep in lockstep with `src/invite.ts` `INVITE_MAX`.
pub const INVITE_MAX: usize = 1024;
/// Raw paste cap (chat wrapping, trailing newline). Compact form still
/// `INVITE_MAX`. Lockstep `src/invite.ts` `INVITE_PASTE_MAX`.
pub const INVITE_PASTE_MAX: usize = INVITE_MAX * 4;
/// How many HTTPS relay URLs to embed in a shareable invite.
const MAX_INVITE_RELAYS: usize = 3;
/// How many shareable socket addrs to embed in a shareable invite.
const MAX_INVITE_IPS: usize = 6;
/// How long to wait for the local iroh endpoint to come up (reach a home
/// relay) before giving up. On a network that blocks outbound UDP/QUIC this
/// would otherwise hang indefinitely instead of failing with a clear error.
const BIND_TIMEOUT: Duration = Duration::from_secs(20);
/// How long to wait for a home relay after bind. Best-effort: after this we
/// still emit whatever addrs we have (direct IPs), but we do not bail early.
const RELAY_WAIT: Duration = Duration::from_secs(8);
/// How long one host `accept` wait lasts before the pairing loop retries.
/// The Remote host stays up until the user cancels — a single 5-minute
/// slice must not kill the invite (sharing it via chat often takes longer).
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// How long the joiner waits for the peer connection itself to establish
/// (direct or relayed) before giving up. Each of two dial attempts gets this
/// full window so slow NAT hole-punch is not aborted at 15s.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the joiner polls the mailbox for the host's address before
/// giving up (covers the host/joiner registering in either order).
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(20);
/// Delay between mailbox lookup polls.
const LOOKUP_POLL_INTERVAL: Duration = Duration::from_millis(700);
/// Bound each mailbox HTTP call so a hung pairing server cannot stall host/join.
const MAILBOX_HTTP_TIMEOUT: Duration = Duration::from_secs(8);
/// Lookup/register JSON is a handful of hints. A hostile mailbox must not
/// stream megabytes into the joiner.
const MAILBOX_BODY_MAX: usize = 64 * 1024;
/// How long to wait for both uni-directional streams to pair up after the
/// QUIC connection itself is established. A connection can succeed (handshake
/// complete) while the path is too lossy/asymmetric for streams to actually
/// open — without this, `open_uni`/`accept_uni` could hang forever instead of
/// surfacing a clear error.
const STREAM_PAIR_TIMEOUT: Duration = Duration::from_secs(30);
/// First byte on each uni stream. iroh does not surface a stream to the
/// peer until the sender writes; both sides wait on `accept_uni`, so this
/// kick must happen before that wait or the data channel deadlocks.
const STREAM_KICK: u8 = 0x01;

/// Hickory's system-conf parse bails on scoped IPv6 (`fe80::1%en0` in
/// macOS `/etc/resolv.conf`) and then falls back to Google UDP `8.8.8.8`,
/// which many networks drop. libc `getaddrinfo` still works. iroh HTTPS
/// `/ping` and `/relay` websocket never fire without a working resolver.
#[derive(Debug, Clone, Copy)]
struct OsDns;

fn frostwall_dns() -> DnsResolver {
    DnsResolver::custom(OsDns)
}

fn dns_host(host: &str) -> &str {
    host.trim_end_matches('.')
}

async fn os_lookup<T: Send + 'static>(
    host: &str,
    pick: fn(IpAddr) -> Option<T>,
) -> Result<BoxIter<T>, DnsError> {
    let host = dns_host(host);
    let addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|_| DnsError::NoResponse {
            meta: Default::default(),
        })?;
    let found: Vec<T> = addrs.filter_map(|sa| pick(sa.ip())).collect();
    if found.is_empty() {
        return Err(DnsError::NoResponse {
            meta: Default::default(),
        });
    }
    Ok(Box::new(found.into_iter()))
}

impl Resolver for OsDns {
    fn lookup_ipv4(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = Result<BoxIter<Ipv4Addr>, DnsError>> + Send>> {
        Box::pin(async move {
            os_lookup(&host, |ip| match ip {
                IpAddr::V4(v) => Some(v),
                _ => None,
            })
            .await
        })
    }

    fn lookup_ipv6(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = Result<BoxIter<Ipv6Addr>, DnsError>> + Send>> {
        Box::pin(async move {
            os_lookup(&host, |ip| match ip {
                IpAddr::V6(v) => Some(v),
                _ => None,
            })
            .await
        })
    }

    fn lookup_txt(
        &self,
        _host: String,
    ) -> Pin<Box<dyn Future<Output = Result<BoxIter<iroh::dns::TxtRecordData>, DnsError>> + Send>>
    {
        // getaddrinfo has no TXT. fwb2 / mailbox carry dial hints; `_iroh` TXT
        // discovery stays best-effort via n0 pkarr HTTP once A/AAAA work.
        Box::pin(async { Ok(Box::new(std::iter::empty()) as BoxIter<_>) })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(OsDns)
    }
}

/// n0 production relays, HTTPS websocket only. QUIC address-discovery (UDP
/// 7842) is skipped so Remote still works on networks that allow HTTPS but
/// drop outbound QUIC — the data plane uses `/relay` websocket either way.
fn n0_https_relay_map() -> RelayMap {
    let src = iroh::defaults::prod::default_relay_map();
    let dst = RelayMap::empty();
    for cfg in src.relays::<Vec<_>>() {
        dst.insert(
            cfg.url.clone(),
            std::sync::Arc::new(RelayConfig::new(cfg.url.clone(), None)),
        );
    }
    dst
}

fn frostwall_net_report() -> NetReportConfig {
    let mut cfg = NetReportConfig::default();
    // n0 `/generate_204` is 404. The HTTP captive-portal probe would only delay
    // picking a home relay; HTTPS `/ping` already proves the network is open.
    cfg.captive_portal_check = false;
    cfg
}

fn frostwall_endpoint_builder() -> iroh::endpoint::Builder {
    Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Custom(n0_https_relay_map()))
        .net_report_config(frostwall_net_report())
        .dns_resolver(frostwall_dns())
        .alpns(vec![ALPN.to_vec()])
}

/// This endpoint's dialable identifier, to publish via the mailbox or invite.
pub fn endpoint_id_string(ep: &Endpoint) -> String {
    ep.id().to_string()
}

/// Parsed Remote invite. Tickets and `fwb2` carry relay/IP hints; `fwb1` is id-only.
pub struct ParsedInvite {
    pub endpoint_id: String,
    pub code: String,
    pub device_name: Option<String>,
    relays: Vec<String>,
    ips: Vec<String>,
}

impl ParsedInvite {
    pub fn id_only(endpoint_id: String, code: String) -> Self {
        Self {
            endpoint_id,
            code,
            device_name: None,
            relays: Vec::new(),
            ips: Vec::new(),
        }
    }

    /// Mailbox lookup: EndpointId plus optional relay/IP hints (no SPAKE2 in mailbox).
    pub fn from_mailbox(
        endpoint_id: String,
        code: String,
        relays: Vec<String>,
        ips: Vec<String>,
    ) -> Self {
        Self {
            endpoint_id,
            code,
            device_name: None,
            relays: retain_shareable_relays(relays),
            ips: retain_shareable_ips(ips),
        }
    }

    /// Local-relay tests: iroh's test server is loopback HTTPS, which
    /// [`retain_shareable_relays`] correctly omits from a real invite.
    #[cfg(test)]
    fn with_test_dial_hints(
        endpoint_id: String,
        code: String,
        relays: Vec<String>,
        ips: Vec<String>,
    ) -> Self {
        Self {
            endpoint_id,
            code,
            device_name: None,
            relays,
            ips,
        }
    }

    /// True when the invite already carries a relay URL or direct IP so the
    /// joiner can dial without waiting on n0 discovery.
    pub fn has_dial_hints(&self) -> bool {
        !self.relays.is_empty() || !self.ips.is_empty()
    }

    /// Build an iroh address: id plus any embedded relay/direct paths.
    /// Invalid or non-shareable hints are skipped so a mailbox typo cannot
    /// void a still-usable relay URL.
    pub fn endpoint_addr(&self) -> Result<EndpointAddr> {
        let pk: PublicKey = self
            .endpoint_id
            .parse()
            .map_err(|_| anyhow!("invalid peer address"))?;
        let mut addr = EndpointAddr::new(pk);
        for r in &self.relays {
            if let Ok(url) = r.parse::<RelayUrl>() {
                addr = addr.with_relay_url(url);
            }
        }
        for i in &self.ips {
            if let Ok(sa) = i.parse::<SocketAddr>() {
                if shareable_socket(&sa) {
                    addr = addr.with_ip_addr(sa);
                }
            }
        }
        Ok(addr)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct InviteNet {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    r: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    i: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    n: Option<String>,
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("not a Frostwall invite"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("not a Frostwall invite"))
        })
        .collect()
}

/// Addresses safe to put in a shareable Remote invite. Loopback would make a
/// remote joiner dial *their* localhost. RFC1918 / CGNAT / link-local would
/// make them dial a host on *their* LAN or a non-routable carrier NAT.
/// Same-Wi-Fi pairing uses LAN mode, not this list.
fn ipv4_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 0x40
}

fn shareable_v4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_private()
        && !ipv4_cgnat(ip)
        && !ip.is_broadcast()
}

fn shareable_socket(sa: &SocketAddr) -> bool {
    match sa.ip() {
        IpAddr::V4(ip) => shareable_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return shareable_v4(v4);
            }
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_unique_local()
        }
    }
}

fn retain_shareable_relays(raw: Vec<String>) -> Vec<String> {
    raw.into_iter()
        .filter(|r| {
            r.parse::<RelayUrl>().is_ok()
                && r.to_ascii_lowercase().starts_with("https://")
                && https_url_host(r).is_some_and(relay_host_shareable)
        })
        .take(MAX_INVITE_RELAYS)
        .collect()
}

/// Host of an `https://` URL. Rejects userinfo (`user@host`) so a hint cannot
/// smuggle credentials. Used so loopback/private relay URLs never go on the wire.
fn https_url_host(s: &str) -> Option<&str> {
    if s.len() < 8 || !s.is_char_boundary(8) || !s[..8].eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &s[8..];
    if rest.is_empty() || rest.contains('@') {
        return None;
    }
    let auth = rest.split('/').next().unwrap_or("");
    if auth.is_empty() {
        return None;
    }
    if let Some(inner) = auth.strip_prefix('[') {
        return inner.split(']').next().filter(|h| !h.is_empty());
    }
    Some(auth.split(':').next().unwrap_or("")).filter(|h| !h.is_empty())
}

fn relay_host_shareable(host: &str) -> bool {
    // iroh encourages FQDN trailing dots (`https://use1-1.relay.n0.iroh.link.`).
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return shareable_socket(&SocketAddr::new(ip, 443));
    }
    host.contains('.') && !host.starts_with('.')
}

fn retain_shareable_ips(raw: Vec<String>) -> Vec<String> {
    raw.into_iter()
        .filter_map(|i| {
            let sa: SocketAddr = i.parse().ok()?;
            shareable_socket(&sa).then(|| sa.to_string())
        })
        .take(MAX_INVITE_IPS)
        .collect()
}

fn merged_shareable_addr(ep: &Endpoint) -> EndpointAddr {
    let mut addr = ep.addr();
    for sa in ep.bound_sockets() {
        if !shareable_socket(&sa) {
            continue;
        }
        addr = addr.with_ip_addr(sa);
    }
    addr
}

/// Relay URLs and shareable IPs for an invite or mailbox registration.
pub fn shareable_hints(ep: &Endpoint) -> (Vec<String>, Vec<String>) {
    let addr = merged_shareable_addr(ep);
    (
        retain_shareable_relays(addr.relay_urls().map(|u| u.to_string()).collect()),
        addr.ip_addrs()
            .filter(|a| shareable_socket(a))
            .map(|a| a.to_string())
            .take(MAX_INVITE_IPS)
            .collect(),
    )
}

/// Compact shareable invite: official iroh `EndpointTicket` plus SPAKE2
/// digits (and optional device name). Falls back to legacy `fwb2`/`fwb1`
/// only if the ticket exceeds [`INVITE_MAX`].
///
/// Merges `bound_sockets()` into `addr()` so a just-bound socket is in the
/// invite even before magicsock publishes it. Loopback, RFC1918, and CGNAT
/// are omitted.
pub fn make_invite(ep: &Endpoint, code: &str) -> String {
    make_invite_named(ep, code, None)
}

pub fn make_invite_named(ep: &Endpoint, code: &str, name: Option<&str>) -> String {
    make_invite_from_addr_named(&merged_shareable_addr(ep), code, name)
}

pub fn make_invite_from_addr(addr: &EndpointAddr, code: &str) -> String {
    make_invite_from_addr_named(addr, code, None)
}

fn shareable_endpoint_addr(addr: &EndpointAddr) -> EndpointAddr {
    let mut out = EndpointAddr::new(addr.id);
    for r in retain_shareable_relays(addr.relay_urls().map(|u| u.to_string()).collect()) {
        if let Ok(url) = r.parse::<RelayUrl>() {
            out = out.with_relay_url(url);
        }
    }
    for sa in addr
        .ip_addrs()
        .filter(|a| shareable_socket(a))
        .copied()
        .take(MAX_INVITE_IPS)
    {
        out = out.with_ip_addr(sa);
    }
    out
}

fn parsed_from_endpoint_addr(
    addr: EndpointAddr,
    code: String,
    device_name: Option<String>,
) -> ParsedInvite {
    ParsedInvite {
        endpoint_id: addr.id.to_string(),
        code,
        device_name,
        relays: retain_shareable_relays(addr.relay_urls().map(|u| u.to_string()).collect()),
        ips: retain_shareable_ips(addr.ip_addrs().map(|a| a.to_string()).collect()),
    }
}

fn encode_ticket_invite(addr: &EndpointAddr, code: &str, name: Option<&str>) -> Option<String> {
    let encoded = EndpointTicket::new(addr.clone()).encode_string();
    let mut with_name = format!("{encoded}-{code}");
    if let Some(n) = name {
        with_name.push('-');
        with_name.push_str(&to_hex(n.as_bytes()));
        if with_name.len() <= INVITE_MAX {
            return Some(with_name);
        }
    } else if with_name.len() <= INVITE_MAX {
        return Some(with_name);
    }
    let stripped = format!("{encoded}-{code}");
    (stripped.len() <= INVITE_MAX).then_some(stripped)
}

fn make_legacy_invite(addr: &EndpointAddr, code: &str, name: Option<&str>) -> String {
    let id = addr.id.to_string();
    let net = InviteNet {
        r: retain_shareable_relays(addr.relay_urls().map(|u| u.to_string()).collect()),
        i: addr
            .ip_addrs()
            .filter(|a| shareable_socket(a))
            .map(|a| a.to_string())
            .take(MAX_INVITE_IPS)
            .collect(),
        n: name.map(str::to_string),
    };
    if net.r.is_empty() && net.i.is_empty() {
        return format!("fwb1-{id}-{code}");
    }
    match serde_json::to_vec(&net) {
        Ok(bytes) => format!("fwb2-{id}-{code}-{}", to_hex(&bytes)),
        Err(_) => format!("fwb1-{id}-{code}"),
    }
}

fn make_invite_from_addr_named(addr: &EndpointAddr, code: &str, name: Option<&str>) -> String {
    let share = shareable_endpoint_addr(addr);
    let name = protocol::sanitize_display_name(name);
    encode_ticket_invite(&share, code, name.as_deref())
        .unwrap_or_else(|| make_legacy_invite(&share, code, name.as_deref()))
}

/// Chat paste: keep ticket alphabet, drop ZWSP / quotes / punctuation.
fn compact_invite(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase()
}

fn invite_window(s: &str) -> &str {
    if s.len() > INVITE_MAX {
        &s[..INVITE_MAX]
    } else {
        s
    }
}

fn parse_endpoint_invite(s: &str) -> Result<ParsedInvite> {
    let (ticket_s, rest) = s
        .split_once('-')
        .ok_or_else(|| anyhow!("invite pairing code must be 6 digits"))?;
    let ticket = EndpointTicket::decode_string(ticket_s)
        .map_err(|_| anyhow!("not a Frostwall invite"))?;
    if rest.len() < 6 || !rest[..6].chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("invite pairing code must be 6 digits"));
    }
    let code = rest[..6].to_string();
    let device_name = rest[6..].strip_prefix('-').and_then(|h| {
        let hex: String = h.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if hex.is_empty() {
            return None;
        }
        from_hex(&hex)
            .ok()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().map(str::to_string))
            .and_then(|raw| protocol::sanitize_display_name(Some(&raw)))
    });
    Ok(parsed_from_endpoint_addr(
        ticket.endpoint_addr().clone(),
        code,
        device_name,
    ))
}

fn parse_fwb2_invite(s: &str) -> Result<ParsedInvite> {
    let rest = s
        .strip_prefix("fwb2-")
        .ok_or_else(|| anyhow!("not a Frostwall invite"))?;
    if rest.len() < 64 + 1 + 6 + 1 {
        return Err(anyhow!("not a Frostwall invite"));
    }
    let id = &rest[..64];
    if !id.chars().all(|c| c.is_ascii_hexdigit()) || rest.as_bytes()[64] != b'-' {
        return Err(anyhow!("not a Frostwall invite"));
    }
    let code = &rest[65..71];
    if code.len() != 6
        || !code.chars().all(|c| c.is_ascii_digit())
        || rest.as_bytes().get(71) != Some(&b'-')
    {
        return Err(anyhow!("invite pairing code must be 6 digits"));
    }
    let payload: String = rest[72..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    let bytes = from_hex(&payload)?;
    let net: InviteNet =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("not a Frostwall invite"))?;
    Ok(ParsedInvite {
        endpoint_id: id.to_string(),
        code: code.to_string(),
        device_name: protocol::sanitize_display_name(net.n.as_deref()),
        relays: retain_shareable_relays(net.r),
        ips: retain_shareable_ips(net.i),
    })
}

fn parse_fwb1_invite(s: &str) -> Result<ParsedInvite> {
    let rest = s
        .strip_prefix("fwb1-")
        .ok_or_else(|| anyhow!("not a Frostwall invite"))?;
    if rest.len() < 64 + 1 + 6 {
        return Err(anyhow!("not a Frostwall invite"));
    }
    let id = &rest[..64];
    if !id.chars().all(|c| c.is_ascii_hexdigit()) || rest.as_bytes()[64] != b'-' {
        return Err(anyhow!("not a Frostwall invite"));
    }
    let code = &rest[65..71];
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("invite pairing code must be 6 digits"));
    }
    Ok(ParsedInvite {
        endpoint_id: id.to_string(),
        code: code.to_string(),
        device_name: None,
        relays: Vec::new(),
        ips: Vec::new(),
    })
}

fn try_each_prefix(s: &str, needle: &str, parse: fn(&str) -> Result<ParsedInvite>) -> Result<ParsedInvite> {
    let mut from = 0;
    let mut last = anyhow!("not a Frostwall invite");
    while let Some(rel) = s[from..].find(needle) {
        let at = from + rel;
        match parse(invite_window(&s[at..])) {
            Ok(p) => return Ok(p),
            Err(e) => last = e,
        }
        from = at + 1;
    }
    Err(last)
}

/// True when paste looks like a Remote invite (not a 6-digit mailbox code).
pub fn looks_like_remote_invite(input: &str) -> bool {
    let s = compact_invite(input);
    let mut from = 0;
    while let Some(rel) = s[from..].find("endpoint") {
        let at = from + rel;
        let rest = &s[at + "endpoint".len()..];
        let body = rest.chars().take_while(|c| c.is_ascii_alphanumeric()).count();
        if body > 0 {
            let after = &rest[body..];
            if after.len() >= 7
                && after.as_bytes()[0] == b'-'
                && after[1..7].chars().all(|c| c.is_ascii_digit())
            {
                return true;
            }
        }
        from = at + 1;
    }
    looks_like_fwb2(&s) || looks_like_fwb1(&s)
}

fn looks_like_fwb2(s: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = s[from..].find("fwb2-") {
        let at = from + rel;
        let rest = &s[at + 5..];
        if rest.len() > 64 + 1 + 6
            && rest.as_bytes()[64] == b'-'
            && rest.as_bytes().get(71) == Some(&b'-')
            && rest[..64].chars().all(|c| c.is_ascii_hexdigit())
            && rest[65..71].chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
        from = at + 1;
    }
    false
}

fn looks_like_fwb1(s: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = s[from..].find("fwb1-") {
        let at = from + rel;
        let rest = &s[at + 5..];
        if rest.len() >= 64 + 1 + 6
            && rest.as_bytes()[64] == b'-'
            && rest[..64].chars().all(|c| c.is_ascii_hexdigit())
            && rest[65..71].chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Parse an invite, or reject. Chat wrapping (quotes, ZWSP, surrounding
/// words) is stripped / scanned. Accepts iroh `endpoint…-<code>` tickets,
/// plus legacy `fwb1` / `fwb2`.
pub fn parse_invite(input: &str) -> Result<ParsedInvite> {
    if input.len() > INVITE_PASTE_MAX {
        return Err(anyhow!("not a Frostwall invite"));
    }
    let s = compact_invite(input);
    if s.is_empty() {
        return Err(anyhow!("not a Frostwall invite"));
    }
    if let Ok(p) = try_each_prefix(&s, "endpoint", parse_endpoint_invite) {
        return Ok(p);
    }
    if let Ok(p) = try_each_prefix(&s, "fwb2-", parse_fwb2_invite) {
        return Ok(p);
    }
    try_each_prefix(&s, "fwb1-", parse_fwb1_invite)
}

async fn wait_dialable(ep: &Endpoint) {
    let _ = tokio::time::timeout(RELAY_WAIT, ep.online()).await;
}

/// Keep waiting after [`wait_dialable`] until a shareable HTTPS relay URL
/// appears, or `limit` elapses. Used to refresh a host invite that went out
/// before the endpoint finished homing.
pub async fn wait_for_shareable_relay(ep: &Endpoint, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if !shareable_hints(ep).0.is_empty() {
            return true;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        // Poll addr updates. `online()` may already have fired during bind
        // and not signal again when the home relay URL appears.
        let slice = (deadline - now).min(Duration::from_millis(400));
        tokio::time::sleep(slice).await;
    }
}

/// Start an iroh endpoint that can accept inbound Frostwall connections
/// (host side).
pub async fn host_endpoint() -> Result<Endpoint> {
    let bind = frostwall_endpoint_builder().bind();
    let ep = tokio::time::timeout(BIND_TIMEOUT, bind)
        .await
        .map_err(|_| anyhow!("timed out starting the internet endpoint (check your network/firewall)"))?
        .map_err(|e| anyhow!("failed to start internet endpoint: {e}"))?;
    wait_dialable(&ep).await;
    Ok(ep)
}

/// Start an iroh endpoint for outbound-only use (joiner side).
/// Does not wait for a home relay: tickets / `fwb2` already carry dial addrs.
/// Discovery-only (`fwb1` / mailbox) waits inside [`connect_to`].
pub async fn join_endpoint() -> Result<Endpoint> {
    let bind = frostwall_endpoint_builder().bind();
    tokio::time::timeout(BIND_TIMEOUT, bind)
        .await
        .map_err(|_| anyhow!("timed out starting the internet endpoint (check your network/firewall)"))?
        .map_err(|e| anyhow!("failed to start internet endpoint: {e}"))
}

/// Accept exactly one inbound connection and wrap it as a [`Connection`].
pub async fn accept_one(ep: &Endpoint) -> Result<Connection> {
    let incoming = tokio::time::timeout(ACCEPT_TIMEOUT, ep.accept())
        .await
        .map_err(|_| anyhow!("timed out waiting for an internet connection"))?
        .ok_or_else(|| anyhow!("internet endpoint closed before a peer connected"))?;
    let conn = incoming
        .await
        .map_err(|e| anyhow!("incoming connection failed: {e}"))?;
    pair_streams(ep, conn).await
}

pub fn accept_wait_timed_out(err: &anyhow::Error) -> bool {
    err.to_string()
        .contains("timed out waiting for an internet connection")
}

/// Transient host-accept failures. The invite stays up: a failed joiner dial,
/// STREAM_KICK mismatch, or 30s stream-pair timeout must not `EV_ERROR` the
/// Remote host. Endpoint close is fatal.
pub fn accept_retryable(err: &anyhow::Error) -> bool {
    if accept_wait_timed_out(err) {
        return true;
    }
    let m = err.to_string();
    m.contains("incoming connection failed")
        || m.contains("timed out establishing the data channel")
        || m.contains("open outgoing stream")
        || m.contains("accept incoming stream")
        || m.contains("could not reach peer")
}

/// Dial a peer using a parsed invite (id + optional relay/direct addrs).
/// Always waits briefly for a home relay: the joiner must be relay-reachable
/// to use the host's relay URL even when the invite already carries hints.
pub async fn connect_to(ep: &Endpoint, invite: &ParsedInvite) -> Result<Connection> {
    wait_dialable(ep).await;
    connect_addr(ep, invite.endpoint_addr()?).await
}

/// Dial a peer by `EndpointAddr` (tests / mailbox id-only path).
pub async fn connect_addr(ep: &Endpoint, addr: EndpointAddr) -> Result<Connection> {
    let mut last = None;
    for attempt in 0..2 {
        // Full CONNECT_TIMEOUT each try. Splitting the budget aborted
        // in-flight hole-punch / relay connect on slow NATs.
        match tokio::time::timeout(CONNECT_TIMEOUT, ep.connect(addr.clone(), ALPN)).await {
            Ok(Ok(conn)) => return pair_streams(ep, conn).await,
            Ok(Err(e)) => last = Some(anyhow!("could not reach peer: {e}")),
            Err(_) => last = Some(anyhow!("timed out connecting to the peer")),
        }
        if attempt == 0 {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("could not reach peer")))
}

/// Open our outbound stream and accept the peer's, joining them into one
/// duplex pipe. `open_uni` is local; `accept_uni` waits until the peer
/// writes. Both sides therefore write [`STREAM_KICK`] before waiting.
///
/// Wrapped in an overall timeout: the QUIC handshake can succeed while the
/// path is too asymmetric/lossy for streams to actually open (seen in
/// practice — a "connected" peer that never finishes pairing), which would
/// otherwise hang this call forever with no way for the caller to recover.
async fn pair_streams(ep: &Endpoint, conn: iroh::endpoint::Connection) -> Result<Connection> {
    tokio::time::timeout(STREAM_PAIR_TIMEOUT, async {
        let mut send = conn
            .open_uni()
            .await
            .map_err(|e| anyhow!("open outgoing stream: {e}"))?;
        send.write_all(&[STREAM_KICK])
            .await
            .map_err(|e| anyhow!("open outgoing stream: {e}"))?;
        send.flush()
            .await
            .map_err(|e| anyhow!("open outgoing stream: {e}"))?;
        let mut recv = conn
            .accept_uni()
            .await
            .map_err(|e| anyhow!("accept incoming stream: {e}"))?;
        let mut kick = [0u8; 1];
        recv.read_exact(&mut kick)
            .await
            .map_err(|e| anyhow!("accept incoming stream: {e}"))?;
        if kick[0] != STREAM_KICK {
            return Err(anyhow!("could not reach peer"));
        }
        Ok(Connection::from_io(EndpointBoundIo {
            io: io::join(recv, send),
            _endpoint: ep.clone(),
        }))
    })
    .await
    .map_err(|_| anyhow!("timed out establishing the data channel with the peer"))?
}

/// Wraps the joined stream pair together with a clone of the owning
/// [`Endpoint`]. The endpoint drives background tasks (hole-punching, relay
/// upkeep) that the connection depends on — dropping it early would be a
/// silent, hard-to-diagnose way to kill an otherwise-healthy session, so we
/// keep it alive for exactly as long as the byte pipe built on top of it is.
struct EndpointBoundIo {
    io: io::Join<RecvStream, SendStream>,
    _endpoint: Endpoint,
}

impl AsyncRead for EndpointBoundIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for EndpointBoundIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// HTTP client for the mailbox rendezvous service: maps a pairing code to
/// the host's `EndpointId` so a joiner on a different network can dial it.
#[derive(Clone)]
pub struct Mailbox {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    code: &'a str,
    endpoint_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<&'a str>,
    relays: &'a [String],
    ips: &'a [String],
}

#[derive(Serialize)]
struct RefreshBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<&'a str>,
    relays: &'a [String],
    ips: &'a [String],
}

#[derive(Deserialize)]
struct RegisterResponse {
    token: String,
}

#[derive(Deserialize)]
pub struct LookupResponse {
    pub endpoint_id: String,
    pub device_name: Option<String>,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
}

impl Mailbox {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::new_with_timeout(base_url, MAILBOX_HTTP_TIMEOUT)
    }

    fn new_with_timeout(base_url: impl Into<String>, timeout: Duration) -> Self {
        Mailbox {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(timeout)
                // Pairing code is in the path; bearer token on unregister.
                // Following a 302 would leak both onto another origin.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client"),
        }
    }

    /// Publish `code -> endpoint_id` plus optional relay/IP hints so a joiner
    /// can dial without n0 discovery. Returns a token required to unregister.
    pub async fn register(
        &self,
        code: &str,
        endpoint_id: &str,
        device_name: Option<&str>,
        relays: &[String],
        ips: &[String],
    ) -> Result<String> {
        let res = self
            .http
            .post(format!("{}/register", self.base_url))
            .json(&RegisterRequest {
                code,
                endpoint_id,
                device_name,
                relays,
                ips,
            })
            .send()
            .await
            .map_err(|e| anyhow!("mailbox unreachable: {e}"))?;
        if res.status().is_success() {
            let body: RegisterResponse = mailbox_json(res).await?;
            Ok(body.token)
        } else if res.status() == reqwest::StatusCode::CONFLICT {
            Err(anyhow!("this pairing code is already registered"))
        } else if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(anyhow!("mailbox rate limit exceeded"))
        } else {
            Err(anyhow!("mailbox rejected registration ({})", res.status()))
        }
    }

    /// Poll the mailbox for `code`'s peer info, tolerating the host not
    /// having registered yet (the two sides don't register/lookup in any
    /// guaranteed order).
    pub async fn lookup(&self, code: &str) -> Result<LookupResponse> {
        let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
        let mut saw_not_found = false;
        loop {
            let attempt = self
                .http
                .get(format!("{}/lookup/{code}", self.base_url))
                .send()
                .await;
            match attempt {
                Ok(res) if res.status().is_success() => {
                    let body: LookupResponse = mailbox_json(res).await?;
                    return take_mailbox_lookup(body);
                }
                Ok(res) if res.status().is_redirection() => {
                    return Err(anyhow!("mailbox returned a malformed response"));
                }
                Ok(res) if res.status() == reqwest::StatusCode::NOT_FOUND => {
                    saw_not_found = true;
                }
                Ok(res) if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    return Err(anyhow!("mailbox rate limit exceeded"));
                }
                Ok(res) => {
                    return Err(anyhow!("mailbox rejected lookup ({})", res.status()));
                }
                Err(_) => {}
            }
            if tokio::time::Instant::now() >= deadline {
                if saw_not_found {
                    return Err(anyhow!(
                        "no peer found for this code (it may have expired, or the \
                         host hasn't started yet)"
                    ));
                }
                return Err(anyhow!("mailbox unreachable"));
            }
            tokio::time::sleep(LOOKUP_POLL_INTERVAL).await;
        }
    }

    /// Best-effort cleanup once a code has served its purpose.
    pub async fn unregister(&self, code: &str, token: Option<&str>) {
        let mut req = self
            .http
            .delete(format!("{}/register/{code}", self.base_url));
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let _ = req.send().await;
    }

    /// Extend mailbox TTL for a still-hosted code (token required).
    pub async fn refresh(&self, code: &str, token: &str) -> Result<()> {
        self.refresh_inner(code, token, None).await
    }

    /// Same as [`refresh`], and replace dial hints in place so the host never
    /// unregisters (no squat gap on the 6-digit code).
    pub async fn refresh_hints(
        &self,
        code: &str,
        token: &str,
        device_name: Option<&str>,
        relays: &[String],
        ips: &[String],
    ) -> Result<()> {
        self.refresh_inner(code, token, Some((device_name, relays, ips)))
            .await
    }

    async fn refresh_inner(
        &self,
        code: &str,
        token: &str,
        hints: Option<(Option<&str>, &[String], &[String])>,
    ) -> Result<()> {
        let mut req = self
            .http
            .post(format!("{}/register/{code}/refresh", self.base_url))
            .header("Authorization", format!("Bearer {token}"));
        if let Some((device_name, relays, ips)) = hints {
            req = req.json(&RefreshBody {
                device_name,
                relays,
                ips,
            });
        }
        let res = req
            .send()
            .await
            .map_err(|e| anyhow!("mailbox unreachable: {e}"))?;
        if res.status().is_success() {
            Ok(())
        } else if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(anyhow!("mailbox registration expired"))
        } else if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(anyhow!("mailbox rate limit exceeded"))
        } else {
            Err(anyhow!("mailbox rejected registration ({})", res.status()))
        }
    }
}

/// Mailbox JSON is untrusted (operator or MITM on a mis-set URL). Cap the
/// device name and drop loopback/private dial hints before the joiner uses them.
fn take_mailbox_lookup(body: LookupResponse) -> Result<LookupResponse> {
    let id = body.endpoint_id.trim();
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("mailbox returned a malformed response"));
    }
    Ok(LookupResponse {
        endpoint_id: id.to_ascii_lowercase(),
        device_name: protocol::sanitize_display_name(body.device_name.as_deref()),
        relays: retain_shareable_relays(body.relays),
        ips: retain_shareable_ips(body.ips),
    })
}

pub(crate) fn mailbox_code_taken(err: &anyhow::Error) -> bool {
    err.to_string().contains("already registered")
}

pub(crate) fn mailbox_slot_lost(err: &anyhow::Error) -> bool {
    err.to_string().contains("mailbox registration expired")
}

async fn mailbox_json<T: serde::de::DeserializeOwned>(res: reqwest::Response) -> Result<T> {
    use futures::StreamExt;
    if res
        .content_length()
        .is_some_and(|n| n > MAILBOX_BODY_MAX as u64)
    {
        return Err(anyhow!("mailbox returned a malformed response"));
    }
    let mut body = Vec::new();
    let mut stream = res.bytes_stream();
    while let Some(next) = stream.next().await {
        let chunk = next.map_err(|e| anyhow!("mailbox returned a malformed response: {e}"))?;
        if body.len().saturating_add(chunk.len()) > MAILBOX_BODY_MAX {
            return Err(anyhow!("mailbox returned a malformed response"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|e| anyhow!("mailbox returned a malformed response: {e}"))
}

/// Outcome of publishing a pairing code to the optional mailbox.
pub struct MailboxRegistration {
    pub code: String,
    pub invite: String,
    pub token: Option<String>,
    pub ok: bool,
}

/// Register `code`. On 409 (first-write-wins squat), rotate the 6-digit SPAKE2
/// code and retry so a joiner who types digits never lands on the squatter.
pub async fn register_or_rotate(
    mb: &Mailbox,
    mut code: String,
    endpoint_id: &str,
    device_name: Option<&str>,
    relays: &[String],
    ips: &[String],
    make_invite: impl Fn(&str) -> String,
) -> MailboxRegistration {
    const MAX: u32 = 8;
    let mut invite = make_invite(&code);
    for attempt in 0..MAX {
        match mb
            .register(&code, endpoint_id, device_name, relays, ips)
            .await
        {
            Ok(token) => {
                return MailboxRegistration {
                    code,
                    invite,
                    token: Some(token),
                    ok: true,
                };
            }
            Err(e) if mailbox_code_taken(&e) && attempt + 1 < MAX => {
                code = crate::session::generate_pairing_code();
                invite = make_invite(&code);
            }
            Err(e) => {
                tracing::warn!("mailbox register skipped: {e}");
                return MailboxRegistration {
                    code,
                    invite,
                    token: None,
                    ok: false,
                };
            }
        }
    }
    tracing::warn!("mailbox register skipped: repeated code collisions");
    code = crate::session::generate_pairing_code();
    invite = make_invite(&code);
    MailboxRegistration {
        code,
        invite,
        token: None,
        ok: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the real iroh stack end-to-end (hole-punch/relay against
    // n0's public infrastructure), so it needs real network access and
    // takes a few seconds — not run by default, see CI/README. Run with
    // `cargo test -p frostwall --lib internet:: -- --ignored`.
    //
    // The whole exchange is wrapped in an outer deadline (on top of the
    // timeouts already inside `host_endpoint`/`connect_to`/`pair_streams`)
    // so a misbehaving network fails this test loudly within ~2 minutes
    // instead of hanging indefinitely — see the "data channel" timeout
    // added after a manual run got silently killed with no diagnostics.
    #[tokio::test]
    #[ignore = "requires real network access to iroh's relay/discovery infra"]
    async fn host_and_join_exchange_frames_over_iroh() {
        tokio::time::timeout(Duration::from_secs(120), async {
            let host_ep = host_endpoint().await.expect("host endpoint");
            let join_ep = join_endpoint().await.expect("join endpoint");
            let _ = tokio::time::timeout(Duration::from_secs(10), join_ep.online()).await;
            let host_addr = host_ep.addr();

            let host_task = tokio::spawn(async move {
                let mut conn = accept_one(&host_ep).await.expect("accept");
                conn.send(b"hello from host").await.expect("send");
                let reply = conn.recv().await.expect("recv");
                assert_eq!(reply, b"hello from joiner");
            });

            // Give the host a moment to be ready to accept before dialing.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut joiner_conn = connect_addr(&join_ep, host_addr).await.expect("connect");
            let first = joiner_conn.recv().await.expect("recv");
            assert_eq!(first, b"hello from host");
            joiner_conn
                .send(b"hello from joiner")
                .await
                .expect("send");

            host_task.await.expect("host task panicked");
        })
        .await
        .expect("test exceeded its 120s safety deadline — see comment above");
    }

    #[tokio::test]
    #[ignore = "same-machine iroh connect needs reachable n0 relay or hole-punch"]
    async fn host_and_join_via_embedded_addrs() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let host_ep = host_endpoint().await.expect("host endpoint");
            let join_ep = join_endpoint().await.expect("join endpoint");
            let _ = tokio::time::timeout(Duration::from_secs(10), join_ep.online()).await;
            let invite = make_invite(&host_ep, "424242");
            let parsed = parse_invite(&invite).expect("parse host invite");
            assert_eq!(parsed.code, "424242");
            let host_addr = parsed.endpoint_addr().expect("addr");
            assert!(
                !host_addr.is_empty(),
                "invite must embed relay or IP: {invite}"
            );

            let host_task = tokio::spawn(async move {
                let mut conn = accept_one(&host_ep).await.expect("accept");
                conn.send(b"hello from host").await.expect("send");
                let reply = conn.recv().await.expect("recv");
                assert_eq!(reply, b"hello from joiner");
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut joiner_conn = connect_addr(&join_ep, host_addr.clone())
                .await
                .unwrap_or_else(|e| panic!("connect: {e}; invite={invite} addr={host_addr:?}"));
            let first = joiner_conn.recv().await.expect("recv");
            assert_eq!(first, b"hello from host");
            joiner_conn
                .send(b"hello from joiner")
                .await
                .expect("send");
            host_task.await.expect("host task panicked");
        })
        .await
        .expect("local iroh exchange exceeded 60s");
    }

    /// IPv4-only sockets + n0 HTTPS relay, no direct IPs. SPAKE2 and a
    /// tiny transfer — production Remote without IPv6 holepunch as a cheat.
    async fn n0_ipv4_endpoint() -> Endpoint {
        let bind = frostwall_endpoint_builder()
            .clear_ip_transports()
            .bind_addr("0.0.0.0:0")
            .expect("ipv4 bind addr")
            .bind();
        tokio::time::timeout(BIND_TIMEOUT, bind)
            .await
            .expect("n0 ipv4 bind timeout")
            .expect("n0 ipv4 bind")
    }

    #[tokio::test]
    #[ignore = "requires n0 public relay (HTTPS /relay); CI/sandbox often cannot"]
    async fn host_and_join_via_n0_relay_only() {
        tokio::time::timeout(Duration::from_secs(90), async {
            let host_ep = n0_ipv4_endpoint().await;
            let join_ep = n0_ipv4_endpoint().await;
            wait_dialable(&host_ep).await;
            wait_dialable(&join_ep).await;
            let (relays, ips) = shareable_hints(&host_ep);
            assert!(
                !relays.is_empty(),
                "n0 home relay missing; relays={relays:?} ips={ips:?} bound={:?}",
                host_ep.bound_sockets()
            );
            assert!(
                host_ep.bound_sockets().iter().all(|s| s.is_ipv4()),
                "test must not bind IPv6: {:?}",
                host_ep.bound_sockets()
            );

            let pk: PublicKey = host_ep.id().to_string().parse().expect("pk");
            let mut host_addr = EndpointAddr::new(pk);
            for r in &relays {
                host_addr = host_addr.with_relay_url(r.parse().expect("relay url"));
            }
            assert!(
                host_addr.ip_addrs().next().is_none(),
                "test must dial n0 relay-only"
            );

            let (host_res, join_res) = tokio::join!(
                accept_one(&host_ep),
                async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    connect_addr(&join_ep, host_addr).await
                }
            );
            let host_conn = host_res.expect("accept");
            let join_conn = join_res.expect("connect");

            let host_task = tokio::spawn(async move {
                crate::session::host_handshake(host_conn, "777888").await
            });
            let joiner = crate::session::joiner_handshake(join_conn, "777888")
                .await
                .expect("joiner handshake");
            let host = host_task.await.expect("host task").expect("host handshake");
            assert_eq!(host.keys().file_key, joiner.keys().file_key);

            let (mut host_conn, host_keys) = host.into_parts();
            let (mut join_conn, join_keys) = joiner.into_parts();
            let dir = tempfile::tempdir().expect("tmp");
            let src = dir.path().join("n0.txt");
            tokio::fs::write(&src, b"n0-relay-payload").await.expect("write");
            let dest = dir.path().join("out");
            tokio::fs::create_dir_all(&dest).await.expect("dest");
            let items = [crate::transfer::SendItem::from_file(src, "n0.txt").expect("item")];
            let send_flag = std::sync::atomic::AtomicBool::new(false);
            let recv_flag = std::sync::atomic::AtomicBool::new(false);
            let mut on_send = |_p: crate::transfer::Progress| {};
            let mut on_recv = |_p: crate::transfer::Progress| {};
            let (send_res, recv_res) = tokio::join!(
                crate::transfer::send(
                    &mut host_conn,
                    &host_keys,
                    &items,
                    &mut on_send,
                    &send_flag
                ),
                crate::transfer::recv(
                    &mut join_conn,
                    &join_keys,
                    &dest,
                    &mut on_recv,
                    &recv_flag
                )
            );
            send_res.unwrap_or_else(|e| panic!("send over n0: {e:#}"));
            recv_res.unwrap_or_else(|e| panic!("recv over n0: {e:#}"));
            let got = tokio::fs::read(dest.join("n0.txt"))
                .await
                .expect("read dest");
            assert_eq!(got, b"n0-relay-payload");
        })
        .await
        .expect("n0 relay transfer exceeded 90s");
    }

    #[tokio::test]
    async fn os_dns_resolves_localhost() {
        let v4 = os_lookup("localhost", |ip| match ip {
            IpAddr::V4(v) => Some(v),
            _ => None,
        })
        .await;
        let v6 = os_lookup("localhost", |ip| match ip {
            IpAddr::V6(v) => Some(v),
            _ => None,
        })
        .await;
        assert!(
            v4.is_ok() || v6.is_ok(),
            "localhost must resolve via getaddrinfo: v4_err={:?} v6_err={:?}",
            v4.as_ref().err(),
            v6.as_ref().err()
        );
    }

    #[test]
    fn n0_https_map_disables_quic_discovery() {
        let map = n0_https_relay_map();
        assert!(map.len() >= 4, "n0 ships four production relays");
        for cfg in map.relays::<Vec<_>>() {
            let url = cfg.url.to_string();
            assert!(cfg.quic.is_none(), "QUIC discovery must stay off: {url}");
            assert!(url.starts_with("https://"), "{url}");
        }
    }

    #[test]
    fn mailbox_base_url_trims_trailing_slash() {
        let mailbox = Mailbox::new("https://mailbox.example.com/");
        assert_eq!(mailbox.base_url, "https://mailbox.example.com");
    }

    #[test]
    fn invite_roundtrip() {
        let id = "a".repeat(64);
        let invite = format!("fwb1-{id}-123456");
        let got = parse_invite(&invite).expect("parse");
        assert_eq!(got.endpoint_id, id);
        assert_eq!(got.code, "123456");
        assert!(got.relays.is_empty() && got.ips.is_empty());
        assert!(!got.has_dial_hints());
    }

    #[test]
    fn invite_ignores_whitespace() {
        let id = "ab".repeat(32);
        let invite = format!("fwb1-{id}-000111");
        let wrapped = format!("  {invite}\n");
        let got = parse_invite(&wrapped).expect("parse");
        assert_eq!(got.endpoint_id, id);
        assert_eq!(got.code, "000111");
    }

    #[test]
    fn invite_paste_from_chat_wrapper() {
        let pk = iroh::SecretKey::generate().public();
        let addr = EndpointAddr::new(pk).with_ip_addr("203.0.113.9:4242".parse().unwrap());
        let invite = make_invite_from_addr(&addr, "000111");
        let chat = format!("Here's the invite:\n`{invite}`.\nThanks!");
        let got = parse_invite(&chat).expect("chat-wrapped ticket");
        assert_eq!(got.code, "000111");
        assert_eq!(got.endpoint_id, parse_invite(&invite).unwrap().endpoint_id);
        let zwsp = format!("\u{200b}{invite}\u{200b}");
        assert_eq!(parse_invite(&zwsp).unwrap().code, "000111");
        assert!(looks_like_remote_invite(&chat));
        assert!(!looks_like_remote_invite("123456"));
        assert!(!looks_like_remote_invite("the endpoint is down"));
        assert!(!looks_like_remote_invite("fwb1-nothex"));
        assert!(!looks_like_remote_invite("fwb2-x"));
        let id = "ab".repeat(32);
        let fwb1 = format!("fwb1-{id}-000111");
        assert!(looks_like_remote_invite(&fwb1));
        assert_eq!(
            parse_invite(&format!("code: {fwb1} please")).unwrap().code,
            "000111"
        );
    }

    #[test]
    fn invite_paste_survives_wrapping_beyond_compact_max() {
        let pk = iroh::SecretKey::generate().public();
        let addr = EndpointAddr::new(pk).with_ip_addr("203.0.113.9:4242".parse().unwrap());
        let invite = make_invite_from_addr(&addr, "000111");
        // Leading whitespace on a compact-max paste: INVITE_MAX slice would
        // drop the last payload byte. Paste cap must keep the whole blob.
        let mut padded = invite.clone();
        while padded.len() <= INVITE_MAX {
            padded.insert(0, '\n');
        }
        assert!(
            padded.len() > INVITE_MAX,
            "wrapped paste must exceed compact cap so UI INVITE_MAX slice would truncate"
        );
        assert!(padded.len() <= INVITE_PASTE_MAX);
        let got = parse_invite(&padded).expect("wrapped invite");
        assert_eq!(got.code, "000111");
        assert_eq!(got.endpoint_id, parse_invite(&invite).unwrap().endpoint_id);
        let over = "a".repeat(INVITE_PASTE_MAX + 1);
        assert!(parse_invite(&over).is_err());
    }

    #[test]
    fn invite_rejects_lan_code_only() {
        assert!(parse_invite("123456").is_err());
        assert!(parse_invite("fwb1-nothex-123456").is_err());
        assert!(parse_invite(&format!("fwb1-{}-123456", "ab".repeat(16))).is_err());
    }

    #[test]
    fn parse_invite_rejects_overlong() {
        let huge = format!("fwb2-{}-123456-{}", "ab".repeat(32), "aa".repeat(INVITE_MAX));
        assert!(huge.len() > INVITE_MAX);
        assert!(parse_invite(&huge).is_err());
    }

    #[test]
    fn invite_caps_hints_and_fits_max() {
        let pk = iroh::SecretKey::generate().public();
        let mut addr = EndpointAddr::new(pk);
        for host in ["a", "b", "c", "d"] {
            let url: RelayUrl = format!("https://{host}.example/").parse().unwrap();
            addr = addr.with_relay_url(url);
        }
        for n in 1..=12u8 {
            addr = addr.with_ip_addr(format!("203.0.113.{n}:4000").parse().unwrap());
        }
        let invite = make_invite_from_addr(&addr, "123456");
        assert!(
            invite.len() <= INVITE_MAX,
            "shareable invite must paste in the UI: len={} invite={invite}",
            invite.len()
        );
        let got = parse_invite(&invite).expect("parse capped invite");
        assert!(got.relays.len() <= MAX_INVITE_RELAYS);
        assert!(got.ips.len() <= MAX_INVITE_IPS);
        assert!(!got.relays.is_empty());
        assert!(!got.ips.is_empty());
    }

    #[test]
    fn invite_fwb2_roundtrip_addrs() {
        let pk = iroh::SecretKey::generate().public();
        let relay: RelayUrl = "https://example.com/".parse().expect("relay url");
        let ip: SocketAddr = "203.0.113.9:4242".parse().expect("ip");
        let addr = EndpointAddr::new(pk)
            .with_relay_url(relay.clone())
            .with_ip_addr(ip);
        let invite = make_invite_from_addr(&addr, "654321");
        assert!(invite.starts_with("endpoint"), "{invite}");
        let got = parse_invite(&invite).expect("parse ticket");
        assert_eq!(got.code, "654321");
        assert_eq!(got.endpoint_id, pk.to_string());
        let rebuilt = got.endpoint_addr().expect("addr");
        assert_eq!(rebuilt.id, pk);
        assert!(rebuilt.relay_urls().any(|u| u == &relay));
        assert!(rebuilt.ip_addrs().any(|a| a == &ip));
        assert!(got.has_dial_hints());
        assert!(got.device_name.is_none());
        let legacy = format!(
            "fwb2-{}-654321-{}",
            pk,
            to_hex(
                &serde_json::to_vec(&InviteNet {
                    r: vec!["https://example.com/".into()],
                    i: vec!["203.0.113.9:4242".into()],
                    n: None,
                })
                .unwrap()
            )
        );
        let old = parse_invite(&legacy).expect("parse legacy fwb2");
        assert_eq!(old.code, "654321");
        assert!(old.has_dial_hints());
    }

    #[test]
    fn invite_ticket_needs_pairing_code() {
        let pk = iroh::SecretKey::generate().public();
        let addr = EndpointAddr::new(pk).with_ip_addr("203.0.113.9:4242".parse().unwrap());
        let bare = EndpointTicket::new(addr.clone()).encode_string();
        assert!(parse_invite(&bare).is_err());
        let private = EndpointAddr::new(pk)
            .with_relay_url("https://127.0.0.1/".parse().unwrap())
            .with_ip_addr("127.0.0.1:9".parse().unwrap())
            .with_ip_addr("203.0.113.9:4242".parse().unwrap());
        let crafted = format!("{}-111222", EndpointTicket::new(private).encode_string());
        let got = parse_invite(&crafted).expect("parse crafted ticket");
        assert!(got.ips.iter().all(|i| !i.starts_with("127.")));
        assert!(got.relays.is_empty());
        assert!(got.ips.iter().any(|i| i.starts_with("203.0.113.9:")));
    }

    #[test]
    fn invite_carries_device_name() {
        let pk = iroh::SecretKey::generate().public();
        let addr = EndpointAddr::new(pk).with_ip_addr("203.0.113.9:4242".parse().unwrap());
        let invite = make_invite_from_addr_named(&addr, "123456", Some("  Mac mini\u{0007}  "));
        let got = parse_invite(&invite).expect("parse named invite");
        assert_eq!(got.device_name.as_deref(), Some("Mac mini"));
        let unnamed = make_invite_from_addr(&addr, "123456");
        assert!(parse_invite(&unnamed).unwrap().device_name.is_none());
        let odd = format!("{unnamed}-abc");
        let odd_got = parse_invite(&odd).expect("odd name hex must not void ticket");
        assert_eq!(odd_got.code, "123456");
        assert!(odd_got.device_name.is_none());
        let bad_utf8 = format!("{unnamed}-ffff");
        let bad_got = parse_invite(&bad_utf8).expect("non-utf8 name must not void ticket");
        assert_eq!(bad_got.code, "123456");
        assert!(bad_got.device_name.is_none());
    }

    #[test]
    fn invite_omits_loopback_addrs() {
        let pk = iroh::SecretKey::generate().public();
        let mixed = EndpointAddr::new(pk)
            .with_ip_addr("127.0.0.1:9".parse().unwrap())
            .with_ip_addr("203.0.113.9:4242".parse().unwrap());
        let got = parse_invite(&make_invite_from_addr(&mixed, "111222")).unwrap();
        assert!(got.ips.iter().any(|i| i.starts_with("203.0.113.9:")));
        assert!(got.ips.iter().all(|i| !i.starts_with("127.")));
        let mixed_lan = EndpointAddr::new(pk)
            .with_relay_url("https://example.com/".parse().unwrap())
            .with_ip_addr("192.168.1.10:9".parse().unwrap())
            .with_ip_addr("10.0.0.5:9".parse().unwrap());
        let lan = parse_invite(&make_invite_from_addr(&mixed_lan, "111222")).unwrap();
        assert!(lan.relays.iter().any(|r| r.contains("example.com")));
        assert!(lan.ips.is_empty(), "private LAN must not be in Remote invite: {:?}", lan.ips);
        let cgnat = parse_invite(
            &make_invite_from_addr(
                &EndpointAddr::new(pk)
                    .with_relay_url("https://example.com/".parse().unwrap())
                    .with_ip_addr("100.64.1.8:9".parse().unwrap()),
                "111222",
            ),
        )
        .unwrap();
        assert!(cgnat.ips.is_empty(), "CGNAT must not be in Remote invite: {:?}", cgnat.ips);
        let mapped = parse_invite(
            &make_invite_from_addr(
                &EndpointAddr::new(pk)
                    .with_relay_url("https://example.com/".parse().unwrap())
                    .with_ip_addr("[::ffff:192.168.1.10]:9".parse().unwrap()),
                "111222",
            ),
        )
        .unwrap();
        assert!(
            mapped.ips.is_empty(),
            "IPv4-mapped RFC1918 must not be in Remote invite: {:?}",
            mapped.ips
        );
        let only_lo = EndpointAddr::new(pk).with_ip_addr("127.0.0.1:9".parse().unwrap());
        let id_only = make_invite_from_addr(&only_lo, "111222");
        assert!(id_only.starts_with("endpoint"), "{id_only}");
        assert!(!parse_invite(&id_only).unwrap().has_dial_hints());
        let crafted = InviteNet {
            r: vec![
                "not-a-url".into(),
                "http://insecure.example/".into(),
                "https://127.0.0.1/".into(),
                "https://192.168.0.1/".into(),
                "https://localhost/".into(),
                "https://user:pass@relay.example/".into(),
            ],
            i: vec!["192.168.0.5:9".into(), "100.64.1.1:9".into()],
            n: None,
        };
        let raw = format!(
            "fwb2-{}-111222-{}",
            pk,
            to_hex(&serde_json::to_vec(&crafted).unwrap())
        );
        let dropped = parse_invite(&raw).unwrap();
        assert!(dropped.ips.is_empty(), "parse must drop private/CGNAT: {:?}", dropped.ips);
        assert!(dropped.relays.is_empty(), "parse must drop loopback/private relays: {:?}", dropped.relays);
        assert!(!dropped.has_dial_hints());
        let n0 = InviteNet {
            r: vec![
                "https://use1-1.relay.n0.iroh.link.".into(),
                "https://euw1-1.relay.iroh.network./".into(),
                "https://localhost./".into(),
            ],
            i: vec![],
            n: None,
        };
        let n0_raw = format!(
            "fwb2-{}-111222-{}",
            pk,
            to_hex(&serde_json::to_vec(&n0).unwrap())
        );
        let n0_got = parse_invite(&n0_raw).unwrap();
        assert!(
            n0_got.relays.iter().any(|r| r.contains("relay.n0.iroh.link")),
            "FQDN trailing-dot n0 relay must stay: {:?}",
            n0_got.relays
        );
        assert!(n0_got.relays.iter().any(|r| r.contains("relay.iroh.network")));
        assert!(n0_got.relays.iter().all(|r| !r.to_ascii_lowercase().contains("localhost")));
        let mixed = InviteNet {
            r: vec!["Https://use1-1.relay.n0.iroh.link./".into()],
            i: vec![],
            n: None,
        };
        let mixed_raw = format!(
            "fwb2-{}-111222-{}",
            pk,
            to_hex(&serde_json::to_vec(&mixed).unwrap())
        );
        let mixed_got = parse_invite(&mixed_raw).unwrap();
        assert!(
            mixed_got.relays.iter().any(|r| r.to_ascii_lowercase().contains("relay.n0.iroh.link")),
            "mixed-case https scheme must still parse: {:?}",
            mixed_got.relays
        );
    }

    #[test]
    fn mailbox_hints_skip_invalid_and_loopback() {
        let pk = iroh::SecretKey::generate().public();
        let parsed = ParsedInvite::from_mailbox(
            pk.to_string(),
            "123456".into(),
            vec!["not-a-url".into(), "https://example.com/".into()],
            vec![
                "nope".into(),
                "127.0.0.1:9".into(),
                "203.0.113.9:4242".into(),
            ],
        );
        let addr = parsed.endpoint_addr().expect("addr");
        assert!(
            addr.relay_urls()
                .any(|u| u.to_string().contains("example.com")),
            "good relay must survive a junk sibling"
        );
        assert!(addr.ip_addrs().any(|a| a.to_string().starts_with("203.0.113.9")));
        assert!(addr.ip_addrs().all(|a| !a.ip().is_loopback()));
    }

    #[test]
    fn mailbox_lookup_sanitizes_hostile_payload() {
        let pk = iroh::SecretKey::generate().public().to_string();
        let got = take_mailbox_lookup(LookupResponse {
            endpoint_id: format!("  {pk}  "),
            device_name: Some(format!("  {}\u{0007}  ", "n".repeat(80))),
            relays: vec![
                "https://relay.example/".into(),
                "https://127.0.0.1/".into(),
                "http://insecure.example/".into(),
            ],
            ips: vec!["203.0.113.9:9".into(), "127.0.0.1:9".into()],
        })
        .unwrap();
        assert_eq!(got.endpoint_id, pk.to_ascii_lowercase());
        let expected_name = "n".repeat(protocol::MAX_DISPLAY_NAME);
        assert_eq!(got.device_name.as_deref(), Some(expected_name.as_str()));
        assert_eq!(got.relays, vec!["https://relay.example/".to_string()]);
        assert_eq!(got.ips, vec!["203.0.113.9:9".to_string()]);
        assert!(take_mailbox_lookup(LookupResponse {
            endpoint_id: "nope".into(),
            device_name: None,
            relays: vec![],
            ips: vec![],
        })
        .is_err());
    }

    #[tokio::test]
    async fn mailbox_json_caps_chunked_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 2048];
            let mut n = 0usize;
            loop {
                let got = sock.read(&mut buf[n..]).await.expect("req");
                if got == 0 {
                    break;
                }
                n += got;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if n == buf.len() {
                    break;
                }
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .expect("hdr");
            let chunk = "a".repeat(4096);
            for _ in 0..20 {
                let line = format!("{:x}\r\n{chunk}\r\n", chunk.len());
                if sock.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
        });
        let client = reqwest::Client::builder()
            .timeout(MAILBOX_HTTP_TIMEOUT)
            .build()
            .expect("client");
        let res = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("send");
        let err = mailbox_json::<serde_json::Value>(res)
            .await
            .expect_err("oversize chunked body");
        assert!(
            err.to_string().contains("malformed"),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn mailbox_json_parses_small_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 2048];
            let mut n = 0usize;
            loop {
                let got = sock.read(&mut buf[n..]).await.expect("req");
                if got == 0 {
                    break;
                }
                n += got;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if n == buf.len() {
                    break;
                }
            }
            let body = br#"{"ok":true}"#;
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            sock.write_all(hdr.as_bytes()).await.expect("hdr");
            sock.write_all(body).await.expect("body");
        });
        let client = reqwest::Client::new();
        let res = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("send");
        let v: serde_json::Value = mailbox_json(res).await.expect("json");
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn mailbox_client_does_not_follow_redirect() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn drain_headers(sock: &mut tokio::net::TcpStream) {
            let mut buf = vec![0u8; 2048];
            let mut n = 0usize;
            loop {
                let got = sock.read(&mut buf[n..]).await.expect("req");
                if got == 0 {
                    break;
                }
                n += got;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
                    break;
                }
            }
        }

        let hit = std::sync::Arc::new(AtomicBool::new(false));
        let sink = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("sink");
        let sink_addr = sink.local_addr().expect("sink addr");
        let hit2 = hit.clone();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = sink.accept().await {
                hit2.store(true, Ordering::SeqCst);
                let _ = sock.shutdown().await;
            }
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                drain_headers(&mut sock).await;
                let loc = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{sink_addr}/register\r\nContent-Length: 0\r\n\r\n"
                );
                let _ = sock.write_all(loc.as_bytes()).await;
            }
        });

        let mb = Mailbox::new(format!("http://{addr}"));
        let id = "ab".repeat(32);
        let err = mb
            .register("123456", &id, None, &[], &[])
            .await
            .expect_err("302 must not look like success");
        assert!(
            err.to_string().contains("rejected"),
            "register 302: {err}"
        );
        let started = tokio::time::Instant::now();
        let lookup_err = match mb.lookup("123456").await {
            Ok(_) => panic!("302 lookup succeeded"),
            Err(e) => e,
        };
        assert!(
            lookup_err.to_string().contains("malformed"),
            "lookup 302: {lookup_err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "redirect must fail fast, not poll LOOKUP_TIMEOUT"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !hit.load(Ordering::SeqCst),
            "mailbox HTTP must not follow redirects"
        );
    }

    #[tokio::test]
    async fn mailbox_lookup_rate_limit_and_5xx_fail_fast() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn drain_headers(sock: &mut tokio::net::TcpStream) {
            let mut buf = vec![0u8; 2048];
            let mut n = 0usize;
            loop {
                let got = sock.read(&mut buf[n..]).await.expect("req");
                if got == 0 {
                    break;
                }
                n += got;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
                    break;
                }
            }
        }

        async fn serve(line: &'static str) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        break;
                    };
                    drain_headers(&mut sock).await;
                    let hdr = format!("HTTP/1.1 {line}\r\nContent-Length: 0\r\n\r\n");
                    let _ = sock.write_all(hdr.as_bytes()).await;
                }
            });
            format!("http://{addr}")
        }

        let mb429 = Mailbox::new(serve("429 Too Many Requests").await);
        let t0 = tokio::time::Instant::now();
        let err429 = match mb429.lookup("123456").await {
            Ok(_) => panic!("429 lookup succeeded"),
            Err(e) => e,
        };
        assert!(
            err429.to_string().contains("rate limit"),
            "lookup 429: {err429}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "429 must fail fast, not poll LOOKUP_TIMEOUT"
        );

        let mb500 = Mailbox::new(serve("500 Internal Server Error").await);
        let t1 = tokio::time::Instant::now();
        let err500 = match mb500.lookup("123456").await {
            Ok(_) => panic!("500 lookup succeeded"),
            Err(e) => e,
        };
        assert!(
            err500.to_string().contains("rejected lookup"),
            "lookup 500: {err500}"
        );
        assert!(
            t1.elapsed() < Duration::from_secs(3),
            "5xx must fail fast, not poll LOOKUP_TIMEOUT"
        );
    }

    /// Mirrors `src/invite.ts` `lanCodeFromInput`. Layout change must fail here.
    fn ts_lan_code(s: &str) -> String {
        let compact = compact_invite(s);
        let mut from = 0;
        while let Some(rel) = compact[from..].find("endpoint") {
            let at = from + rel;
            let rest = &compact[at + "endpoint".len()..];
            let body = rest.chars().take_while(|c| c.is_ascii_alphanumeric()).count();
            if body > 0 {
                let after = &rest[body..];
                if after.len() >= 7
                    && after.as_bytes()[0] == b'-'
                    && after[1..7].chars().all(|c| c.is_ascii_digit())
                {
                    return after[1..7].to_string();
                }
            }
            from = at + 1;
        }
        if compact.contains("endpoint") {
            return String::new();
        }
        if let Some(at) = compact.find("fwb2-") {
            let rest = &compact[at + 5..];
            if rest.len() > 64 + 1 + 6
                && rest.as_bytes()[64] == b'-'
                && rest.as_bytes().get(71) == Some(&b'-')
                && rest[..64].chars().all(|c| c.is_ascii_hexdigit())
                && rest[65..71].chars().all(|c| c.is_ascii_digit())
            {
                return rest[65..71].to_string();
            }
        }
        if let Some(at) = compact.find("fwb1-") {
            let rest = &compact[at + 5..];
            if rest.len() >= 64 + 1 + 6
                && rest.as_bytes()[64] == b'-'
                && rest[..64].chars().all(|c| c.is_ascii_hexdigit())
                && rest[65..71].chars().all(|c| c.is_ascii_digit())
            {
                return rest[65..71].to_string();
            }
        }
        if compact.contains("fwb") {
            return String::new();
        }
        compact
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect()
    }

    #[test]
    fn frontend_lan_code_matches_parse() {
        let id = "ab".repeat(32);
        let fwb1 = format!("fwb1-{id}-445566");
        assert_eq!(ts_lan_code(&fwb1), parse_invite(&fwb1).unwrap().code);
        let fwb2 = format!(
            "fwb2-{}-778899-{}",
            id,
            to_hex(br#"{"i":["203.0.113.9:4242"]}"#)
        );
        assert_eq!(ts_lan_code(&fwb2), parse_invite(&fwb2).unwrap().code);
        let pk = iroh::SecretKey::generate().public();
        let addr = EndpointAddr::new(pk).with_ip_addr("203.0.113.9:4242".parse().unwrap());
        let ticket = make_invite_from_addr(&addr, "778899");
        assert!(ticket.starts_with("endpoint"), "{ticket}");
        assert_eq!(ts_lan_code(&ticket), parse_invite(&ticket).unwrap().code);
        let named = make_invite_from_addr_named(&addr, "112233", Some("Desk"));
        assert_eq!(ts_lan_code(&named), parse_invite(&named).unwrap().code);
        assert_eq!(ts_lan_code("12ab34"), "1234");
        assert_eq!(ts_lan_code("1234567"), "1234567");
        assert_eq!(ts_lan_code("fwb1-deadbeef"), "");
        assert_eq!(ts_lan_code("fwb3-123456"), "");
        assert_eq!(ts_lan_code("endpoint-123456"), "");
        assert_eq!(ts_lan_code("endpointabc-123456"), "123456");
        assert_eq!(ts_lan_code("endpointabc-123456-"), "123456");
        assert_eq!(ts_lan_code("endpointabc-123456-de"), "123456");
        let wrapped = format!("Here's the invite:\n`{ticket}`.\n");
        assert_eq!(ts_lan_code(&wrapped), parse_invite(&wrapped).unwrap().code);
        assert_eq!(INVITE_MAX, 1024, "lockstep with src/invite.ts INVITE_MAX");
        assert_eq!(
            INVITE_PASTE_MAX, 4096,
            "lockstep with src/invite.ts INVITE_PASTE_MAX"
        );
        assert!(accept_wait_timed_out(&anyhow::anyhow!(
            "timed out waiting for an internet connection"
        )));
        assert!(!accept_wait_timed_out(&anyhow::anyhow!(
            "internet endpoint closed before a peer connected"
        )));
        assert!(accept_retryable(&anyhow::anyhow!(
            "incoming connection failed: reset"
        )));
        assert!(accept_retryable(&anyhow::anyhow!(
            "timed out establishing the data channel with the peer"
        )));
        assert!(accept_retryable(&anyhow::anyhow!("open outgoing stream: x")));
        assert!(accept_retryable(&anyhow::anyhow!(
            "accept incoming stream: x"
        )));
        assert!(accept_retryable(&anyhow::anyhow!("could not reach peer")));
        assert!(!accept_retryable(&anyhow::anyhow!(
            "internet endpoint closed before a peer connected"
        )));
    }

    #[tokio::test]
    async fn wait_for_shareable_relay_times_out_without_https_home() {
        use iroh::RelayMode;
        use std::net::Ipv4Addr;
        let bind = Endpoint::builder(presets::N0)
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("bind_addr");
        let ep = tokio::time::timeout(Duration::from_secs(8), bind.bind())
            .await
            .expect("bind timeout")
            .expect("bind");
        let t0 = tokio::time::Instant::now();
        assert!(
            !wait_for_shareable_relay(&ep, Duration::from_millis(50)).await,
            "disabled-relay loopback has no shareable HTTPS home"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "zero-hint wait must return at the deadline, not hang on online()"
        );
    }

    #[tokio::test]
    async fn host_and_join_loopback_no_n0_relay() {
        use iroh::RelayMode;
        use std::net::Ipv4Addr;
        async fn loopback() -> Endpoint {
            let bind = Endpoint::builder(presets::N0)
                .relay_mode(RelayMode::Disabled)
                .alpns(vec![ALPN.to_vec()])
                .bind_addr((Ipv4Addr::LOCALHOST, 0))
                .expect("bind_addr");
            tokio::time::timeout(Duration::from_secs(8), bind.bind())
                .await
                .expect("bind timeout")
                .expect("bind")
        }

        tokio::time::timeout(Duration::from_secs(20), async {
            let (host_ep, join_ep) = tokio::join!(loopback(), loopback());
            let invite = make_invite(&host_ep, "111222");
            let parsed = parse_invite(&invite).expect("parse");
            assert!(
                parsed.ips.iter().all(|i| i
                    .parse::<SocketAddr>()
                    .map(|s| !s.ip().is_loopback())
                    .unwrap_or(true)),
                "shareable invite must not leak loopback: {invite} ips={:?}",
                parsed.ips
            );
            let mut host_addr = EndpointAddr::new(host_ep.id());
            for sa in host_ep.bound_sockets() {
                if !sa.ip().is_unspecified() && !sa.ip().is_multicast() {
                    host_addr = host_addr.with_ip_addr(sa);
                }
            }
            assert!(
                host_addr.ip_addrs().any(|a| a.ip().is_loopback()),
                "loopback bind must still be dialable locally"
            );

            let (host_res, join_res) = tokio::join!(
                accept_one(&host_ep),
                async {
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    connect_addr(&join_ep, host_addr).await
                }
            );
            let mut host_conn = host_res.expect("accept");
            let mut join_conn = join_res.expect("connect");
            host_conn.send(b"ping").await.expect("host send");
            assert_eq!(join_conn.recv().await.expect("join recv"), b"ping");
            join_conn.send(b"pong").await.expect("join send");
            assert_eq!(host_conn.recv().await.expect("host recv"), b"pong");
        })
        .await
        .expect("loopback iroh exchange exceeded 20s");
    }

    /// WAN-shaped path: joiner gets only the relay URL from the invite (no
    /// direct IPs). Uses a local iroh relay, not n0 — proves the Remote
    /// fallback without same-LAN sockets.
    #[tokio::test]
    async fn host_and_join_via_local_relay_no_direct_ip() {
        use iroh::tls::CaTlsConfig;
        use iroh::RelayMap;
        use iroh::RelayMode;

        tokio::time::timeout(Duration::from_secs(45), async {
            let (relay_map, _url, _server) = iroh::test_utils::run_relay_server()
                .await
                .expect("local relay");

            async fn ep(relay_map: RelayMap) -> Endpoint {
                Endpoint::builder(presets::Minimal)
                    .relay_mode(RelayMode::Custom(relay_map))
                    .alpns(vec![ALPN.to_vec()])
                    .ca_tls_config(CaTlsConfig::insecure_skip_verify())
                    .bind()
                    .await
                    .expect("bind")
            }

            let (host_ep, join_ep) = tokio::join!(ep(relay_map.clone()), ep(relay_map));
            tokio::time::timeout(Duration::from_secs(10), host_ep.online())
                .await
                .expect("host never reached local relay");

            let relays: Vec<String> = host_ep.addr().relay_urls().map(|u| u.to_string()).collect();
            assert!(!relays.is_empty(), "invite must embed relay URL");
            let shareable = parse_invite(&make_invite(&host_ep, "333444")).expect("parse");
            assert!(
                shareable.relays.is_empty(),
                "loopback test relay must not go on a shareable invite: {:?}",
                shareable.relays
            );

            let parsed = ParsedInvite::with_test_dial_hints(
                endpoint_id_string(&host_ep),
                "333444".into(),
                relays,
                Vec::new(),
            );
            let host_addr = parsed.endpoint_addr().expect("addr");
            assert!(
                host_addr.ip_addrs().next().is_none(),
                "test must dial relay-only"
            );

            let (host_res, join_res) = tokio::join!(
                accept_one(&host_ep),
                async {
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    connect_addr(&join_ep, host_addr).await
                }
            );
            let host_conn = host_res.expect("accept");
            let join_conn = join_res.expect("connect");

            let host_task = tokio::spawn(async move {
                crate::session::host_handshake(host_conn, "333444").await
            });
            let joiner = crate::session::joiner_handshake(join_conn, "333444")
                .await
                .expect("joiner handshake");
            let host = host_task.await.expect("host task").expect("host handshake");
            let now = 1_700_000_000u64;
            assert_eq!(host.liveness_code(now), joiner.liveness_code(now));
            assert_eq!(host.keys().file_key, joiner.keys().file_key);

            let (mut host_conn, host_keys) = host.into_parts();
            let (mut join_conn, join_keys) = joiner.into_parts();
            host_conn.send(b"pipe").await.expect("post-handshake send");
            assert_eq!(join_conn.recv().await.expect("post-handshake recv"), b"pipe");

            let dir = tempfile::tempdir().expect("tmp");
            let src = dir.path().join("hello.txt");
            let nested_dir = dir.path().join("sub");
            let nested = nested_dir.join("n.txt");
            let content = b"iroh-relay-payload";
            tokio::fs::create_dir_all(&nested_dir).await.expect("nested dir");
            tokio::fs::write(&src, content).await.expect("write src");
            tokio::fs::write(&nested, b"nested").await.expect("write nested");
            let dest = dir.path().join("out");
            tokio::fs::create_dir_all(&dest).await.expect("dest dir");
            let items = [
                crate::transfer::SendItem::from_file(src, "hello.txt").expect("item"),
                crate::transfer::SendItem::from_file(nested, "sub/n.txt").expect("item"),
            ];
            let send_flag = std::sync::atomic::AtomicBool::new(false);
            let recv_flag = std::sync::atomic::AtomicBool::new(false);
            let mut on_send = |_p: crate::transfer::Progress| {};
            let mut on_recv = |_p: crate::transfer::Progress| {};
            let (send_res, recv_res) = tokio::join!(
                crate::transfer::send(
                    &mut host_conn,
                    &host_keys,
                    &items,
                    &mut on_send,
                    &send_flag
                ),
                crate::transfer::recv(
                    &mut join_conn,
                    &join_keys,
                    &dest,
                    &mut on_recv,
                    &recv_flag
                )
            );
            send_res.unwrap_or_else(|e| panic!("send over iroh: {e:#}"));
            recv_res.unwrap_or_else(|e| panic!("recv over iroh: {e:#}"));
            let got = tokio::fs::read(dest.join("hello.txt"))
                .await
                .expect("read dest");
            assert_eq!(got, content);
            let nested_got = tokio::fs::read(dest.join("sub/n.txt"))
                .await
                .expect("read nested dest");
            assert_eq!(nested_got, b"nested");
        })
        .await
        .expect("local-relay iroh exchange exceeded 45s");
    }

    #[tokio::test]
    async fn mailbox_http_client_roundtrip() {
        let url = frostwall_mailbox::start_local()
            .await
            .expect("local mailbox");
        let mb = Mailbox::new(url);
        let id = "ab".repeat(32);
        let token = mb
            .register("424242", &id, Some("lab"), &[], &[])
            .await
            .expect("register");
        let got = mb.lookup("424242").await.expect("lookup");
        assert_eq!(got.endpoint_id, id);
        assert_eq!(got.device_name.as_deref(), Some("lab"));
        assert!(got.relays.is_empty() && got.ips.is_empty());
        mb.refresh("424242", &token).await.expect("refresh");
        mb.lookup("424242").await.expect("lookup after refresh");
        assert!(mb.refresh("424242", "not-the-token").await.is_err());
        mb.refresh_hints(
            "424242",
            &token,
            Some("lab"),
            &["https://relay.example/".into()],
            &["203.0.113.9:4242".into()],
        )
        .await
        .expect("refresh hints");
        let hinted = mb.lookup("424242").await.expect("lookup hints");
        assert!(
            hinted.relays.iter().any(|r| r.contains("relay.example")),
            "{:?}",
            hinted.relays
        );
        assert!(hinted.ips.iter().any(|i| i.starts_with("203.0.113.9")));
        let collide = mb
            .register("424242", &id, None, &[], &[])
            .await
            .expect_err("refresh must not drop the slot");
        assert!(mailbox_code_taken(&collide), "{collide}");
        let lost = mb
            .refresh("424242", "not-the-token")
            .await
            .expect_err("bad token");
        assert!(mailbox_slot_lost(&lost), "{lost}");
        mb.unregister("424242", Some(&token)).await;
    }

    #[tokio::test]
    async fn mailbox_http_times_out_when_server_silent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let mb = Mailbox::new_with_timeout(format!("http://{addr}"), Duration::from_millis(400));
        let t0 = tokio::time::Instant::now();
        let err = mb
            .register("123456", &"ab".repeat(32), None, &[], &[])
            .await
            .expect_err("silent TCP must not hang");
        assert!(
            err.to_string().contains("mailbox unreachable"),
            "{err}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "mailbox HTTP timeout must fire, elapsed={:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn mailbox_conflict_rotates_spake2_code() {
        let url = frostwall_mailbox::start_local()
            .await
            .expect("local mailbox");
        let mb = Mailbox::new(url);
        let squat_id = "ab".repeat(32);
        let host_id = "cd".repeat(32);
        mb.register("111111", &squat_id, None, &[], &[])
            .await
            .expect("squat");
        let reg = register_or_rotate(
            &mb,
            "111111".into(),
            &host_id,
            Some("host"),
            &[],
            &[],
            |c| format!("fwb1-{host_id}-{c}"),
        )
        .await;
        assert!(reg.ok, "host must win a free code");
        assert_ne!(reg.code, "111111", "must not keep the squatted SPAKE2 code");
        assert!(reg.invite.ends_with(&reg.code));
        let looked = mb.lookup(&reg.code).await.expect("lookup rotated");
        assert_eq!(looked.endpoint_id, host_id);
        let squat = mb.lookup("111111").await.expect("squat still there");
        assert_eq!(squat.endpoint_id, squat_id);
    }

    /// 6-digit mailbox path: joiner never sees the fwb2 invite — only
    /// EndpointId + relay URL from lookup. Local relay, no n0, no direct IPs.
    #[tokio::test]
    async fn host_and_join_via_mailbox_relay_hints() {
        use iroh::tls::CaTlsConfig;
        use iroh::RelayMap;
        use iroh::RelayMode;

        tokio::time::timeout(Duration::from_secs(45), async {
            let (relay_map, _url, _server) = iroh::test_utils::run_relay_server()
                .await
                .expect("local relay");
            let mailbox_url = frostwall_mailbox::start_local()
                .await
                .expect("local mailbox");

            async fn ep(relay_map: RelayMap) -> Endpoint {
                Endpoint::builder(presets::Minimal)
                    .relay_mode(RelayMode::Custom(relay_map))
                    .alpns(vec![ALPN.to_vec()])
                    .ca_tls_config(CaTlsConfig::insecure_skip_verify())
                    .bind()
                    .await
                    .expect("bind")
            }

            let (host_ep, join_ep) = tokio::join!(ep(relay_map.clone()), ep(relay_map));
            tokio::time::timeout(Duration::from_secs(10), host_ep.online())
                .await
                .expect("host never reached local relay");

            let relays: Vec<String> = host_ep.addr().relay_urls().map(|u| u.to_string()).collect();
            assert!(!relays.is_empty(), "host must have a local relay URL");
            let (shareable_relays, _) = shareable_hints(&host_ep);
            assert!(
                shareable_relays.is_empty(),
                "loopback test relay must not be a shareable hint: {shareable_relays:?}"
            );
            let mb = Mailbox::new(mailbox_url);
            let id = endpoint_id_string(&host_ep);
            mb.register("555666", &id, Some("host"), &[], &[])
                .await
                .expect("mailbox register");

            let looked = mb.lookup("555666").await.expect("mailbox lookup");
            assert_eq!(looked.endpoint_id, id);
            assert!(looked.relays.is_empty(), "mailbox must drop loopback relays");
            assert!(looked.ips.is_empty());
            let parsed = ParsedInvite::with_test_dial_hints(
                looked.endpoint_id,
                "555666".into(),
                relays,
                looked.ips,
            );
            assert!(parsed.has_dial_hints());
            assert!(
                parsed
                    .endpoint_addr()
                    .expect("addr")
                    .ip_addrs()
                    .next()
                    .is_none(),
                "mailbox path must stay relay-only in this test"
            );

            let (host_res, join_res) = tokio::join!(
                accept_one(&host_ep),
                async {
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    connect_to(&join_ep, &parsed).await
                }
            );
            let mut host_conn = host_res.expect("accept");
            let mut join_conn = join_res.expect("connect");
            host_conn.send(b"mb").await.expect("host send");
            assert_eq!(join_conn.recv().await.expect("join recv"), b"mb");
        })
        .await
        .expect("mailbox relay path exceeded 45s");
    }
}
