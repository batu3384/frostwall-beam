//! LAN peer discovery via mDNS (Bonjour-style), using the pure-Rust
//! `mdns-sd` crate so no system Bonjour runtime is required on Windows.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;

use anyhow::{anyhow, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

/// The mDNS service type we advertise and browse for.
pub const SERVICE_TYPE: &str = "_frostwall._tcp.local.";

/// Wraps an `mdns-sd` daemon to advertise our presence and browse for peers.
pub struct Discovery {
    daemon: ServiceDaemon,
}

impl Discovery {
    /// Start a new mDNS daemon on this host.
    pub fn new() -> Result<Self> {
        let daemon =
            ServiceDaemon::new().map_err(|e| anyhow!("failed to start mDNS daemon: {e}"))?;
        Ok(Discovery { daemon })
    }

    /// Advertise this device so a peer on the same LAN can find it.
    pub fn advertise(&mut self, instance: &str, addr: IpAddr, port: u16) -> Result<()> {
        let host_name = format!("{instance}.local.");
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            instance,
            &host_name,
            addr.to_string(),
            port,
            HashMap::new(),
        )
        .map_err(|e| anyhow!("build mDNS service info: {e}"))?;
        self.daemon
            .register(info)
            .map_err(|e| anyhow!("register mDNS service: {e}"))?;
        Ok(())
    }

    /// Begin browsing for peers. Returns a channel of discovery events.
    pub fn browse(&self) -> Result<mdns_sd::Receiver<ServiceEvent>> {
        self.daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| anyhow!("browse mDNS: {e}"))
    }

    /// Shut the daemon down cleanly.
    pub fn shutdown(self) -> Result<()> {
        self.daemon
            .shutdown()
            .map_err(|e| anyhow!("mDNS shutdown: {e}"))?;
        Ok(())
    }
}

/// Human-readable label from an mDNS instance name (`frostwall-my-mac` → `my mac`).
pub fn display_name_from_instance(instance: &str) -> String {
    let slug = instance
        .strip_prefix("frostwall-")
        .unwrap_or(instance)
        .replace('-', " ");
    if slug.is_empty() {
        instance.to_string()
    } else {
        slug
    }
}

/// Browse the LAN for Frostwall hosts for up to `timeout`.
/// `keep` returning false ends the wait early (Cancel bumps `session_epoch`
/// while this runs on `spawn_blocking`).
pub fn browse_peers_while(
    timeout: Duration,
    keep: impl Fn() -> bool,
) -> Result<Vec<(String, IpAddr, u16)>> {
    use std::time::Instant;
    let disc = Discovery::new()?;
    let recv = disc.browse()?;
    let deadline = Instant::now() + timeout;
    let mut peers: HashMap<String, (String, IpAddr, u16)> = HashMap::new();
    while Instant::now() < deadline {
        if !keep() {
            break;
        }
        if let Ok(ServiceEvent::ServiceResolved(info)) =
            recv.recv_timeout(Duration::from_millis(200))
        {
            let ips = info.get_addresses().iter().map(|a| a.to_ip_addr());
            if let Some(ip) = pick_browse_ip(ips) {
                let instance = info
                    .get_fullname()
                    .split('.')
                    .next()
                    .unwrap_or("frostwall")
                    .to_string();
                let display = display_name_from_instance(&instance);
                peers.insert(
                    info.get_fullname().to_string(),
                    (display, ip, info.get_port()),
                );
            }
        }
    }
    let _ = disc.shutdown();
    Ok(peers.into_values().collect())
}

/// Best-effort primary LAN IPv4 of this host, found by opening a UDP socket
/// toward a public address (no packets are sent) and reading the bound local
/// address — this reveals the interface that would be used for outbound traffic.
pub fn local_lan_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(sa) => Some(*sa.ip()),
        std::net::SocketAddr::V6(_) => None,
    }
}

fn local_lan_ipv6() -> Option<Ipv6Addr> {
    let sock = UdpSocket::bind("[::]:0").ok()?;
    sock.connect("[2001:4860:4860::8888]:80").ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V6(sa) => Some(*sa.ip()),
        std::net::SocketAddr::V4(_) => None,
    }
}

fn lan_bindable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_unspecified() && !v.is_loopback() && !v.is_multicast() && !v.is_broadcast()
        }
        IpAddr::V6(v) => !v.is_unspecified() && !v.is_loopback() && !v.is_multicast(),
    }
}

/// IPv4 preferred; IPv6 when this host has no usable v4 (IPv6-only LAN).
pub fn local_lan_ip() -> Option<IpAddr> {
    if let Some(v4) = local_lan_ipv4() {
        let ip = IpAddr::V4(v4);
        if lan_bindable(&ip) {
            return Some(ip);
        }
    }
    local_lan_ipv6().map(IpAddr::V6).filter(lan_bindable)
}

/// Prefer IPv4 from an mDNS record, then IPv6. Skip loopback / unspecified.
fn pick_browse_ip(addrs: impl IntoIterator<Item = IpAddr>) -> Option<IpAddr> {
    let mut v6 = None;
    for ip in addrs {
        if !lan_bindable(&ip) {
            continue;
        }
        if ip.is_ipv4() {
            return Some(ip);
        }
        if v6.is_none() {
            v6 = Some(ip);
        }
    }
    v6
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn starts_and_shuts_down() {
        let d = Discovery::new().unwrap();
        d.shutdown().unwrap();
    }

    #[test]
    #[ignore = "requires working mDNS multicast; flaky in CI/sandbox"]
    fn browse_finds_advertised_service() {
        let mut adv = Discovery::new().unwrap();
        let brw = Discovery::new().unwrap();

        let port = 45123u16;
        let ip = local_lan_ip().unwrap_or_else(|| "127.0.0.1".parse().unwrap());
        adv.advertise("kopru-unit-test", ip, port).unwrap();

        let recv = brw.browse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut found = false;
        while Instant::now() < deadline {
            if let Ok(ServiceEvent::ServiceResolved(info)) =
                recv.recv_timeout(Duration::from_millis(250))
            {
                if info.get_port() == port && info.get_fullname().contains("kopru-unit-test") {
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "browser should resolve the advertised service");

        let _ = adv.shutdown();
        let _ = brw.shutdown();
    }

    #[test]
    fn display_name_from_instance_slug() {
        assert_eq!(display_name_from_instance("frostwall-mac-mini"), "mac mini");
        assert_eq!(display_name_from_instance("other"), "other");
    }

    #[test]
    fn local_lan_ipv4_does_not_panic() {
        let _ = local_lan_ipv4();
    }

    #[test]
    fn local_lan_ip_does_not_panic() {
        let _ = local_lan_ip();
    }

    #[test]
    fn pick_browse_ip_prefers_v4_then_v6() {
        let v4: IpAddr = "192.168.1.9".parse().unwrap();
        let v6: IpAddr = "fd00::9".parse().unwrap();
        let lo4: IpAddr = "127.0.0.1".parse().unwrap();
        let lo6: IpAddr = "::1".parse().unwrap();
        assert_eq!(pick_browse_ip([v6, v4]), Some(v4));
        assert_eq!(pick_browse_ip([v6]), Some(v6));
        assert!(pick_browse_ip([lo4, lo6]).is_none());
        assert_eq!(pick_browse_ip([lo6, v6]), Some(v6));
    }

    #[test]
    fn browse_peers_while_stops_when_keep_false() {
        let start = Instant::now();
        let peers = browse_peers_while(Duration::from_secs(5), || false).unwrap();
        assert!(peers.is_empty());
        assert!(
            start.elapsed() < Duration::from_millis(800),
            "cancelled browse must not sit on the 5s timeout"
        );
    }
}
