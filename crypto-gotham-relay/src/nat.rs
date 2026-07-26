// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Automatic NAT traversal for home-hosted volunteer relays (UPnP-IGD).
//!
//! A relay must accept **unsolicited inbound UDP** on its advertised port: the
//! directory authority's proof-of-presence probe dials back to it, and peers
//! route packets to it. A volunteer behind a home router normally has to log
//! into the router and hand-configure a port-forward — the single biggest
//! reason volunteer relays silently fail to enrol.
//!
//! Most consumer routers speak **UPnP-IGD**. This module discovers the
//! gateway, learns the external (WAN) IP, and installs a UDP port mapping
//! (`external_port -> this_host:listen_port`), then keeps the lease alive — so
//! a volunteer behind a *single* home NAT is reachable with zero manual setup.
//!
//! What this does **not** solve: **CGNAT**. When the ISP double-NATs the
//! subscriber, the router's own WAN IP is itself private/100.64, so no local
//! port-mapping can make the host reachable. We detect that case and warn; the
//! real fix for CGNAT is the reverse/rendezvous transport (roadmap B3).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tracing::{info, warn};

/// Description tag stored in the router's port-mapping table (so a human can
/// see who opened the port).
const MAPPING_DESC: &str = "gotham-relay";

/// A successful UPnP auto-configuration.
#[derive(Debug, Clone)]
pub struct NatMapping {
    /// Public `ip:port` to advertise in the directory.
    pub external: SocketAddr,
    /// `true` when the router's WAN IP is itself private/CGNAT — the mapping
    /// was installed but the relay is still unreachable from the public
    /// internet (needs the reverse/rendezvous transport).
    pub cgnat: bool,
}

/// Error from UPnP auto-configuration.
#[derive(Debug, thiserror::Error)]
#[error("UPnP-IGD auto-configuration failed: {0}")]
pub struct NatError(String);

/// Ask the local router (UPnP-IGD) to open `listen_port`/UDP and report the
/// public address to advertise. Spawns a background task that renews the lease
/// at half its TTL (routers evict mappings at expiry).
///
/// Returns an error if no IGD gateway is discoverable on the LAN or the router
/// refuses the mapping — the caller should then fall back to a manually
/// supplied `--advertise-addr`.
pub async fn upnp_autoconfigure(listen_port: u16, lease_secs: u32) -> Result<NatMapping, NatError> {
    use igd_next::aio::tokio as igd_tokio;
    use igd_next::{PortMappingProtocol, SearchOptions};

    let gateway = igd_tokio::search_gateway(SearchOptions::default())
        .await
        .map_err(|e| NatError(format!("no UPnP-IGD gateway found on the LAN: {e}")))?;

    let external_ip = gateway
        .get_external_ip()
        .await
        .map_err(|e| NatError(format!("router did not report an external IP: {e}")))?;

    let local_ipv4 =
        primary_lan_ipv4().map_err(|e| NatError(format!("could not determine LAN IPv4: {e}")))?;
    let internal = SocketAddr::new(IpAddr::V4(local_ipv4), listen_port);

    gateway
        .add_port(
            PortMappingProtocol::UDP,
            listen_port,
            internal,
            lease_secs,
            MAPPING_DESC,
        )
        .await
        .map_err(|e| NatError(format!("router refused add_port(UDP {listen_port}): {e}")))?;

    let cgnat = is_private_or_cgnat(external_ip);
    let external = SocketAddr::new(external_ip, listen_port);
    if cgnat {
        warn!(
            %external_ip,
            "UPnP mapping installed, but the router's WAN IP is private/CGNAT — this relay will \
             NOT be reachable from the internet (the authority's probe will fail). CGNAT needs the \
             reverse/rendezvous transport."
        );
    } else {
        info!(%external, "UPnP-IGD port mapping installed — auto-advertising this address");
    }

    // Renew the lease at half-life so the mapping never lapses while we run.
    let renew_every = Duration::from_secs(((lease_secs as u64) / 2).max(60));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(renew_every).await;
            match gateway
                .add_port(
                    PortMappingProtocol::UDP,
                    listen_port,
                    internal,
                    lease_secs,
                    MAPPING_DESC,
                )
                .await
            {
                Ok(()) => info!("UPnP lease renewed"),
                Err(e) => {
                    warn!(error = %e, "UPnP lease renewal failed — relay may become unreachable")
                }
            }
        }
    });

    Ok(NatMapping { external, cgnat })
}

/// The LAN IPv4 this host uses to reach the internet. No packet is sent — a
/// *connected* UDP socket just makes the kernel resolve the source address it
/// would use for that route (here the router's LAN side).
fn primary_lan_ipv4() -> std::io::Result<Ipv4Addr> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    // 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed non-routable/no real
    // host, so connect() only picks a source IP and never emits traffic.
    sock.connect((Ipv4Addr::new(192, 0, 2, 1), 80))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(std::io::Error::other("host has no IPv4 LAN address")),
    }
}

/// `true` if `ip` is private, loopback, link-local, unspecified, or CGNAT
/// (100.64.0.0/10) — i.e. not publicly routable, so advertising it means the
/// relay is unreachable from the internet.
fn is_private_or_cgnat(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            v6.is_loopback()
                || v6.is_unspecified()
                || (o[0] & 0xfe) == 0xfc // unique-local fc00::/7
                || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80) // link-local fe80::/10
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn flags_private_and_cgnat_v4() {
        for ip in [
            Ipv4Addr::new(192, 168, 1, 5),
            Ipv4Addr::new(10, 0, 0, 8),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(100, 64, 0, 1),      // CGNAT low edge
            Ipv4Addr::new(100, 127, 255, 255), // CGNAT high edge
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
        ] {
            assert!(
                is_private_or_cgnat(ip.into()),
                "{ip} should be non-routable"
            );
        }
    }

    #[test]
    fn accepts_public_v4_including_cgnat_boundaries() {
        for ip in [
            Ipv4Addr::new(84, 235, 233, 41),  // a live relay
            Ipv4Addr::new(144, 24, 205, 188), // the authority
            Ipv4Addr::new(100, 63, 255, 255), // one below CGNAT
            Ipv4Addr::new(100, 128, 0, 1),    // one above CGNAT
        ] {
            assert!(!is_private_or_cgnat(ip.into()), "{ip} should be routable");
        }
    }

    #[test]
    fn flags_v6_ula_and_link_local() {
        assert!(is_private_or_cgnat(Ipv6Addr::LOCALHOST.into()));
        assert!(is_private_or_cgnat(
            "fc00::1".parse::<Ipv6Addr>().unwrap().into()
        ));
        assert!(is_private_or_cgnat(
            "fd12:3456::1".parse::<Ipv6Addr>().unwrap().into()
        ));
        assert!(is_private_or_cgnat(
            "fe80::1".parse::<Ipv6Addr>().unwrap().into()
        ));
        assert!(!is_private_or_cgnat(
            "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap().into()
        ));
    }
}
