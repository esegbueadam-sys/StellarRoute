//! Trusted-proxy aware client IP resolution.
//!
//! Forwarding headers (`X-Forwarded-For`, `X-Real-IP`) are attacker-controlled
//! unless the request actually arrived from a proxy we operate. This module
//! therefore only reads them when the TCP peer address is inside the
//! `TRUSTED_PROXY_CIDRS` allowlist, and then applies the standard
//! "rightmost untrusted address" rule:
//!
//! 1. Start with the TCP peer address.
//! 2. If the peer is not trusted, stop — every forwarding header is ignored.
//! 3. Otherwise walk `X-Forwarded-For` from right to left, skipping entries
//!    that are themselves trusted proxies. The first untrusted hop is the
//!    caller.
//!
//! Walking from the right is what prevents clients from spoofing their
//! identity by prepending arbitrary values to `X-Forwarded-For`: the proxy we
//! control appends the address it observed, so anything further left is only
//! reachable after that address has been discounted.
//!
//! `TRUSTED_PROXY_CIDRS` is a comma-separated list of IP addresses or CIDR
//! ranges (IPv4 or IPv6), for example:
//!
//! ```text
//! TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128,10.0.0.0/8
//! ```
//!
//! When the variable is unset (or empty), no proxy is trusted. This is the
//! safe default: the API uses the TCP peer address and ignores forwarding
//! headers entirely. An invalid entry rejects the whole allowlist rather than
//! partially trusting it.

use axum::http::HeaderMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Environment variable holding the comma-separated trusted proxy allowlist.
pub const TRUSTED_PROXY_CIDRS_ENV: &str = "TRUSTED_PROXY_CIDRS";

/// Allowlist of reverse proxies whose forwarding headers may be trusted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxyConfig {
    cidrs: Vec<IpCidr>,
}

impl TrustedProxyConfig {
    /// Empty allowlist: no peer is a trusted proxy.
    pub fn none() -> Self {
        Self::default()
    }

    /// Parse a comma-separated CIDR list.
    ///
    /// Blank entries are ignored. An invalid address, prefix, or prefix length
    /// rejects the entire list so a typo can never widen trust.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut cidrs = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            cidrs.push(IpCidr::parse(entry)?);
        }
        Ok(Self { cidrs })
    }

    /// Load the allowlist from `TRUSTED_PROXY_CIDRS`.
    ///
    /// Invalid configuration is logged to stderr and treated as "trust no
    /// proxy" so the service keeps running with forwarding headers ignored.
    pub fn from_env() -> Self {
        match std::env::var(TRUSTED_PROXY_CIDRS_ENV) {
            Ok(raw) => match Self::parse(&raw) {
                Ok(config) => config,
                Err(err) => {
                    eprintln!(
                        "warning: ignoring {TRUSTED_PROXY_CIDRS_ENV} because it is invalid ({err}); \
                         forwarded headers will not be trusted"
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// True when no proxy is trusted, i.e. forwarding headers are ignored.
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// True when `ip` is inside one of the configured proxy ranges.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

impl fmt::Display for TrustedProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.cidrs.is_empty() {
            return f.write_str("<none>");
        }
        for (idx, cidr) in self.cidrs.iter().enumerate() {
            if idx > 0 {
                f.write_str(",")?;
            }
            write!(f, "{cidr}")?;
        }
        Ok(())
    }
}

/// Resolve the caller IP from forwarding headers and the TCP peer address.
///
/// `peer` is normally the socket address from `ConnectInfo`. When it is
/// missing (unit tests, embedded routers) the resolution falls back to
/// loopback, and because loopback is only trusted when explicitly listed, the
/// forwarding headers are still ignored by default.
pub fn resolve_client_ip(
    x_forwarded_for: Option<&str>,
    x_real_ip: Option<&str>,
    peer: Option<IpAddr>,
    config: &TrustedProxyConfig,
) -> IpAddr {
    let peer = canonical(peer.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    if !config.contains(peer) {
        return peer;
    }

    if let Some(forwarded_for) = x_forwarded_for {
        let mut client = peer;
        for hop in forwarded_for.split(',').rev() {
            let hop = hop.trim();
            // A malformed or empty hop means the chain cannot be trusted
            // beyond the last address we already accepted.
            let Ok(hop_ip) = hop.parse::<IpAddr>() else {
                break;
            };
            if !config.contains(client) {
                break;
            }
            client = canonical(hop_ip);
        }
        return client;
    }

    if let Some(real_ip) = x_real_ip.and_then(|value| value.trim().parse::<IpAddr>().ok()) {
        return canonical(real_ip);
    }

    peer
}

/// Convenience wrapper for request headers plus an optional TCP peer.
pub fn resolve_client_ip_from_headers(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    config: &TrustedProxyConfig,
) -> IpAddr {
    let x_forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    let x_real_ip = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok());

    resolve_client_ip(x_forwarded_for, x_real_ip, peer, config)
}

/// Normalize IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) to IPv4 so an
/// allowlist entry matches regardless of the socket representation.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpCidr {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

impl IpCidr {
    fn parse(raw: &str) -> Result<Self, String> {
        let (addr, prefix) = match raw.split_once('/') {
            Some((addr, prefix)) => (addr.trim(), Some(prefix.trim())),
            None => (raw, None),
        };

        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid IP address in trusted proxy entry `{raw}`"))?;

        match ip {
            IpAddr::V4(v4) => Ok(IpCidr::V4(v4, parse_prefix(prefix, 32, raw)?)),
            IpAddr::V6(v6) => Ok(IpCidr::V6(v6, parse_prefix(prefix, 128, raw)?)),
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpCidr::V4(network, prefix), IpAddr::V4(addr)) => {
                let mask = v4_mask(*prefix);
                (u32::from(*network) & mask) == (u32::from(addr) & mask)
            }
            (IpCidr::V6(network, prefix), IpAddr::V6(addr)) => {
                let mask = v6_mask(*prefix);
                (u128::from(*network) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpCidr::V4(addr, prefix) => write!(f, "{addr}/{prefix}"),
            IpCidr::V6(addr, prefix) => write!(f, "{addr}/{prefix}"),
        }
    }
}

fn parse_prefix(prefix: Option<&str>, max: u8, raw: &str) -> Result<u8, String> {
    match prefix {
        None => Ok(max),
        Some(value) => {
            let parsed = value
                .parse::<u8>()
                .map_err(|_| format!("invalid prefix length in trusted proxy entry `{raw}`"))?;
            if parsed > max {
                return Err(format!(
                    "prefix length {parsed} exceeds {max} in trusted proxy entry `{raw}`"
                ));
            }
            Ok(parsed)
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("valid test IP")
    }

    fn config(raw: &str) -> TrustedProxyConfig {
        TrustedProxyConfig::parse(raw).expect("valid trusted proxy config")
    }

    #[test]
    fn unset_allowlist_trusts_nobody() {
        let cfg = TrustedProxyConfig::none();
        assert!(cfg.is_empty());
        assert!(!cfg.contains(ip("127.0.0.1")));
        assert!(!cfg.contains(ip("10.0.0.1")));
    }

    #[test]
    fn parses_single_addresses_and_cidrs() {
        let cfg = config("127.0.0.1, 10.0.0.0/8,::1/128, 2001:db8::/32");
        assert!(cfg.contains(ip("127.0.0.1")));
        assert!(cfg.contains(ip("10.20.30.40")));
        assert!(cfg.contains(ip("::1")));
        assert!(cfg.contains(ip("2001:db8:1234::1")));
        assert!(!cfg.contains(ip("11.0.0.1")));
        assert!(!cfg.contains(ip("2001:db9::1")));
    }

    #[test]
    fn rejects_invalid_entries() {
        assert!(TrustedProxyConfig::parse("10.0.0.0/33").is_err());
        assert!(TrustedProxyConfig::parse("::1/129").is_err());
        assert!(TrustedProxyConfig::parse("not-an-ip").is_err());
        assert!(TrustedProxyConfig::parse("10.0.0.0/not-a-prefix").is_err());
    }

    #[test]
    fn empty_entries_are_ignored() {
        let cfg = config(" , 10.0.0.1, ");
        assert!(!cfg.is_empty());
        assert!(cfg.contains(ip("10.0.0.1")));
    }

    #[test]
    fn untrusted_peer_forwards_are_ignored() {
        let cfg = TrustedProxyConfig::none();
        let resolved = resolve_client_ip(
            Some("203.0.113.5"),
            Some("198.51.100.1"),
            Some(ip("192.0.2.10")),
            &cfg,
        );
        assert_eq!(resolved, ip("192.0.2.10"));
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_hop() {
        let cfg = config("10.0.0.0/8");
        let resolved = resolve_client_ip(
            Some("203.0.113.5, 10.0.0.2"),
            None,
            Some(ip("10.0.0.254")),
            &cfg,
        );
        assert_eq!(resolved, ip("203.0.113.5"));
    }

    #[test]
    fn spoofed_leftmost_value_does_not_win() {
        // Attacker sends `X-Forwarded-For: 1.2.3.4`; the trusted proxy appends
        // the address it actually observed.
        let cfg = config("10.0.0.0/8");
        let resolved = resolve_client_ip(
            Some("1.2.3.4, 203.0.113.5"),
            None,
            Some(ip("10.0.0.254")),
            &cfg,
        );
        assert_eq!(resolved, ip("203.0.113.5"));
    }

    #[test]
    fn all_trusted_hops_resolve_to_leftmost() {
        let cfg = config("10.0.0.0/8");
        let resolved = resolve_client_ip(
            Some("10.0.0.1, 10.0.0.2"),
            None,
            Some(ip("10.0.0.254")),
            &cfg,
        );
        assert_eq!(resolved, ip("10.0.0.1"));
    }

    #[test]
    fn x_real_ip_requires_trusted_peer() {
        let cfg = config("10.0.0.0/8");
        assert_eq!(
            resolve_client_ip(None, Some("203.0.113.5"), Some(ip("10.0.0.1")), &cfg),
            ip("203.0.113.5")
        );
        assert_eq!(
            resolve_client_ip(None, Some("203.0.113.5"), Some(ip("192.0.2.1")), &cfg),
            ip("192.0.2.1")
        );
    }

    #[test]
    fn malformed_forwarded_for_falls_back_to_peer() {
        let cfg = config("10.0.0.0/8");
        assert_eq!(
            resolve_client_ip(Some("not-an-ip"), None, Some(ip("10.0.0.1")), &cfg),
            ip("10.0.0.1")
        );
        assert_eq!(
            resolve_client_ip(Some(""), None, Some(ip("10.0.0.1")), &cfg),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ipv4_mapped_peer_matches_ipv4_allowlist() {
        let cfg = config("127.0.0.1/32");
        let resolved = resolve_client_ip(
            Some("203.0.113.5"),
            None,
            Some(ip("::ffff:127.0.0.1")),
            &cfg,
        );
        assert_eq!(resolved, ip("203.0.113.5"));
    }

    #[test]
    fn missing_peer_uses_loopback_and_ignores_headers_by_default() {
        let cfg = TrustedProxyConfig::none();
        assert_eq!(
            resolve_client_ip(Some("203.0.113.5"), None, None, &cfg),
            ip("127.0.0.1")
        );
    }
}
