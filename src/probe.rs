//! Name resolution helpers.
//!
//! This module used to also measure latency by timing a TCP handshake to each
//! server. That was removed rather than kept as a fallback: on a censored
//! network the hostname resolves to a nearby interception box that completes
//! the handshake instantly, so every server reported roughly 0 ms and the list
//! looked healthy while nothing worked. A test that confidently reports the
//! wrong answer is worse than no test.
//!
//! Latency now lives in [`crate::latency`], which measures a real request
//! through each server.

use std::net::{IpAddr, ToSocketAddrs};

/// Every address a hostname resolves to.
///
/// Used to bypass the proxy server in the transparent-proxy ruleset, so it must
/// return *all* addresses -- missing one leaves a path where Xray's own traffic
/// gets intercepted and the router recurses.
pub fn resolve_all(host: &str) -> Vec<IpAddr> {
    // A literal address needs no lookup, and `to_socket_addrs` on one still
    // costs a getaddrinfo round trip.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    // Port 0 is a placeholder; only the addresses matter.
    (host, 0u16)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_addresses_skip_the_resolver() {
        assert_eq!(resolve_all("1.2.3.4"), ["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(resolve_all("::1"), ["::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn localhost_resolves() {
        assert!(!resolve_all("localhost").is_empty());
    }

    #[test]
    fn an_unresolvable_name_yields_nothing_rather_than_panicking() {
        assert!(resolve_all("no-such-host.invalid").is_empty());
    }
}
