//! Reading the router's actual network layout instead of assuming it.
//!
//! Everything the firewall rules need is discoverable at runtime, and every
//! value that is guessed instead is a router this will silently not work on.
//! `br-lan` is the OpenWrt convention, not a guarantee: a guest network adds a
//! second bridge, VLANs change the name, and a device with a non-standard
//! layout would simply never be intercepted -- with no error, because the rules
//! load fine and just never match.
//!
//! Each lookup is layered: the native mechanism first, then a plainer one, then
//! a documented default. A router that answers none of them still gets a
//! working configuration, and the panel shows what was chosen.

use serde_json::Value;
use std::fs;
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// Interfaces whose traffic should be intercepted.
///
/// Everything that is up and carries an L3 device, minus whatever holds the
/// default route -- that one is the WAN, and intercepting it would mean
/// intercepting the tunnel's own egress.
///
/// Derived from the default route rather than from the name `wan`, because the
/// name is a convention too: the interface can be `wwan`, `wan6`, a modem, or
/// several of them.
pub fn lan_interfaces() -> Vec<String> {
    if let Some(found) = lan_from_ubus() {
        if !found.is_empty() {
            return found;
        }
    }
    if let Some(dev) = uci_get("network.lan.device").or_else(|| uci_get("network.lan.ifname")) {
        return vec![dev];
    }
    // Last resort. Reported by the panel so it is visible that discovery
    // failed rather than that this device happens to be conventional.
    vec!["br-lan".into()]
}

fn lan_from_ubus() -> Option<Vec<String>> {
    let out = Command::new("ubus")
        .args(["call", "network.interface", "dump"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let parsed: Value = serde_json::from_slice(&out.stdout).ok()?;
    let interfaces = parsed.get("interface")?.as_array()?;

    let mut devices = Vec::new();
    for iface in interfaces {
        if iface.get("up").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(dev) = iface.get("l3_device").and_then(Value::as_str) else {
            continue;
        };
        if dev == "lo" || dev.is_empty() {
            continue;
        }
        if carries_default_route(iface) {
            continue; // this is the WAN
        }
        if !devices.iter().any(|d| d == dev) {
            devices.push(dev.to_string());
        }
    }
    Some(devices)
}

/// Whether this interface holds a default route, in either family.
fn carries_default_route(iface: &Value) -> bool {
    let Some(routes) = iface.get("route").and_then(Value::as_array) else {
        return false;
    };
    routes.iter().any(|r| {
        let target = r.get("target").and_then(Value::as_str).unwrap_or("");
        let mask = r.get("mask").and_then(Value::as_u64).unwrap_or(1);
        mask == 0 && (target == "0.0.0.0" || target == "::")
    })
}

/// Resolvers the router itself can reach without the tunnel.
///
/// Used to answer the proxy servers' own hostnames. Taking the router's real
/// upstream rather than a fixed public address matters in two ways: it works on
/// networks where public resolvers are blocked outright, and it keeps working
/// when the ISP hands out a different one.
pub fn upstream_resolvers() -> Vec<IpAddr> {
    // OpenWrt keeps the DHCP-provided servers here; /etc/resolv.conf usually
    // just points at the local dnsmasq, which is the thing we are bypassing.
    for path in [
        "/tmp/resolv.conf.d/resolv.conf.auto",
        "/var/resolv.conf.d/resolv.conf.auto",
        "/etc/resolv.conf",
    ] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let found = parse_nameservers(&text);
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

/// Nameservers from a resolv.conf, minus loopback.
///
/// A loopback entry is the local resolver -- the one whose upstream we are
/// trying to become. Using it would be the resolution deadlock again.
fn parse_nameservers(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix("nameserver") else {
            continue;
        };
        let Ok(ip) = value.trim().parse::<IpAddr>() else {
            continue;
        };
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// Where the Xray binary actually is.
pub fn xray_binary() -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "/usr/bin/xray",
        "/usr/sbin/xray",
        "/usr/bin/xray-core",
        "/usr/libexec/xray",
    ];
    for path in CANDIDATES {
        if std::path::Path::new(path).exists() {
            return Some((*path).to_string());
        }
    }
    // A package could have put it anywhere on PATH.
    let out = Command::new("which")
        .arg("xray")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !path.is_empty()).then_some(path)
}

fn uci_get(key: &str) -> Option<String> {
    let out = Command::new("uci")
        .args(["-q", "get", key])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The WAN is identified by holding a default route, not by being called
    /// "wan" -- it can be `wwan`, a modem, or several interfaces.
    #[test]
    fn the_default_route_identifies_the_wan() {
        let wan = serde_json::json!({
            "route": [{ "target": "0.0.0.0", "mask": 0, "nexthop": "10.0.0.1" }]
        });
        let lan = serde_json::json!({
            "route": [{ "target": "192.168.1.0", "mask": 24 }]
        });
        let no_routes = serde_json::json!({});
        assert!(carries_default_route(&wan));
        assert!(!carries_default_route(&lan));
        assert!(!carries_default_route(&no_routes));
    }

    #[test]
    fn ipv6_default_route_also_marks_a_wan() {
        let wan6 = serde_json::json!({ "route": [{ "target": "::", "mask": 0 }] });
        assert!(carries_default_route(&wan6));
    }

    /// A loopback nameserver is the local resolver -- the one we are replacing.
    /// Using it as the bypass would recreate the deadlock.
    #[test]
    fn loopback_resolvers_are_not_usable_as_a_bypass() {
        let text = "search lan\nnameserver 127.0.0.1\nnameserver ::1\nnameserver 1.1.1.1\n";
        assert_eq!(parse_nameservers(text), ["1.1.1.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn nameservers_are_deduped_and_order_preserved() {
        let text = "nameserver 1.1.1.1\nnameserver 1.0.0.1\nnameserver 1.1.1.1\n";
        let got = parse_nameservers(text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_resolv_conf_with_nothing_usable_yields_nothing() {
        assert!(parse_nameservers("search lan\n# a comment\n").is_empty());
        assert!(parse_nameservers("nameserver not-an-ip\n").is_empty());
    }
}
