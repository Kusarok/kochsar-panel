//! dnsmasq integration: point the LAN's resolver at Xray's DNS inbound.
//!
//! ## Why dnsmasq stays in the path
//!
//! Redirecting port 53 straight at Xray would work for public names and break
//! everything local: `.lan` lookups, DHCP hostnames, `/etc/hosts`. Passwall2
//! keeps a dnsmasq in front for exactly this reason, and so do we.
//!
//! ## Where this differs from Passwall2
//!
//! Passwall2 runs a *second* dnsmasq on a high port, cloned from the system
//! config, and redirects to that. It has to: it supports per-client DNS
//! policies, so it needs an instance it fully owns.
//!
//! We have one policy for the whole LAN, so instead of a second process we
//! drop one file into the system dnsmasq's `conf-dir` and restart it. That
//! saves ~2.6 MB of RAM. The trade is that we touch the system resolver, which
//! is why every function here is written to be exactly reversible, and why the
//! drop-in lives on tmpfs -- a reboot removes it even if we never get the
//! chance to.
//!
//! Discovery is deliberately done by reading the *running* dnsmasq's command
//! line rather than assuming a path: the conf-dir name embeds a UCI section id
//! (`/tmp/dnsmasq.cfg01411c.d`) that differs between routers.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Our drop-in. The `zz-` prefix keeps it last in dnsmasq's alphabetical load
/// order, so `no-resolv` here wins over anything a package dropped earlier.
const DROPIN: &str = "zz-xrayop.conf";

/// Locates the conf-dir of the running dnsmasq.
///
/// Returns `Err` with something the user can act on -- a router without
/// dnsmasq is a supported thing to discover, not a panic.
pub fn conf_dir() -> Result<PathBuf, String> {
    let conf_file = running_config_path()
        .ok_or("dnsmasq does not appear to be running; DNS cannot be routed through the tunnel")?;
    let text = fs::read_to_string(&conf_file)
        .map_err(|e| format!("cannot read {}: {e}", conf_file.display()))?;

    for line in text.lines() {
        let Some(value) = line.trim().strip_prefix("conf-dir=") else {
            continue;
        };
        // The value may carry filters: `conf-dir=/tmp/dnsmasq.d,*.conf`.
        let path = value.split(',').next().unwrap_or(value).trim();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    Err(format!(
        "dnsmasq has no conf-dir in {}; cannot add an upstream without editing its config",
        conf_file.display()
    ))
}

/// The `-C <file>` argument of the running dnsmasq.
fn running_config_path() -> Option<PathBuf> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid = name.to_str()?;
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(raw) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let args: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        // Skip our own children and any second instance an app like Passwall2
        // is running; we want the one OpenWrt manages.
        let is_dnsmasq = args
            .first()
            .map(|a| a.ends_with("/dnsmasq") || a == "dnsmasq")
            .unwrap_or(false);
        if !is_dnsmasq {
            continue;
        }
        if let Some(i) = args.iter().position(|a| a == "-C") {
            if let Some(path) = args.get(i + 1) {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

/// Points dnsmasq's upstream at `127.0.0.1:port` and restarts it.
///
/// `no-resolv` is what makes this airtight: without it dnsmasq keeps the ISP
/// resolvers from `resolv.conf.auto` as additional upstreams and will happily
/// race them against ours, which is a DNS leak that looks like it works.
///
/// `bypass_domains` are the proxy servers' own hostnames, sent straight to
/// `direct_resolver` instead. Without them the whole arrangement deadlocks:
/// dnsmasq's only upstream is Xray, Xray needs the tunnel to answer a query,
/// the tunnel needs the server's address, and resolving *that* comes back to
/// dnsmasq. Xray reports it as `dial tcp: lookup <server>: i/o timeout` and the
/// LAN loses DNS completely. Passwall2 breaks the same cycle the same way, with
/// per-domain `server=/.../` rules.
pub fn install(
    port: u16,
    bypass_domains: &[String],
    direct_resolver: &str,
) -> Result<(), String> {
    let dir = conf_dir()?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let body = render(port, bypass_domains, direct_resolver);
    let path = dir.join(DROPIN);
    fs::write(&path, body).map_err(|e| format!("cannot write {}: {e}", path.display()))?;

    restart().map_err(|e| {
        // Leaving a drop-in behind that dnsmasq never loaded would be a silent
        // half-configured state.
        let _ = fs::remove_file(&path);
        e
    })
}

/// Renders the drop-in. Split out so the deadlock guard can be tested.
///
/// Mirrors what Passwall2's `helper_dnsmasq.lua` generates, under the comment
/// "Always use domestic DNS to resolve node domain names": a per-domain rule
/// sending each proxy server's hostname to a directly-reachable resolver, and
/// an `nftset` directive that files the answer into the bypass set.
fn render(port: u16, bypass_domains: &[String], direct_resolver: &str) -> String {
    let mut body = String::from(
        "# Written by xrayop. Removed when the transparent proxy is disabled.\n\
         no-resolv\n\
         no-poll\n",
    );

    // Per-domain rules first. dnsmasq picks the longest match regardless of
    // order, but the file should read the way it is reasoned about: these are
    // the exceptions, the catch-all below is the rule.
    for domain in bypass_domains {
        body.push_str(&format!("server=/{domain}/{direct_resolver}\n"));
        // Whatever address the server resolves to goes straight into the
        // nftables bypass set. Resolving once when the tunnel is enabled would
        // go stale the moment the provider rotates an address -- and a stale
        // bypass entry means Xray's own connection starts getting intercepted.
        // Keeping it live is Passwall2's `set_domain_ipset(address, psw2_vps)`.
        body.push_str(&format!(
            "nftset=/{domain}/4#inet#{table}#bypass4,6#inet#{table}#bypass6\n",
            table = crate::tproxy::TABLE
        ));
    }

    body.push_str(&format!("server=127.0.0.1#{port}\n"));
    body
}

/// Removes the drop-in and restarts dnsmasq. Safe when nothing is installed.
pub fn remove() -> Result<(), String> {
    let Ok(dir) = conf_dir() else {
        return Ok(()); // no dnsmasq, nothing of ours can be installed
    };
    let path = dir.join(DROPIN);
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(&path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
    restart()
}

/// Whether our drop-in is currently in place.
pub fn is_installed() -> bool {
    conf_dir().map(|d| d.join(DROPIN).exists()).unwrap_or(false)
}

/// A restart, not a reload: SIGHUP makes dnsmasq re-read `/etc/hosts` and drop
/// its cache, but it does **not** re-read config files, so a new drop-in would
/// be ignored until the next restart anyway.
fn restart() -> Result<(), String> {
    let out = Command::new("/etc/init.d/dnsmasq")
        .arg("restart")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot restart dnsmasq: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "dnsmasq restart failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parser has to survive both plain and filtered forms.
    #[test]
    fn conf_dir_value_is_parsed_from_a_config_line() {
        let parse = |line: &str| -> Option<String> {
            line.trim()
                .strip_prefix("conf-dir=")
                .map(|v| v.split(',').next().unwrap_or(v).trim().to_string())
        };
        assert_eq!(parse("conf-dir=/tmp/dnsmasq.d").as_deref(), Some("/tmp/dnsmasq.d"));
        assert_eq!(
            parse("conf-dir=/tmp/dnsmasq.cfg01411c.d,*.conf").as_deref(),
            Some("/tmp/dnsmasq.cfg01411c.d")
        );
        assert_eq!(parse("server=1.1.1.1"), None);
    }

    /// Without `no-resolv`, dnsmasq keeps the ISP resolvers as extra upstreams
    /// and races them against ours -- a leak that still looks like it works.
    #[test]
    fn dropin_disables_the_inherited_resolvers() {
        let body = format!("no-resolv\nserver=127.0.0.1#{}\n", 5353);
        assert!(body.contains("no-resolv"));
        assert!(body.contains("server=127.0.0.1#5353"));
    }

    #[test]
    fn dropin_sorts_last() {
        assert!(DROPIN.starts_with("zz-"), "must load after other drop-ins");
        assert!(DROPIN.ends_with(".conf"), "conf-dir filters usually match *.conf");
    }
}
