//! Subscription fetching.
//!
//! Delegates HTTPS to the `curl` that OpenWrt already ships. That keeps a TLS
//! stack, its certificate handling and a C toolchain out of this binary --
//! which is what lets the whole project cross-compile with nothing but
//! `cargo build --target armv7-unknown-linux-musleabihf`.

use std::process::{Command, Stdio};

/// Sent as User-Agent. Most panels (Marzban, X-UI, Hiddify) branch on this and
/// only return a plain base64 node list for a known client.
const USER_AGENT: &str = "v2rayNG/1.9.5";

/// Refuse anything larger; a subscription is a text file, and this bounds how
/// much of the router's RAM a hostile or broken endpoint can consume.
const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Fetches `url` and returns the body as text.
///
/// Only http and https are permitted -- both checked here and enforced on curl
/// via `--proto`, so a `file://` or `scp://` URL cannot be used to read local
/// files. The URL is passed as an argv entry, never through a shell.
pub fn fetch(url: &str, timeout_secs: u32) -> Result<String, String> {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return Err("subscription URL must start with http:// or https://".into());
    }
    // `-` would be read by curl as an option even after the scheme check.
    if url.starts_with('-') {
        return Err("invalid subscription URL".into());
    }
    // This runs as root from inside the LAN, so an unrestricted fetcher is an
    // SSRF primitive: it can reach the router's own admin interfaces and any
    // LAN host. Loopback and link-local are never legitimate subscription
    // hosts, so they are refused outright. Other private ranges are allowed
    // because self-hosting a subscription on the LAN is a real thing people do.
    if let Some(host) = host_of(url) {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if ip.is_loopback() || is_link_local(&ip) || ip.is_unspecified() {
                return Err("subscription URL may not point at the router itself".into());
            }
        } else if host.eq_ignore_ascii_case("localhost") {
            return Err("subscription URL may not point at the router itself".into());
        }
    }

    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--location",
            "--fail",
            "--proto",
            "=http,https",
            "--proto-redir",
            "=http,https",
            "--max-redirs",
            "5",
            "--max-time",
            &timeout_secs.to_string(),
            "--max-filesize",
            &MAX_BYTES.to_string(),
            "--user-agent",
            USER_AGENT,
        ])
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "curl is not installed".to_string(),
            _ => format!("cannot run curl: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        let code = output.status.code().unwrap_or(-1);
        return Err(if detail.is_empty() {
            format!("fetch failed (curl exit {code})")
        } else {
            // curl prefixes its own messages; strip the noise for the panel.
            detail.replace("curl: ", "").trim().to_string()
        });
    }

    // Subscriptions are ASCII base64 or ASCII URIs, so a lossy conversion can
    // only affect content that was already unusable.
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Host portion of a URL, without userinfo, port, or brackets.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    // Strip any user:pass@ prefix.
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split_once(']').map(|(h, _)| h.to_string());
    }
    Some(
        authority
            .rsplit_once(':')
            .map(|(h, p)| if p.chars().all(|c| c.is_ascii_digit()) { h } else { authority })
            .unwrap_or(authority)
            .to_string(),
    )
}

/// `Ipv4Addr::is_link_local` exists but the v6 equivalent is unstable, so both
/// are spelled out here.
fn is_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host() {
        assert_eq!(host_of("https://a.com/x?y").as_deref(), Some("a.com"));
        assert_eq!(host_of("http://a.com:8080/x").as_deref(), Some("a.com"));
        assert_eq!(host_of("http://u:p@a.com/x").as_deref(), Some("a.com"));
        assert_eq!(host_of("http://[::1]:80/x").as_deref(), Some("::1"));
        assert_eq!(host_of("http://127.0.0.1").as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn refuses_to_fetch_the_router_itself() {
        for url in [
            "http://127.0.0.1/cgi-bin/luci",
            "http://127.0.0.1:8088/api/state",
            "http://localhost/x",
            "http://[::1]/x",
            "http://0.0.0.0/x",
            "http://169.254.169.254/latest/meta-data",
        ] {
            let err = fetch(url, 5).unwrap_err();
            assert!(err.contains("router itself"), "{url} gave: {err}");
        }
    }

    #[test]
    fn rejects_non_http_schemes() {
        for url in [
            "file:///etc/shadow",
            "scp://host/file",
            "ftp://host/f",
            "/etc/passwd",
        ] {
            assert!(fetch(url, 5).is_err(), "{url} should be rejected");
        }
    }

    #[test]
    fn rejects_option_lookalike() {
        assert!(fetch("-o/tmp/pwned", 5).is_err());
    }
}
