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

#[cfg(test)]
mod tests {
    use super::*;

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
