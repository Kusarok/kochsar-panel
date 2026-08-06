//! DNS presets for the panel's one-click picker.

use crate::model::Settings;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Preset {
    pub key: &'static str,
    pub label: &'static str,
    pub servers: &'static [&'static str],
    /// Short hint rendered under the label in the panel.
    pub note: &'static str,
}

/// Order here is the order shown in the panel.
///
/// The Iranian resolvers are included because they are the ones that actually
/// unblock sanctioned destinations from inside Iran; the international ones are
/// for traffic that already leaves through the tunnel.
pub const PRESETS: &[Preset] = &[
    Preset {
        key: "cloudflare",
        label: "Cloudflare",
        servers: &["1.1.1.1", "1.0.0.1"],
        note: "fast, privacy-focused",
    },
    Preset {
        key: "google",
        label: "Google",
        servers: &["8.8.8.8", "8.8.4.4"],
        note: "widely reachable",
    },
    Preset {
        key: "quad9",
        label: "Quad9",
        servers: &["9.9.9.9", "149.112.112.112"],
        note: "blocks known-malicious domains",
    },
    Preset {
        key: "adguard",
        label: "AdGuard",
        servers: &["94.140.14.14", "94.140.15.15"],
        note: "filters ads and trackers",
    },
    Preset {
        key: "shecan",
        label: "Shecan",
        servers: &["178.22.122.100", "185.51.200.2"],
        note: "Iran — unblocks sanctioned sites",
    },
    Preset {
        key: "electro",
        label: "Electro",
        servers: &["78.157.42.100", "78.157.42.101"],
        note: "Iran — unblocks sanctioned sites",
    },
    Preset {
        key: "begzar",
        label: "Begzar",
        servers: &["185.55.226.26", "185.55.225.25"],
        note: "Iran — unblocks sanctioned sites",
    },
    Preset {
        key: "radar",
        label: "Radar Game",
        servers: &["10.202.10.10", "10.202.10.11"],
        note: "Iran — tuned for gaming",
    },
];

/// Destinations offered for the connection test.
///
/// Which one you pick is a real choice, not a cosmetic one: a server can reach
/// Google and still fail on Instagram, and the point of the test is to answer
/// "does this server work for the thing I actually use". Endpoints are chosen
/// to return a tiny response so the number reflects latency, not download size.
#[derive(Debug, Clone, Serialize)]
pub struct TestTarget {
    pub key: &'static str,
    pub label: &'static str,
    pub url: &'static str,
}

pub const TEST_TARGETS: &[TestTarget] = &[
    TestTarget {
        key: "google",
        label: "Google",
        // 204 with an empty body -- the standard connectivity probe.
        url: "https://www.google.com/generate_204",
    },
    TestTarget {
        key: "youtube",
        label: "YouTube",
        url: "https://www.youtube.com/generate_204",
    },
    TestTarget {
        key: "github",
        label: "GitHub",
        // A few words of plain text; the smallest thing GitHub's API serves.
        url: "https://api.github.com/zen",
    },
    TestTarget {
        key: "telegram",
        label: "Telegram",
        url: "https://api.telegram.org/",
    },
    TestTarget {
        key: "instagram",
        label: "Instagram",
        url: "https://www.instagram.com/favicon.ico",
    },
    TestTarget {
        key: "cloudflare",
        label: "Cloudflare",
        url: "https://cp.cloudflare.com/generate_204",
    },
    TestTarget {
        key: "openai",
        label: "OpenAI",
        url: "https://api.openai.com/",
    },
];

pub fn find_target(key: &str) -> Option<&'static TestTarget> {
    TEST_TARGETS.iter().find(|t| t.key == key)
}

/// The URL to test against, resolved from the settings.
///
/// Falls back to Google rather than to nothing, so a stale or misspelled
/// preset still produces a usable test instead of an error.
pub fn test_url(settings: &Settings) -> String {
    if settings.test_target == "custom" {
        let u = settings.test_url_custom.trim();
        if is_valid_test_url(u) {
            return u.to_string();
        }
    }
    find_target(&settings.test_target)
        .or_else(|| find_target("google"))
        .map(|t| t.url.to_string())
        .unwrap_or_default()
}

/// Only http(s), and never the router itself -- a test that passes because it
/// reached the local web server would be worse than no test at all.
pub fn is_valid_test_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return false;
    }
    let host = lower
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or("")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if host.is_empty() {
        return false;
    }
    let bare = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    !(bare == "localhost" || bare.starts_with("127.") || bare == "::1")
}

pub fn find(key: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.key == key)
}

/// Splits a user-entered custom DNS string into individual entries.
pub fn split_custom(raw: &str) -> Vec<String> {
    raw.split([',', '\n', ' ', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Whether Xray will accept `s` as a DNS server address.
///
/// Without this a typo is written straight into the config, Xray refuses to
/// start, and the panel reports "xray exited" with no hint as to why.
pub fn is_valid_resolver(s: &str) -> bool {
    /// Transport prefixes Xray understands for DNS servers.
    const SCHEMES: &[&str] = &[
        "https://",
        "h2c://",
        "tcp://",
        "udp://",
        "quic://",
        "https+local://",
        "tcp+local://",
        "udp+local://",
        "quic+local://",
    ];
    if SCHEMES.iter().any(|p| s.starts_with(p) && s.len() > p.len()) {
        return true;
    }
    // Xray's own keywords.
    if s == "localhost" || s == "fakedns" {
        return true;
    }

    // Bare address, optionally with a port: 1.1.1.1, 1.1.1.1:53, [::1]:53.
    let host = if let Some(rest) = s.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else if s.matches(':').count() == 1 {
        // Exactly one colon means host:port; more means a bare IPv6 literal.
        s.split(':').next().unwrap_or(s)
    } else {
        s
    };
    host.parse::<std::net::IpAddr>().is_ok()
}

/// The resolver list to hand to Xray.
///
/// Falls back to Cloudflare when the preset is unknown or a `custom` entry is
/// blank, so a bad setting degrades to working DNS instead of no DNS.
pub fn resolvers(settings: &Settings) -> Vec<String> {
    if settings.dns_preset == "custom" {
        let list = split_custom(&settings.dns_custom);
        if !list.is_empty() {
            return list;
        }
    }
    find(&settings.dns_preset)
        .or_else(|| find("cloudflare"))
        .map(|p| p.servers.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(preset: &str, custom: &str) -> Settings {
        Settings {
            dns_preset: preset.into(),
            dns_custom: custom.into(),
            ..Default::default()
        }
    }

    #[test]
    fn preset_keys_are_unique() {
        let mut keys: Vec<_> = PRESETS.iter().map(|p| p.key).collect();
        let total = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), total);
    }

    #[test]
    fn resolves_known_preset() {
        assert_eq!(resolvers(&settings("quad9", "")), ["9.9.9.9", "149.112.112.112"]);
    }

    #[test]
    fn custom_accepts_mixed_separators() {
        let got = resolvers(&settings("custom", "1.2.3.4, 5.6.7.8\n9.9.9.9"));
        assert_eq!(got, ["1.2.3.4", "5.6.7.8", "9.9.9.9"]);
    }

    #[test]
    fn blank_custom_falls_back_rather_than_breaking_dns() {
        assert_eq!(resolvers(&settings("custom", "   ")), ["1.1.1.1", "1.0.0.1"]);
    }

    #[test]
    fn unknown_preset_falls_back() {
        assert_eq!(resolvers(&settings("nope", "")), ["1.1.1.1", "1.0.0.1"]);
    }

    #[test]
    fn accepts_real_resolver_forms() {
        for ok in [
            "1.1.1.1",
            "8.8.8.8:53",
            "2606:4700:4700::1111",
            "[2606:4700:4700::1111]:53",
            "https://dns.google/dns-query",
            "tcp://9.9.9.9",
            "udp+local://223.5.5.5",
            "localhost",
            "fakedns",
        ] {
            assert!(is_valid_resolver(ok), "{ok} should be accepted");
        }
    }

    #[test]
    fn rejects_typos_that_would_stop_xray_starting() {
        for bad in [
            "hello",
            "1.1.1",
            "999.1.1.1",
            "https://",
            "",
            "1.1.1.1 8.8.8.8",
            "[::1",
        ] {
            assert!(!is_valid_resolver(bad), "{bad:?} should be rejected");
        }
    }
}
