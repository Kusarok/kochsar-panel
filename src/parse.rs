//! Parsing of `vless://` share links and subscription payloads.
//!
//! The grammar follows the XTLS share-link standard:
//!
//! ```text
//! vless://<uuid>@<host>:<port>?<query>#<remark>
//! ```
//!
//! Real-world links are messier than the spec, so the parser is deliberately
//! lenient: unknown query keys are ignored, both `allowInsecure` and `insecure`
//! are accepted, and a missing `type`/`security` falls back to the spec default
//! rather than erroring.

use crate::model::Node;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;

/// Parses one share link into a [`Node`].
///
/// Returns `Err` with a human-readable reason; callers surface these per-line
/// so one bad entry in a subscription does not discard the rest.
pub fn parse_uri(uri: &str) -> Result<Node, String> {
    let uri = uri.trim();
    let body = uri
        .strip_prefix("vless://")
        .ok_or_else(|| "not a vless:// link".to_string())?;

    // Fragment first: a remark may legitimately contain '?' or '@'.
    let (body, fragment) = match body.find('#') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => (body, ""),
    };

    let (authority, query) = match body.find('?') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => (body, ""),
    };

    // rsplit: a UUID never contains '@', but be tolerant if something else does.
    let (uuid, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "missing '@' between id and host".to_string())?;
    if uuid.is_empty() {
        return Err("empty id".into());
    }

    let (server, port) = split_host_port(hostport)?;
    let q = Query::parse(query);

    let mut node = Node {
        protocol: "vless".into(),
        server,
        port,
        uuid: decode(uuid),
        raw: uri.to_string(),
        ..Default::default()
    };

    node.name = {
        let n = decode(fragment);
        if n.trim().is_empty() {
            node.endpoint()
        } else {
            n.trim().to_string()
        }
    };

    node.encryption = q.get_or("encryption", "none");
    node.flow = q.get("flow");
    node.network = {
        // `type` is the modern key; `net` appears in older generators.
        let t = q.get("type");
        let t = if t.is_empty() { q.get("net") } else { t };
        // One spelling reaches the rest of the code. Xray accepts `raw` and
        // `tcp` as the same transport, and `splithttp` and `xhttp` likewise;
        // normalising here means every match arm and every check downstream has
        // exactly one string to consider.
        match t.as_str() {
            "" => "tcp".into(),
            "raw" => "tcp".into(),
            "splithttp" => "xhttp".into(),
            _ => t,
        }
    };
    node.security = q.get_or("security", "none");
    // Some generators only send `peer`/`host` and expect it to act as SNI.
    node.sni = {
        let s = q.get("sni");
        if s.is_empty() {
            q.get("peer")
        } else {
            s
        }
    };
    node.fingerprint = q.get("fp");
    node.alpn = q.get("alpn");
    node.public_key = q.get("pbk");
    node.short_id = q.get("sid");
    node.spider_x = q.get("spx");
    node.path = q.get("path");
    node.host = q.get("host");
    node.service_name = {
        let s = q.get("serviceName");
        if s.is_empty() {
            q.get("servicename")
        } else {
            s
        }
    };
    node.mode = q.get("mode");
    node.header_type = q.get("headerType");
    node.allow_insecure = {
        // Three spellings are in circulation; generators disagree.
        let a = ["allowInsecure", "insecure", "allow_insecure"]
            .iter()
            .map(|k| q.get(k))
            .find(|v| !v.is_empty())
            .unwrap_or_default();
        a == "1" || a.eq_ignore_ascii_case("true")
    };
    node.verify_peer_cert_by_name = q.get("vcn");
    node.pinned_peer_cert_sha256 = q.get("pcs");
    node.ech_config_list = q.get("ech");
    node.mldsa65_verify = q.get("pqv");

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// Rejects links Xray would refuse, at the moment they are imported.
///
/// Every one of these is a *hard* error inside Xray, not a warning: the config
/// fails to load and the core does not start. Because one config carries every
/// node, a single bad link takes down the whole instance -- so an unusable link
/// has to be caught here, where it can be reported against the line it came
/// from, rather than at start-up where it looks like a crash.
///
/// Line references are to Xray-core 26.x `infra/conf/`.
fn validate(node: &Node) -> Result<(), String> {
    // Removed transports. Xray answers these with PrintRemovedFeatureError.
    match node.network.as_str() {
        "h2" | "http" | "h3" => {
            return Err("the HTTP/2 transport was removed from Xray; ask the provider for a ws, grpc or xhttp link".into())
        }
        "quic" => return Err("the QUIC transport was removed from Xray".into()),
        // mKCP survives, but its `header` and `seed` -- the only reason a share
        // link ever specifies it -- do not.
        "kcp" | "mkcp" => {
            return Err("mKCP header and seed were removed from Xray, so this link cannot be used".into())
        }
        "tcp" | "ws" | "grpc" | "xhttp" | "httpupgrade" => {}
        other => return Err(format!("unknown transport \"{other}\"")),
    }

    match node.security.as_str() {
        "xtls" => return Err("legacy XTLS was removed from Xray; this link needs reality or tls".into()),
        "none" | "tls" | "reality" => {}
        other => return Err(format!("unknown security \"{other}\"")),
    }

    if node.security == "reality" {
        // "REALITY only supports RAW, XHTTP and gRPC for now."
        if !matches!(node.network.as_str(), "tcp" | "xhttp" | "grpc") {
            return Err(format!(
                "reality cannot run over {}; Xray allows only tcp, xhttp and grpc",
                node.network
            ));
        }
        if node.public_key.is_empty() {
            return Err("reality link is missing the pbk (public key) parameter".into());
        }
        // 32 bytes, unpadded base64url. A truncated key is a common copy/paste
        // failure and produces a handshake error with no useful message.
        if base64url_len(&node.public_key) != Some(32) {
            return Err("reality pbk is not a 32-byte key; the link looks truncated".into());
        }
        if node.short_id.len() > 16 || !node.short_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("reality sid must be at most 16 hex characters".into());
        }
        if !node.spider_x.is_empty() && !node.spider_x.starts_with('/') {
            return Err("reality spx must start with '/'".into());
        }
    }

    // Only these three are accepted on an outbound; anything else is refused.
    if !matches!(
        node.flow.as_str(),
        "" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
    ) {
        return Err(format!("Xray does not accept the flow \"{}\"", node.flow));
    }

    if node.network == "xhttp"
        && !matches!(
            node.mode.as_str(),
            "" | "auto" | "packet-up" | "stream-up" | "stream-one"
        )
    {
        return Err(format!("unknown xhttp mode \"{}\"", node.mode));
    }

    Ok(())
}

/// Decoded length of an unpadded base64url string, or `None` if it is not one.
fn base64url_len(s: &str) -> Option<usize> {
    let s = s.trim_end_matches('=');
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return None;
    }
    // 4 characters carry 3 bytes; a trailing group of 2 or 3 carries 1 or 2.
    match s.len() % 4 {
        0 => Some(s.len() / 4 * 3),
        2 => Some(s.len() / 4 * 3 + 1),
        3 => Some(s.len() / 4 * 3 + 2),
        _ => None, // a remainder of 1 cannot occur in valid base64
    }
}

/// Splits `host:port`, honouring the `[::1]:443` form for IPv6 literals.
fn split_host_port(s: &str) -> Result<(String, u16), String> {
    let (host, port_str) = if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| "unclosed '[' in host".to_string())?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| "missing port after IPv6 host".to_string())?;
        (host.to_string(), port)
    } else {
        let (h, p) = s
            .rsplit_once(':')
            .ok_or_else(|| "missing ':' before port".to_string())?;
        (h.to_string(), p)
    };

    if host.is_empty() {
        return Err("empty host".into());
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port {port_str:?}"))?;
    if port == 0 {
        return Err("port must not be 0".into());
    }
    Ok((host, port))
}

/// Percent-decodes, falling back to the raw text if the bytes are not UTF-8.
fn decode(s: &str) -> String {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_string())
}

/// A parsed query string. Small enough that linear lookup beats a map.
struct Query(Vec<(String, String)>);

impl Query {
    fn parse(raw: &str) -> Self {
        let mut out = Vec::new();
        for pair in raw.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            out.push((decode(k), decode(v)));
        }
        Query(out)
    }

    fn get(&self, key: &str) -> String {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    fn get_or(&self, key: &str, default: &str) -> String {
        let v = self.get(key);
        if v.is_empty() {
            default.to_string()
        } else {
            v
        }
    }
}

/// Outcome of decoding a subscription body.
pub struct SubParse {
    pub nodes: Vec<Node>,
    /// One entry per line that failed, as `(line_number, reason)`.
    pub errors: Vec<(usize, String)>,
    /// Links that parsed as neither VLESS nor a comment.
    pub skipped: usize,
}

/// Decodes a subscription body and parses every link it contains.
///
/// Accepts base64 (standard or URL-safe, padded or not) as well as plain text,
/// which is what providers actually serve in the wild.
pub fn parse_subscription(body: &str) -> SubParse {
    let text = decode_body(body);
    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    let mut skipped = 0usize;

    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if !line.starts_with("vless://") {
            // Other protocols are out of scope for now; count rather than error
            // so a mixed subscription reports "12 imported, 5 unsupported".
            skipped += 1;
            continue;
        }
        match parse_uri(line) {
            Ok(n) => nodes.push(n),
            Err(e) => errors.push((i + 1, e)),
        }
    }

    SubParse {
        nodes,
        errors,
        skipped,
    }
}

/// Returns the body as plain text, base64-decoding it first if that yields
/// something that looks like share links.
fn decode_body(body: &str) -> String {
    // Already plain? Cheapest and most common check first.
    if body.contains("://") {
        return body.to_string();
    }

    // Providers wrap base64 at 76 columns, so strip all ASCII whitespace.
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty() {
        return String::new();
    }

    for engine in [
        &STANDARD as &dyn EngineDyn,
        &STANDARD_NO_PAD,
        &URL_SAFE,
        &URL_SAFE_NO_PAD,
    ] {
        if let Some(text) = engine.try_decode(&compact) {
            if text.contains("://") {
                return text;
            }
        }
    }

    // Not base64 and not obviously links -- hand it back so the caller reports
    // "0 nodes" rather than silently succeeding.
    body.to_string()
}

/// Lets the four base64 alphabets be tried through one loop.
trait EngineDyn {
    fn try_decode(&self, s: &str) -> Option<String>;
}

impl<T: Engine> EngineDyn for T {
    fn try_decode(&self, s: &str) -> Option<String> {
        self.decode(s).ok().and_then(|b| String::from_utf8(b).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reality_tcp_link() {
        let uri = "vless://11111111-2222-3333-4444-555555555555@example.com:443\
                   ?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome\
                   &pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123abcd&spx=%2F&type=tcp&flow=xtls-rprx-vision#My%20Node";
        let n = parse_uri(uri).expect("should parse");
        assert_eq!(n.server, "example.com");
        assert_eq!(n.port, 443);
        assert_eq!(n.security, "reality");
        assert_eq!(n.sni, "www.microsoft.com");
        assert_eq!(n.public_key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(n.short_id, "0123abcd");
        assert_eq!(n.spider_x, "/");
        assert_eq!(n.flow, "xtls-rprx-vision");
        assert_eq!(n.name, "My Node");
    }

    /// A valid 32-byte REALITY key: 43 unpadded base64url characters.
    const PBK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// One config carries every node, so a link Xray refuses does not fail
    /// alone -- it stops the core and takes the whole server list with it.
    /// Catching these at import turns that into one visible error on one line.
    #[test]
    fn transports_xray_removed_are_refused_at_import() {
        for (t, expect) in [
            ("h2", "HTTP/2"),
            ("http", "HTTP/2"),
            ("quic", "QUIC"),
            ("kcp", "mKCP"),
            ("mkcp", "mKCP"),
            ("carrier-pigeon", "unknown transport"),
        ] {
            let e = parse_uri(&format!("vless://u@ex.com:443?type={t}#n")).unwrap_err();
            assert!(e.contains(expect), "type={t} gave {e:?}");
        }
    }

    #[test]
    fn legacy_xtls_and_unknown_security_are_refused() {
        assert!(parse_uri("vless://u@ex.com:443?security=xtls#n")
            .unwrap_err()
            .contains("XTLS"));
        assert!(parse_uri("vless://u@ex.com:443?security=magic#n")
            .unwrap_err()
            .contains("unknown security"));
    }

    /// Xray: "REALITY only supports RAW, XHTTP and gRPC for now."
    #[test]
    fn reality_is_refused_on_transports_it_cannot_use() {
        for t in ["ws", "httpupgrade"] {
            let e = parse_uri(&format!(
                "vless://u@ex.com:443?security=reality&type={t}&pbk={PBK}#n"
            ))
            .unwrap_err();
            assert!(e.contains("reality cannot run over"), "type={t} gave {e:?}");
        }
        for t in ["tcp", "xhttp", "grpc"] {
            assert!(
                parse_uri(&format!(
                    "vless://u@ex.com:443?security=reality&type={t}&pbk={PBK}#n"
                ))
                .is_ok(),
                "type={t} should be allowed"
            );
        }
    }

    /// A key that lost characters in a copy/paste produces a handshake failure
    /// with nothing useful in the log, which is a miserable thing to debug.
    #[test]
    fn a_truncated_reality_key_is_caught() {
        let e = parse_uri("vless://u@ex.com:443?security=reality&pbk=ABCDEF#n").unwrap_err();
        assert!(e.contains("32-byte"), "{e}");
        assert!(parse_uri(&format!("vless://u@ex.com:443?security=reality&pbk={PBK}#n")).is_ok());
    }

    #[test]
    fn reality_short_id_must_be_hex_and_spider_x_a_path() {
        let bad_sid =
            parse_uri(&format!("vless://u@e.com:443?security=reality&pbk={PBK}&sid=zzz#n"))
                .unwrap_err();
        assert!(bad_sid.contains("hex"), "{bad_sid}");
        let bad_spx =
            parse_uri(&format!("vless://u@e.com:443?security=reality&pbk={PBK}&spx=x#n"))
                .unwrap_err();
        assert!(bad_spx.contains("spx"), "{bad_spx}");
    }

    #[test]
    fn only_the_three_flows_xray_accepts_are_allowed() {
        for f in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] {
            assert!(parse_uri(&format!("vless://u@e.com:443?flow={f}#n")).is_ok(), "{f}");
        }
        // xtls-rprx-direct and friends were removed years ago but still appear.
        let e = parse_uri("vless://u@e.com:443?flow=xtls-rprx-direct#n").unwrap_err();
        assert!(e.contains("flow"), "{e}");
    }

    #[test]
    fn an_unknown_xhttp_mode_is_caught() {
        assert!(parse_uri("vless://u@e.com:443?type=xhttp&mode=stream-one#n").is_ok());
        let e = parse_uri("vless://u@e.com:443?type=xhttp&mode=turbo#n").unwrap_err();
        assert!(e.contains("xhttp mode"), "{e}");
    }

    /// Xray takes both spellings of each; carrying two through the codebase
    /// would mean every downstream match had to remember it.
    #[test]
    fn transport_aliases_are_normalised_at_the_door() {
        assert_eq!(parse_uri("vless://u@e.com:443?type=raw#n").unwrap().network, "tcp");
        assert_eq!(
            parse_uri("vless://u@e.com:443?type=splithttp#n").unwrap().network,
            "xhttp"
        );
    }

    #[test]
    fn the_replacements_for_allow_insecure_are_parsed() {
        let n = parse_uri(
            "vless://u@e.com:443?security=tls&vcn=a.com,b.com&pcs=AA:BB&ech=abc123&insecure=1#n",
        )
        .unwrap();
        assert_eq!(n.verify_peer_cert_by_name, "a.com,b.com");
        assert_eq!(n.pinned_peer_cert_sha256, "AA:BB");
        assert_eq!(n.ech_config_list, "abc123");
        assert!(n.allow_insecure, "the link's request is recorded");
    }

    /// Three spellings are in circulation and generators disagree.
    #[test]
    fn every_spelling_of_allow_insecure_is_understood() {
        for q in ["allowInsecure=1", "insecure=true", "allow_insecure=1"] {
            assert!(
                parse_uri(&format!("vless://u@e.com:443?{q}#n")).unwrap().allow_insecure,
                "{q}"
            );
        }
        assert!(!parse_uri("vless://u@e.com:443?insecure=0#n").unwrap().allow_insecure);
    }

    #[test]
    fn parses_ws_tls_link_with_encoded_path() {
        let uri = "vless://aaaa@1.2.3.4:8443?type=ws&security=tls&path=%2Fws%3Fed%3D2048\
                   &host=cdn.example.com&sni=cdn.example.com#WS";
        let n = parse_uri(uri).unwrap();
        assert_eq!(n.network, "ws");
        assert_eq!(n.path, "/ws?ed=2048");
        assert_eq!(n.host, "cdn.example.com");
    }

    #[test]
    fn handles_ipv6_literal() {
        let n = parse_uri("vless://aaaa@[2001:db8::1]:443?type=tcp#v6").unwrap();
        assert_eq!(n.server, "2001:db8::1");
        assert_eq!(n.port, 443);
    }

    #[test]
    fn defaults_network_and_security() {
        let n = parse_uri("vless://aaaa@host:443").unwrap();
        assert_eq!(n.network, "tcp");
        assert_eq!(n.security, "none");
        assert_eq!(n.name, "host:443", "blank remark should fall back to endpoint");
    }

    #[test]
    fn rejects_reality_without_pbk() {
        let err = parse_uri("vless://a@h:443?security=reality").unwrap_err();
        assert!(err.contains("pbk"), "got: {err}");
    }

    #[test]
    fn rejects_malformed_links() {
        assert!(parse_uri("vmess://whatever").is_err());
        assert!(parse_uri("vless://nohost").is_err());
        assert!(parse_uri("vless://a@host:notaport").is_err());
        assert!(parse_uri("vless://a@host:0").is_err());
    }

    #[test]
    fn id_ignores_remark_but_tracks_endpoint() {
        let a = parse_uri("vless://u@h:443?type=tcp#name-one").unwrap();
        let b = parse_uri("vless://u@h:443?type=tcp#name-two").unwrap();
        let c = parse_uri("vless://u@h:444?type=tcp#name-one").unwrap();
        assert_eq!(a.id, b.id, "renaming must not change identity");
        assert_ne!(a.id, c.id, "different port must be a different node");
    }

    #[test]
    fn decodes_base64_subscription() {
        let plain = "vless://u@a.com:443?type=tcp#A\nvless://u@b.com:443?type=tcp#B";
        let encoded = STANDARD.encode(plain);
        let r = parse_subscription(&encoded);
        assert_eq!(r.nodes.len(), 2);
        assert!(r.errors.is_empty());
    }

    #[test]
    fn decodes_wrapped_urlsafe_subscription() {
        let plain = "vless://u@a.com:443?type=tcp#A";
        let encoded = URL_SAFE_NO_PAD.encode(plain);
        let wrapped = format!("{}\n{}", &encoded[..8], &encoded[8..]);
        assert_eq!(parse_subscription(&wrapped).nodes.len(), 1);
    }

    #[test]
    fn plain_subscription_reports_unsupported_and_bad_lines() {
        let body = "vless://u@a.com:443#ok\n\
                    trojan://x@b.com:443#other\n\
                    # a comment\n\
                    vless://broken";
        let r = parse_subscription(body);
        assert_eq!(r.nodes.len(), 1);
        assert_eq!(r.skipped, 1, "trojan link");
        assert_eq!(r.errors.len(), 1, "broken vless line");
        assert_eq!(r.errors[0].0, 4, "error should carry the 1-based line number");
    }
}
