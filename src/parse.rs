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
    if let Some(rest) = uri.strip_prefix("vmess://") {
        return parse_vmess(uri, rest);
    }
    if let Some(rest) = uri.strip_prefix("trojan://") {
        return parse_trojan(uri, rest);
    }
    if let Some(rest) = uri.strip_prefix("ss://") {
        return parse_ss(uri, rest);
    }
    for p in ["hysteria2://", "hy2://"] {
        if let Some(rest) = uri.strip_prefix(p) {
            return parse_hysteria2(uri, rest);
        }
    }
    if let Some(rest) = uri.strip_prefix("wireguard://") {
        return parse_wireguard(uri, rest);
    }
    for p in ["socks5://", "socks://"] {
        if let Some(rest) = uri.strip_prefix(p) {
            return parse_socks(uri, rest);
        }
    }
    parse_vless(uri)
}

/// Every scheme [`parse_uri`] understands, for the subscription splitter.
///
/// Everything here runs on the Xray core the router already has. TUIC and
/// Hysteria v1 are deliberately absent: Xray has no TUIC outbound at all, and
/// rejects Hysteria unless the version is 2. Supporting them would mean
/// shipping a second core, which on this hardware costs more memory than the
/// whole rest of the stack.
pub const SCHEMES: &[&str] = &[
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
    "wireguard://",
    "socks5://",
    "socks://",
];

fn parse_vless(uri: &str) -> Result<Node, String> {
    let body = uri
        .strip_prefix("vless://")
        .ok_or_else(|| "not a supported share link".to_string())?;

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
    apply_stream_params(&mut node, &q);

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// Applies the transport and TLS query parameters shared by every scheme that
/// carries them: VLESS, the standard VMess URI form, and Trojan.
fn apply_stream_params(node: &mut Node, q: &Query) {
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
    node.authority = q.get("authority");
    node.xhttp_extra = q.get("extra");
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
}

/// `trojan://<password>@<host>:<port>?<query>#<remark>`
///
/// The password comes from the userinfo, so it is percent-decoded: a link with
/// `@` or `:` in the password must escape them, and a provider that did not is
/// simply broken.
fn parse_trojan(uri: &str, rest: &str) -> Result<Node, String> {
    let (authority, query, fragment) = split_link(rest);
    let (password, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "missing '@' between password and host".to_string())?;
    if password.is_empty() {
        return Err("empty trojan password".into());
    }
    let (server, port) = split_host_port(hostport)?;
    let q = Query::parse(query);

    let mut node = Node {
        protocol: "trojan".into(),
        server,
        port,
        password: decode(password),
        raw: uri.to_string(),
        ..Default::default()
    };
    node.name = remark(fragment, &node);
    apply_stream_params(&mut node, &q);
    // Trojan is TLS by definition; a link with no query at all still means it.
    if query.is_empty() {
        node.security = "tls".into();
    }
    // Never carried over: Xray answers any non-empty Trojan flow with
    // PrintRemovedFeatureError, and links in the wild do set it.
    node.flow = String::new();

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// `vmess://` in either shape.
///
/// The base64-JSON blob is the original and still the common one; the standard
/// URI form looks like a VLESS link. v2rayNG picks between them by testing for
/// `?` *and* `&`, which sends a single-parameter standard link down the base64
/// path where it fails. Dispatching on `@` in the body has no such hole.
fn parse_vmess(uri: &str, rest: &str) -> Result<Node, String> {
    let head = rest.split(['?', '#']).next().unwrap_or("");
    if head.contains('@') {
        return parse_vmess_uri(uri, rest);
    }
    parse_vmess_json(uri, rest)
}

fn parse_vmess_uri(uri: &str, rest: &str) -> Result<Node, String> {
    let (authority, query, fragment) = split_link(rest);
    let (uuid, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "missing '@' between id and host".to_string())?;
    let (server, port) = split_host_port(hostport)?;
    let q = Query::parse(query);

    let mut node = Node {
        protocol: "vmess".into(),
        server,
        port,
        uuid: decode(uuid),
        // The standard form has no way to name a cipher.
        method: "auto".into(),
        raw: uri.to_string(),
        ..Default::default()
    };
    node.name = remark(fragment, &node);
    apply_stream_params(&mut node, &q);

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// `vmess://` + base64 of a flat JSON object.
///
/// Its keys are terse and several are overloaded by transport: `type` is the
/// TCP header type but the gRPC mode, `host` is the Host header but the gRPC
/// authority, `path` is the path but the gRPC service name.
fn parse_vmess_json(uri: &str, rest: &str) -> Result<Node, String> {
    let text = decode_base64(rest).ok_or("vmess link is not valid base64")?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("vmess payload is not JSON: {e}"))?;

    // Every field is a string in this format, including the numeric ones.
    let s = |k: &str| -> String {
        match &v[k] {
            serde_json::Value::String(x) => x.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => String::new(),
        }
    };

    let server = s("add");
    if server.is_empty() {
        return Err("vmess link has no address".into());
    }
    let port: u16 = s("port")
        .parse()
        .map_err(|_| format!("vmess port \"{}\" is not a number", s("port")))?;
    if port == 0 {
        return Err("vmess port is zero".into());
    }
    let uuid = s("id");
    if uuid.is_empty() {
        return Err("vmess link has no id".into());
    }
    // AlterId was removed from Xray entirely. A legacy server imports cleanly,
    // produces a config Xray loads without complaint -- unknown keys are
    // dropped -- and then never completes a handshake. Saying so here is the
    // only place it can be explained.
    let aid = s("aid");
    if !aid.is_empty() && aid != "0" {
        return Err(format!(
            "this server uses alterId {aid}, which Xray removed; ask the provider for an AEAD (alterId 0) link"
        ));
    }

    let network = match s("net").as_str() {
        "" | "raw" => "tcp".to_string(),
        "splithttp" => "xhttp".to_string(),
        other => other.to_string(),
    };
    let mut node = Node {
        protocol: "vmess".into(),
        server,
        port,
        uuid,
        method: {
            let m = s("scy");
            if m.is_empty() { "auto".into() } else { m }
        },
        security: {
            let t = s("tls");
            if t.is_empty() { "none".into() } else { t }
        },
        sni: s("sni"),
        fingerprint: s("fp"),
        alpn: s("alpn"),
        allow_insecure: matches!(s("insecure").as_str(), "1" | "true"),
        verify_peer_cert_by_name: s("vcn"),
        pinned_peer_cert_sha256: s("pcs"),
        raw: uri.to_string(),
        ..Default::default()
    };

    // `type`, `host` and `path` each mean something different per transport.
    match network.as_str() {
        "grpc" => {
            node.mode = s("type");
            node.service_name = s("path");
            node.host = s("host");
        }
        "tcp" => {
            node.header_type = s("type");
            node.host = s("host");
            node.path = s("path");
        }
        _ => {
            node.host = s("host");
            node.path = s("path");
        }
    }
    node.network = network;
    node.name = {
        let n = s("ps");
        if n.trim().is_empty() {
            node.endpoint()
        } else {
            n.trim().to_string()
        }
    };

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// `ss://` in both the SIP002 and the older all-base64 shape.
fn parse_ss(uri: &str, rest: &str) -> Result<Node, String> {
    let (authority, query, fragment) = split_link(rest);

    // SIP002 keeps the host in the clear: `ss://<userinfo>@host:port`.
    // The legacy form base64s the whole thing, so it has no bare '@'.
    let (method, password, server, port) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => {
            let (server, port) = split_host_port(hostport)?;
            let creds = decode(userinfo);
            // Either plaintext `method:password`, or base64 of the same.
            let creds = if creds.contains(':') {
                creds
            } else {
                decode_base64(&creds).ok_or("shadowsocks credentials are neither plain nor base64")?
            };
            let (m, p) = creds
                .split_once(':')
                .ok_or("shadowsocks credentials are not method:password")?;
            (m.to_string(), p.to_string(), server, port)
        }
        None => {
            // Legacy: base64(method:password@host:port)
            let text = decode_base64(authority).ok_or("shadowsocks link is not valid base64")?;
            let (creds, hostport) = text
                .rsplit_once('@')
                .ok_or("shadowsocks link has no '@' after decoding")?;
            let (m, p) = creds
                .split_once(':')
                .ok_or("shadowsocks credentials are not method:password")?;
            let (server, port) = split_host_port(hostport)?;
            (m.to_string(), p.to_string(), server, port)
        }
    };

    let mut node = Node {
        protocol: "shadowsocks".into(),
        server,
        port,
        // Lowercased for the AEAD names, which Xray matches case-insensitively.
        // The 2022 names are matched exactly, and are lower-case already.
        method: method.trim().to_ascii_lowercase(),
        password,
        network: "tcp".into(),
        security: "none".into(),
        raw: uri.to_string(),
        ..Default::default()
    };
    node.name = remark(fragment, &node);

    // The one plugin worth honouring: simple-obfs in http mode is just the
    // TCP HTTP disguise under another name. Anything else changes the wire
    // format in a way Xray cannot reproduce, so it is refused rather than
    // imported as a server that will never connect.
    let plugin = Query::parse(query).get("plugin");
    if !plugin.is_empty() {
        let mut opts = plugin.split(';');
        let name = opts.next().unwrap_or("");
        let kv = |want: &str| -> String {
            plugin
                .split(';')
                .filter_map(|p| p.split_once('='))
                .find(|(k, _)| *k == want)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        };
        let obfs = kv("obfs");
        if (name.contains("obfs") || name.contains("simple-obfs")) && obfs == "http" {
            node.header_type = "http".into();
            node.host = kv("obfs-host");
            node.path = kv("path");
        } else {
            return Err(format!(
                "the \"{name}\" plugin is not supported; Xray cannot reproduce its wire format"
            ));
        }
    }

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// `hysteria2://<password>@<host>:<port>?<query>#<remark>`
///
/// QUIC-only, and TLS is not optional -- Xray's dialer refuses to start
/// without it. The password does not live in `settings` like every other
/// protocol's does; it goes in `hysteriaSettings.auth`.
fn parse_hysteria2(uri: &str, rest: &str) -> Result<Node, String> {
    let (authority, query, fragment) = split_link(rest);
    let (password, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "missing '@' between password and host".to_string())?;
    let (server, port) = split_host_port(hostport)?;
    let q = Query::parse(query);

    let mut node = Node {
        protocol: "hysteria2".into(),
        server,
        port,
        password: decode(password),
        network: "hysteria".into(),
        security: "tls".into(),
        sni: q.get("sni"),
        fingerprint: q.get("fp"),
        // Forced, not taken from the link: Xray runs Hysteria2 over HTTP/3 and
        // any other ALPN is a handshake that cannot succeed.
        alpn: "h3".into(),
        obfs: q.get("obfs"),
        obfs_password: q.get("obfs-password"),
        port_hopping: q.get("mport"),
        pinned_peer_cert_sha256: q.get("pinSHA256"),
        raw: uri.to_string(),
        ..Default::default()
    };
    node.allow_insecure = matches!(q.get("insecure").as_str(), "1" | "true");
    node.name = remark(fragment, &node);

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// `wireguard://<secretKey>@<host>:<port>?publickey=..&address=..#<remark>`
///
/// There is no transport and no TLS here; WireGuard is its own thing. What
/// does still apply is `sockopt`, which is how the tunnel's own packets carry
/// our mark and escape interception.
fn parse_wireguard(uri: &str, rest: &str) -> Result<Node, String> {
    let (authority, query, fragment) = split_link(rest);
    let (secret, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| "missing '@' between key and endpoint".to_string())?;
    let (server, port) = split_host_port(hostport)?;
    let q = Query::parse(query);

    let mut node = Node {
        protocol: "wireguard".into(),
        server,
        port,
        secret_key: decode(secret),
        // Query keys are all-lowercase in this scheme, unlike every other.
        peer_public_key: q.get("publickey"),
        pre_shared_key: q.get("presharedkey"),
        local_address: q.get("address"),
        reserved: q.get("reserved"),
        mtu: q.get("mtu").parse().unwrap_or(0),
        network: String::new(),
        security: "none".into(),
        raw: uri.to_string(),
        ..Default::default()
    };
    node.name = remark(fragment, &node);

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// `socks://[<userinfo>@]<host>:<port>#<remark>`
///
/// No encryption of any kind, so this is only useful for chaining to something
/// already on the local network. `socks4://` is deliberately not accepted:
/// Xray's client always speaks SOCKS5, so importing one would be a promise the
/// core cannot keep.
fn parse_socks(uri: &str, rest: &str) -> Result<Node, String> {
    let (authority, _query, fragment) = split_link(rest);
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (u, h),
        None => ("", authority),
    };
    let (server, port) = split_host_port(hostport)?;

    let (username, password) = if userinfo.is_empty() {
        (String::new(), String::new())
    } else {
        let creds = decode(userinfo);
        // Either plaintext `user:pass`, or base64 of the same.
        let creds = if creds.contains(':') {
            creds
        } else {
            decode_base64(&creds).unwrap_or(creds)
        };
        match creds.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (creds, String::new()),
        }
    };

    let mut node = Node {
        protocol: "socks".into(),
        server,
        port,
        username,
        password,
        network: "tcp".into(),
        security: "none".into(),
        raw: uri.to_string(),
        ..Default::default()
    };
    node.name = remark(fragment, &node);

    validate(&node)?;
    node.id = node.compute_id();
    Ok(node)
}

/// Splits `<authority>[?query][#fragment]`, fragment first so a remark may
/// legitimately contain `?` or `@`.
fn split_link(rest: &str) -> (&str, &str, &str) {
    let (body, fragment) = match rest.find('#') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let (authority, query) = match body.find('?') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => (body, ""),
    };
    (authority, query, fragment)
}

/// The display name, falling back to `host:port` rather than to the literal
/// string "none" that most clients substitute.
fn remark(fragment: &str, node: &Node) -> String {
    let n = decode(fragment);
    if n.trim().is_empty() {
        node.endpoint()
    } else {
        n.trim().to_string()
    }
}

/// Decodes base64 in any of the four alphabets, padded or not.
fn decode_base64(s: &str) -> Option<String> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    for engine in [
        &STANDARD as &dyn EngineDyn,
        &STANDARD_NO_PAD,
        &URL_SAFE,
        &URL_SAFE_NO_PAD,
    ] {
        if let Some(text) = engine.try_decode(&compact) {
            return Some(text);
        }
    }
    None
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
    // Two protocols do not use the stream transports at all, so the checks
    // below do not apply to them.
    if node.protocol == "wireguard" {
        if node.secret_key.is_empty() {
            return Err("wireguard link has no private key".into());
        }
        if node.peer_public_key.is_empty() {
            return Err("wireguard link has no publickey for the peer".into());
        }
        // Xray takes 64-char hex, standard base64 or base64url, padded or not.
        for (what, key) in [
            ("private key", &node.secret_key),
            ("publickey", &node.peer_public_key),
        ] {
            if !is_wg_key(key) {
                return Err(format!("wireguard {what} is not a 32-byte key"));
            }
        }
        let n = node.reserved.split(',').filter(|p| !p.trim().is_empty()).count();
        if n != 0 && n != 3 {
            return Err("wireguard reserved must be exactly three numbers".into());
        }
        return Ok(());
    }
    if node.protocol == "hysteria2" {
        if node.password.is_empty() {
            return Err("hysteria2 link has no password".into());
        }
        if !node.obfs.is_empty() && node.obfs != "salamander" {
            return Err(format!(
                "hysteria2 obfuscation \"{}\" is not one Xray implements; only salamander is",
                node.obfs
            ));
        }
        return Ok(());
    }
    if node.protocol == "socks" {
        // A username with no password is meaningless to Xray's client: it
        // sends both or neither.
        if !node.username.is_empty() && node.password.is_empty() {
            return Err("socks link has a username but no password".into());
        }
        return Ok(());
    }

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

    if node.protocol == "shadowsocks" {
        if node.password.is_empty() {
            return Err("shadowsocks link has no password".into());
        }
        // Xray dropped every stream cipher. `aes-256-cfb`, `rc4-md5` and
        // friends are still handed out by old panels, and a server using one
        // cannot be reached at all -- Xray answers with "unknown cipher
        // method" and refuses to start, taking every other node with it.
        const AEAD: &[&str] = &[
            "aes-128-gcm",
            "aead_aes_128_gcm",
            "aes-256-gcm",
            "aead_aes_256_gcm",
            "chacha20-poly1305",
            "aead_chacha20_poly1305",
            "chacha20-ietf-poly1305",
            "xchacha20-poly1305",
            "aead_xchacha20_poly1305",
            "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ];
        if !AEAD.contains(&node.method.as_str()) {
            return Err(format!(
                "Xray does not support the \"{}\" cipher; it needs an AEAD or 2022-blake3 method",
                node.method
            ));
        }
    }

    if node.protocol == "trojan" && node.password.is_empty() {
        return Err("trojan link has no password".into());
    }

    if node.protocol == "vmess" && node.uuid.is_empty() {
        return Err("vmess link has no id".into());
    }

    Ok(())
}

/// Whether a string is a 32-byte WireGuard key in any form Xray accepts.
fn is_wg_key(s: &str) -> bool {
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    decode_base64(s).map(|_| ()).is_some()
        && s.trim_end_matches('=').len() == 43
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '='))
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
        if !SCHEMES.iter().any(|s| line.starts_with(s)) {
            // Protocols we do not speak yet -- hysteria2, wireguard, socks.
            // Counted rather than raised, so a mixed subscription reports
            // "12 imported, 5 unsupported" instead of five errors.
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

    fn b64(s: &str) -> String {
        use base64::Engine;
        STANDARD.encode(s)
    }

    #[test]
    fn parses_a_trojan_link() {
        let n = parse_uri(
            "trojan://p%40ssw0rd%3Ax@t.example.com:443?security=tls&sni=t.example.com\
             &type=ws&path=%2Ftj&host=t.example.com#Trojan%20HK",
        )
        .unwrap();
        assert_eq!(n.protocol, "trojan");
        assert_eq!(n.password, "p@ssw0rd:x", "userinfo is percent-decoded");
        assert_eq!(n.network, "ws");
        assert_eq!(n.security, "tls");
        assert_eq!(n.name, "Trojan HK");
    }

    /// Trojan is TLS by definition, and a link with no query at all still is.
    #[test]
    fn a_bare_trojan_link_is_still_tls() {
        let n = parse_uri("trojan://pw@t.example.com:443#x").unwrap();
        assert_eq!(n.security, "tls");
    }

    /// Xray answers a non-empty Trojan flow with a removed-feature error and
    /// refuses to start. Links in the wild set it anyway.
    #[test]
    fn a_trojan_flow_is_dropped_rather_than_passed_on() {
        let n = parse_uri("trojan://pw@t.com:443?flow=xtls-rprx-vision#x").unwrap();
        assert_eq!(n.flow, "");
    }

    #[test]
    fn parses_a_vmess_json_link() {
        let payload = r#"{"v":"2","ps":"HK-01","add":"cdn.example.com","port":"443",
            "id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","aid":"0","scy":"auto","net":"ws",
            "type":"none","host":"cdn.example.com","path":"/ws","tls":"tls",
            "sni":"cdn.example.com","alpn":"h2,http/1.1","fp":"chrome"}"#;
        let n = parse_uri(&format!("vmess://{}", b64(payload))).unwrap();
        assert_eq!(n.protocol, "vmess");
        assert_eq!(n.server, "cdn.example.com");
        assert_eq!(n.port, 443);
        assert_eq!(n.method, "auto");
        assert_eq!(n.network, "ws");
        assert_eq!(n.security, "tls");
        assert_eq!(n.path, "/ws");
        assert_eq!(n.name, "HK-01");
    }

    /// AlterId was removed from Xray. A legacy server would import cleanly,
    /// produce a config Xray loads without complaint, and then never complete
    /// a handshake -- so this is the only place it can be explained.
    #[test]
    fn a_legacy_alterid_vmess_server_is_refused_with_a_reason() {
        let payload = r#"{"add":"a.com","port":"443","id":"u","aid":"64","net":"tcp"}"#;
        let e = parse_uri(&format!("vmess://{}", b64(payload))).unwrap_err();
        assert!(e.contains("alterId"), "{e}");
        let ok = r#"{"add":"a.com","port":"443","id":"u","aid":"0","net":"tcp"}"#;
        assert!(parse_uri(&format!("vmess://{}", b64(ok))).is_ok());
    }

    /// In VMess-JSON these three keys mean different things per transport.
    #[test]
    fn overloaded_vmess_keys_land_in_the_right_fields() {
        let grpc = r#"{"add":"a.com","port":"443","id":"u","net":"grpc",
                       "type":"multi","path":"GunSvc","host":"auth.example"}"#;
        let n = parse_uri(&format!("vmess://{}", b64(grpc))).unwrap();
        assert_eq!(n.service_name, "GunSvc", "path is the grpc service name");
        assert_eq!(n.mode, "multi", "type is the grpc mode");

        let tcp = r#"{"add":"a.com","port":"443","id":"u","net":"tcp",
                      "type":"http","host":"play.google.com","path":"/"}"#;
        let n = parse_uri(&format!("vmess://{}", b64(tcp))).unwrap();
        assert_eq!(n.header_type, "http", "type is the tcp header type");
        assert_eq!(n.host, "play.google.com");
    }

    /// v2rayNG picks the standard form by testing for `?` and `&`, so a
    /// single-parameter link goes down the base64 path and fails. Dispatching
    /// on `@` has no such hole.
    #[test]
    fn a_single_parameter_vmess_uri_still_parses() {
        let n = parse_uri("vmess://uuid-here@a.com:443?type=ws#One").unwrap();
        assert_eq!(n.protocol, "vmess");
        assert_eq!(n.uuid, "uuid-here");
        assert_eq!(n.network, "ws");
    }

    #[test]
    fn parses_shadowsocks_in_both_shapes() {
        // SIP002, base64 userinfo
        let n = parse_uri(&format!(
            "ss://{}@ss.example.com:8388#HK%20SS",
            b64("aes-256-gcm:my-secret")
        ))
        .unwrap();
        assert_eq!(n.protocol, "shadowsocks");
        assert_eq!(n.method, "aes-256-gcm");
        assert_eq!(n.password, "my-secret");
        assert_eq!(n.port, 8388);
        assert_eq!(n.name, "HK SS");

        // SIP002, plaintext userinfo
        let n = parse_uri("ss://chacha20-ietf-poly1305:pw@ss.example.com:8388#x").unwrap();
        assert_eq!(n.method, "chacha20-ietf-poly1305");
        assert_eq!(n.password, "pw");

        // Legacy: the whole authority is base64
        let n = parse_uri(&format!(
            "ss://{}#old",
            b64("aes-128-gcm:pw@legacy.example.com:1080")
        ))
        .unwrap();
        assert_eq!(n.server, "legacy.example.com");
        assert_eq!(n.port, 1080);
    }

    /// A password containing ':' must survive -- SS2022 keys are `iPSK:uPSK`.
    #[test]
    fn a_shadowsocks_password_may_contain_a_colon() {
        let n = parse_uri(&format!(
            "ss://{}@a.com:443#x",
            b64("2022-blake3-aes-256-gcm:aaaa:bbbb")
        ))
        .unwrap();
        assert_eq!(n.password, "aaaa:bbbb");
    }

    /// Xray dropped every stream cipher. Old panels still hand them out, and
    /// one such node would stop the core for every other node too.
    #[test]
    fn shadowsocks_stream_ciphers_are_refused_by_name() {
        for bad in ["aes-256-cfb", "rc4-md5", "none"] {
            let e = parse_uri(&format!("ss://{}@a.com:443#x", b64(&format!("{bad}:pw"))))
                .unwrap_err();
            assert!(e.contains(bad), "{bad} gave {e:?}");
        }
    }

    /// simple-obfs in http mode is the TCP disguise under another name, so it
    /// maps cleanly. The others change the wire format and cannot be honoured.
    #[test]
    fn only_the_obfs_plugin_shadowsocks_shares_with_xray_is_accepted() {
        let n = parse_uri(&format!(
            "ss://{}@a.com:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#x",
            b64("aes-128-gcm:pw")
        ))
        .unwrap();
        assert_eq!(n.header_type, "http");
        assert_eq!(n.host, "bing.com");

        let e = parse_uri(&format!(
            "ss://{}@a.com:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket#x",
            b64("aes-128-gcm:pw")
        ))
        .unwrap_err();
        assert!(e.contains("v2ray-plugin"), "{e}");
    }

    /// Two accounts on one host and port are two servers. Hashing only the
    /// uuid -- which Trojan does not have -- would collapse them.
    #[test]
    fn nodes_differing_only_by_credential_stay_distinct() {
        let a = parse_uri("trojan://one@h.com:443#a").unwrap();
        let b = parse_uri("trojan://two@h.com:443#b").unwrap();
        assert_ne!(a.id, b.id);
    }

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
                    trojan://pw@b.com:443#also-ok\n\
                    tuic://pw@c.com:443#no-xray-support\n\
                    # a comment\n\
                    vless://broken";
        let r = parse_subscription(body);
        assert_eq!(r.nodes.len(), 2, "vless and trojan both import");
        assert_eq!(r.skipped, 1, "tuic has no Xray outbound at all");
        assert_eq!(r.errors.len(), 1, "broken vless line");
        assert_eq!(r.errors[0].0, 5, "error should carry the 1-based line number");
    }
}
