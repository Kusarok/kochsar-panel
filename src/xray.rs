//! Xray config generation and process supervision.

use crate::dnscfg;
use crate::model::{Node, State};
use serde_json::{json, Map, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long to watch a freshly spawned Xray before calling the start a success.
/// See [`Supervisor::wait_until_settled`].
const SETTLE: Duration = Duration::from_millis(500);
/// Poll interval within that window, so a failure is reported promptly.
const POLL: Duration = Duration::from_millis(50);
/// How much of the log the panel may read. See [`Supervisor::log_tail`].
const TAIL_BYTES: u64 = 64 * 1024;

/// Addresses that must never be tunnelled, so LAN and loopback stay reachable
/// through the proxy port. Written out literally instead of `geoip:private` so
/// the daemon does not depend on geoip.dat being installed.
const PRIVATE_NETS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// Builds a complete Xray config for the selected node.
///
/// Returns `None` when no node is selected -- the caller should stop Xray
/// rather than run it with an empty outbound list.
pub fn build_config(state: &State) -> Option<Value> {
    let s = &state.settings;
    // "off" is a first-class state, not an absence of configuration: the core
    // is stopped so that nothing this daemon does can affect connectivity.
    if !s.core_enabled() {
        return None;
    }
    let node = state.find(&state.active)?;
    let listen = if s.allow_lan { "0.0.0.0" } else { "127.0.0.1" };

    // `routeOnly` keeps the sniffed domain for routing decisions but leaves the
    // connection pointed at the address the client chose. Overriding the
    // destination instead is what breaks Tor, Apple push notifications and
    // several IoT devices -- Xray's own inbound docs call this out, and
    // Passwall2 ships route-only for the same reason.
    let sniffing = json!({
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": s.sniff_route_only
    });

    let mut inbounds = vec![
        json!({
            "tag": "socks-in",
            "listen": listen,
            "port": s.socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
            "sniffing": sniffing
        }),
        json!({
            "tag": "http-in",
            "listen": listen,
            "port": s.http_port,
            "protocol": "http",
            "settings": {},
            "sniffing": sniffing
        }),
    ];

    if s.transparent {
        // Receives whatever nftables redirects here. `followRedirect` is what
        // makes dokodemo-door read the original destination out of the socket
        // rather than using a fixed address.
        inbounds.push(json!({
            "tag": "tproxy-in",
            "listen": "0.0.0.0",
            "port": s.tproxy_port,
            "protocol": "dokodemo-door",
            "settings": { "network": "tcp,udp", "followRedirect": true },
            "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
            "sniffing": sniffing
        }));

        // dnsmasq forwards the LAN's queries here. Bound to loopback: only the
        // router's own resolver should reach it, never a LAN client directly.
        //
        // This is the piece that makes transparent proxying actually private.
        // Without it the client resolves a name *before* the tunnel sees
        // anything, so a poisoned answer sends it to the wrong address and the
        // tunnel faithfully delivers it there. By then the name is gone and the
        // proxy has only an IP to work with.
        inbounds.push(json!({
            "tag": "dns-in",
            "listen": "127.0.0.1",
            "port": s.dns_port,
            "protocol": "dokodemo-door",
            "settings": {
                // Nominal target; the `dns` outbound answers from the `dns`
                // block instead, which is what gives DoH and caching.
                "address": dnscfg::resolvers(s)
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "1.1.1.1".into()),
                "port": 53,
                "network": "tcp,udp"
            }
        }));
    }

    let mut outbounds = vec![
        build_outbound(node, s.transparent),
        json!({
            "tag": "direct",
            "protocol": "freedom",
            "settings": { "domainStrategy": "UseIP" },
            "streamSettings": { "sockopt": sockopt_mark(s.transparent) }
        }),
        json!({ "tag": "block", "protocol": "blackhole", "settings": {} }),
    ];

    let mut rules = vec![json!({
        "type": "field", "ip": PRIVATE_NETS, "outboundTag": "direct"
    })];

    if s.transparent {
        // The `dns` outbound answers queries from Xray's own DNS client, so
        // the panel's resolver choice is what actually gets used -- including
        // DoH URLs, which a plain dokodemo forward could not handle.
        outbounds.push(json!({ "tag": "dns-out", "protocol": "dns" }));
        // Must precede the private-range rule: a resolver like 10.202.10.10 is
        // inside RFC1918 and would otherwise be sent direct.
        rules.insert(
            0,
            json!({ "type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out" }),
        );
    }

    // With logging off, tell Xray not to produce lines at all rather than
    // producing them and discarding them -- formatting them costs CPU on a
    // router that has little to spare.
    let loglevel = if s.log_enabled {
        s.log_level.as_str()
    } else {
        "none"
    };

    Some(json!({
        // `access` is a separate stream from `loglevel` in Xray: without an
        // explicit "none" it keeps emitting a line per connection regardless of
        // level. On a busy LAN that is the single largest log producer.
        "log": { "loglevel": loglevel, "access": "none" },
        "dns": build_dns(state),
        "policy": build_policy(s.conn_idle_secs),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "domainStrategy": "AsIs", "rules": rules }
    }))
}

/// Connection lifetime policy.
///
/// `connIdle` is the most consequential number in this whole config once
/// transparent proxying is on. TPROXY UDP carries no close signal, so Xray
/// holds one socket per 4-tuple until this expires; at the stock 300s a single
/// torrent client creates sockets faster than they are reclaimed and the router
/// dies of fd exhaustion or OOM. This is the most-reported router failure in
/// Xray's own issue tracker (#5263, #4586, #4194), maintainer-diagnosed.
///
/// `bufferSize` is explicit because Xray's architecture-dependent default is
/// zero on ARM/MIPS but 4 KiB on ARM64. Xray documents that a value that is too
/// low can discard UDP writes when the buffer is full, wasting bandwidth. Four
/// KiB matches the ARM64 default without importing the much larger x86 cost.
fn build_policy(conn_idle_secs: u32) -> Value {
    json!({
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": conn_idle_secs,
                "uplinkOnly": 2,
                "downlinkOnly": 2,
                // Xray defaults this to zero on ARM/MIPS, unlike ARM64.  An
                // explicit small buffer avoids UDP drops on the armv7 router
                // while keeping the per-connection memory cost predictable.
                "bufferSize": 4
            }
        },
        "system": { "statsInboundUplink": false, "statsInboundDownlink": false }
    })
}

/// DNS block. The resolvers come from the panel's preset picker.
///
/// In this build the panel only serves SOCKS/HTTP inbounds, so these servers
/// resolve names for the routing engine and for the `direct` outbound -- they
/// are not yet the LAN's DNS. That happens once transparent proxying lands.
fn build_dns(state: &State) -> Value {
    let servers = dnscfg::resolvers(&state.settings);
    json!({
        "servers": servers,
        "queryStrategy": "UseIP",
        "disableFallback": false,
        "tag": "dns-out"
    })
}

/// The `sockopt` block that stamps Xray's own sockets with
/// [`crate::tproxy::XRAY_MARK`].
///
/// This is the guard that stops the tunnel eating itself: the nftables
/// `intercept` chain returns early on this mark, so Xray's connection to the
/// remote server is never re-intercepted. Only emitted in transparent mode,
/// where it is load-bearing.
fn sockopt_mark(transparent: bool) -> Value {
    if transparent {
        json!({ "mark": crate::tproxy::XRAY_MARK })
    } else {
        json!({})
    }
}

/// An outbound for the latency probe: the same server, a different tag.
///
/// It carries the same socket mark as the live outbound when the router's own
/// traffic is being tunnelled. Without it the probe's own connections would be
/// intercepted by our output chain and measured *through the active tunnel* --
/// so every server would report the latency of the one already in use, which is
/// exactly the comparison the sweep exists to avoid.
pub fn probe_outbound(node: &Node, tag: &str, marked: bool) -> Value {
    let mut stream = build_stream(node);
    if marked {
        if let Some(obj) = stream.as_object_mut() {
            obj.insert("sockopt".into(), sockopt_mark(true));
        }
    }
    json!({
        "tag": tag,
        "protocol": protocol_name(node),
        "settings": build_settings(node),
        "streamSettings": stream
    })
}

fn build_outbound(node: &Node, transparent: bool) -> Value {
    let mut stream = build_stream(node);
    if transparent {
        if let Some(obj) = stream.as_object_mut() {
            obj.insert("sockopt".into(), sockopt_mark(true));
        }
    }
    json!({
        "tag": "proxy",
        "protocol": protocol_name(node),
        "settings": build_settings(node),
        "streamSettings": stream
    })
}

/// The outbound protocol Xray should load. Anything unrecognised is treated as
/// VLESS, which is what a node parsed before `protocol` existed will be.
fn protocol_name(node: &Node) -> &str {
    match node.protocol.as_str() {
        "vmess" => "vmess",
        "trojan" => "trojan",
        "shadowsocks" => "shadowsocks",
        // Xray calls the outbound `hysteria` and takes the version as a field;
        // there is no `hysteria2` protocol name.
        "hysteria2" => "hysteria",
        "wireguard" => "wireguard",
        "socks" => "socks",
        _ => "vless",
    }
}

/// The `settings` object, whose shape is per-protocol.
///
/// VLESS and VMess address a server through `vnext` with a user account;
/// Trojan and Shadowsocks through `servers` with a password on the server
/// itself. Both forms take exactly one entry -- Xray rejects more.
///
/// `level` stays 0 on purpose. It selects the policy bucket, and only level 0
/// is defined in the config this builds, so any other value would silently
/// fall back to Xray's default 300-second idle timeout and discard the
/// `conn_idle_secs` setting. v2rayNG writes 8 here and loses exactly that.
fn build_settings(node: &Node) -> Value {
    match protocol_name(node) {
        "vmess" => json!({
            "vnext": [{
                "address": node.server,
                "port": node.port,
                "users": [{
                    "id": node.uuid,
                    "security": non_empty(&node.method, "auto"),
                    "level": 0
                }]
            }]
        }),
        "trojan" => json!({
            "servers": [{
                "address": node.server,
                "port": node.port,
                "password": node.password,
                "level": 0
                // No `flow`: Xray answers any non-empty Trojan flow with a
                // removed-feature error and refuses to start.
            }]
        }),
        "shadowsocks" => json!({
            "servers": [{
                "address": node.server,
                "port": node.port,
                "method": node.method,
                "password": node.password,
                "level": 0
            }]
        }),
        // The password is *not* here -- it lives in hysteriaSettings.auth,
        // which is the one protocol that keeps its credential in the transport.
        "hysteria" => json!({
            "address": node.server,
            "port": node.port,
            "version": 2
        }),
        "wireguard" => {
            let mut s = Map::new();
            s.insert("secretKey".into(), json!(node.secret_key));
            let addrs = csv(&node.local_address);
            s.insert(
                "address".into(),
                // Xray's own default is a bogon pair; a link that omits this
                // almost always means the usual single address.
                json!(if addrs.is_empty() {
                    vec!["172.16.0.2/32"]
                } else {
                    addrs
                }),
            );
            let mut peer = Map::new();
            peer.insert("publicKey".into(), json!(node.peer_public_key));
            peer.insert(
                "endpoint".into(),
                json!(format!("{}:{}", node.server, node.port)),
            );
            if !node.pre_shared_key.is_empty() {
                peer.insert("preSharedKey".into(), json!(node.pre_shared_key));
            }
            s.insert("peers".into(), json!([Value::Object(peer)]));
            if node.mtu > 0 {
                s.insert("mtu".into(), json!(node.mtu));
            }
            let reserved: Vec<u8> = csv(&node.reserved)
                .iter()
                .filter_map(|p| p.parse().ok())
                .collect();
            if reserved.len() == 3 {
                s.insert("reserved".into(), json!(reserved));
            }
            // Load-bearing on a router. Running as root, Xray would otherwise
            // take its kernel-TUN path: it writes 0 to rp_filter, creates a
            // real wg interface, and installs its own routes and ip rules --
            // on top of the policy routing our transparent proxy depends on.
            // The userspace netstack keeps all of that inside the process.
            s.insert("noKernelTun".into(), json!(true));
            Value::Object(s)
        }
        "socks" => {
            let mut server = Map::new();
            server.insert("address".into(), json!(node.server));
            server.insert("port".into(), json!(node.port));
            if !node.username.is_empty() {
                server.insert(
                    "users".into(),
                    json!([{ "user": node.username, "pass": node.password, "level": 0 }]),
                );
            }
            json!({ "servers": [Value::Object(server)] })
        }
        _ => json!({
            "vnext": [{
                "address": node.server,
                "port": node.port,
                "users": [build_user(node)]
            }]
        }),
    }
}

fn build_user(node: &Node) -> Value {
    let mut user = Map::new();
    user.insert("id".into(), json!(node.uuid));
    user.insert("encryption".into(), json!(non_empty(&node.encryption, "none")));
    user.insert("level".into(), json!(0));
    if !node.flow.is_empty() {
        user.insert("flow".into(), json!(node.flow));
    }
    Value::Object(user)
}

fn build_stream(node: &Node) -> Value {
    // WireGuard carries no transport and no TLS. It still gets a
    // streamSettings object, because `sockopt` lives there and the mark that
    // keeps our own packets out of the tunnel is the one thing it does need.
    if node.protocol == "wireguard" {
        return Value::Object(Map::new());
    }

    if node.protocol == "hysteria2" {
        let mut s = Map::new();
        s.insert("network".into(), json!("hysteria"));
        // Not optional: Xray's Hysteria dialer fails with "tls config is nil".
        s.insert("security".into(), json!("tls"));
        s.insert(
            "hysteriaSettings".into(),
            json!({ "version": 2, "auth": node.password }),
        );
        let mut t = Map::new();
        t.insert("serverName".into(), json!(server_name(node)));
        t.insert("alpn".into(), json!(["h3"]));
        if !node.fingerprint.is_empty() {
            t.insert("fingerprint".into(), json!(node.fingerprint));
        }
        if !node.pinned_peer_cert_sha256.is_empty() {
            t.insert(
                "pinnedPeerCertSha256".into(),
                json!(csv(&node.pinned_peer_cert_sha256)),
            );
        }
        s.insert("tlsSettings".into(), Value::Object(t));

        // Obfuscation and port hopping are not settings of the transport; Xray
        // puts both under finalmask, and the deprecated in-transport spellings
        // are ignored with only a warning.
        let mut mask = Map::new();
        if node.obfs == "salamander" && !node.obfs_password.is_empty() {
            mask.insert(
                "udp".into(),
                json!([{ "type": "salamander",
                         "settings": { "password": node.obfs_password } }]),
            );
        }
        if !node.port_hopping.is_empty() {
            mask.insert(
                "quicParams".into(),
                json!({ "udpHop": { "ports": node.port_hopping, "interval": "30" } }),
            );
        }
        if !mask.is_empty() {
            s.insert("finalmask".into(), Value::Object(mask));
        }
        return Value::Object(s);
    }

    let mut stream = Map::new();
    stream.insert("network".into(), json!(node.network));
    stream.insert("security".into(), json!(non_empty(&node.security, "none")));

    match node.security.as_str() {
        "reality" => {
            let mut r = Map::new();
            r.insert("serverName".into(), json!(server_name(node)));
            r.insert("publicKey".into(), json!(node.public_key));
            r.insert("shortId".into(), json!(node.short_id));
            r.insert("spiderX".into(), json!(non_empty(&node.spider_x, "/")));
            // Xray rejects an empty fingerprint for REALITY.
            r.insert(
                "fingerprint".into(),
                json!(non_empty(&node.fingerprint, "chrome")),
            );
            if !node.mldsa65_verify.is_empty() {
                r.insert("mldsa65Verify".into(), json!(node.mldsa65_verify));
            }
            // Nothing else belongs here. REALITY has no alpn, no
            // allowInsecure, no ech, no pinned certificates -- Xray's decoder
            // drops unknown keys silently, so extra ones are invisible noise
            // in a config someone may have to read on a router.
            stream.insert("realitySettings".into(), Value::Object(r));
        }
        "tls" => {
            let mut t = Map::new();
            t.insert("serverName".into(), json!(server_name(node)));
            // `allowInsecure` is deliberately never written. Xray removed it,
            // and removed here means the config does not load at all -- a
            // single link carrying `insecure=1` would stop the core, taking
            // every other server with it. These two are the replacements Xray
            // names: both still verify the chain, so neither is a way back to
            // trusting anything.
            if !node.verify_peer_cert_by_name.is_empty() {
                t.insert(
                    "verifyPeerCertByName".into(),
                    json!(csv(&node.verify_peer_cert_by_name)),
                );
            }
            if !node.pinned_peer_cert_sha256.is_empty() {
                t.insert(
                    "pinnedPeerCertSha256".into(),
                    json!(csv(&node.pinned_peer_cert_sha256)),
                );
            }
            if !node.ech_config_list.is_empty() {
                t.insert("echConfigList".into(), json!(node.ech_config_list));
            }
            if !node.fingerprint.is_empty() {
                t.insert("fingerprint".into(), json!(node.fingerprint));
            }
            let alpn = csv(&node.alpn);
            if !alpn.is_empty() {
                t.insert("alpn".into(), json!(alpn));
            }
            stream.insert("tlsSettings".into(), Value::Object(t));
        }
        _ => {}
    }

    match node.network.as_str() {
        "ws" => {
            let mut w = Map::new();
            w.insert("path".into(), json!(non_empty(&node.path, "/")));
            if !node.host.is_empty() {
                w.insert("host".into(), json!(node.host));
            }
            stream.insert("wsSettings".into(), Value::Object(w));
        }
        "grpc" => {
            let mut g = Map::new();
            g.insert("serviceName".into(), json!(node.service_name));
            g.insert("multiMode".into(), json!(node.mode == "multi"));
            if !node.authority.is_empty() {
                g.insert("authority".into(), json!(node.authority));
            }
            // Xray spells these two in snake_case, unlike everything around
            // them. Values match what other clients send.
            g.insert("idle_timeout".into(), json!(60));
            g.insert("health_check_timeout".into(), json!(20));
            stream.insert("grpcSettings".into(), Value::Object(g));
        }
        "xhttp" | "splithttp" => {
            let mut x = Map::new();
            x.insert("path".into(), json!(non_empty(&node.path, "/")));
            if !node.host.is_empty() {
                x.insert("host".into(), json!(node.host));
            }
            x.insert("mode".into(), json!(non_empty(&node.mode, "auto")));
            // The escape hatch for xmux and the padding knobs a share link
            // cannot otherwise express. Embedded verbatim, but only if it is
            // really a JSON object -- Xray refuses the whole config over a
            // malformed one, and losing a tuning parameter beats that.
            if !node.xhttp_extra.is_empty() {
                match serde_json::from_str::<Value>(&node.xhttp_extra) {
                    Ok(v) if v.is_object() => {
                        x.insert("extra".into(), v);
                    }
                    _ => eprintln!(
                        "xrayop: ignoring the `extra` parameter on \"{}\": not a JSON object",
                        node.name
                    ),
                }
            }
            stream.insert("xhttpSettings".into(), Value::Object(x));
        }
        "httpupgrade" => {
            let mut h = Map::new();
            h.insert("path".into(), json!(non_empty(&node.path, "/")));
            if !node.host.is_empty() {
                h.insert("host".into(), json!(node.host));
            }
            stream.insert("httpupgradeSettings".into(), Value::Object(h));
        }
        "tcp" | "raw" => {
            // Only when the link asks for the HTTP disguise. Bare TCP needs no
            // block at all, and Xray treats a missing one as `header.type=none`.
            if node.header_type.eq_ignore_ascii_case("http") {
                stream.insert(
                    "tcpSettings".into(),
                    json!({ "header": http_header(node) }),
                );
            }
        }
        _ => {}
    }

    Value::Object(stream)
}

/// The `tcpSettings.header` block for `headerType=http`.
///
/// Xray wraps the connection in an authenticator that writes this as a real
/// HTTP request, and the server matches on it. Get it wrong and the connection
/// is accepted at TCP level and then dropped, which reads as "server is down".
///
/// Every header is written explicitly, and that is the whole point: Xray fills
/// in defaults of its own when `request.headers` is absent -- `Host` becomes
/// `www.baidu.com, www.bing.com` (`infra/conf/transport_authenticators.go`).
/// A config emitting only `{"type":"http"}` is therefore valid, starts
/// cleanly, and still fails, with the node's real host nowhere in the request.
///
/// `host` and `path` may carry comma-separated lists; both are passed through
/// as arrays, which is what Xray's `StringList` expects.
fn http_header(node: &Node) -> Value {
    let split = |s: &str, fallback: &str| -> Vec<String> {
        let out: Vec<String> = s
            .split(',')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        if out.is_empty() {
            vec![fallback.to_string()]
        } else {
            out
        }
    };
    // Falling back to the server address mirrors what other clients do when a
    // link sets `headerType=http` but leaves `host` out.
    let hosts = split(
        if node.host.is_empty() { &node.server } else { &node.host },
        &node.server,
    );

    json!({
        "type": "http",
        "request": {
            "version": "1.1",
            "method": "GET",
            "path": split(&node.path, "/"),
            "headers": {
                "Host": hosts,
                "User-Agent": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
                ],
                "Accept-Encoding": ["gzip, deflate"],
                "Connection": ["keep-alive"],
                "Pragma": "no-cache"
            }
        }
    })
}

fn non_empty<'a>(v: &'a str, default: &'a str) -> &'a str {
    if v.is_empty() {
        default
    } else {
        v
    }
}

/// The name to present in SNI, when the link did not say.
///
/// An empty `serverName` is not neutral: Xray fills it with the destination
/// address, so a server addressed by IP ends up announcing that IP in the
/// handshake, which REALITY and most TLS front-ends reject. Something
/// plausible has to be chosen.
///
/// The order is the one other clients settled on. Each transport carries a
/// host of its own -- gRPC in `authority`, the rest in `host` -- and that is
/// tried first, then the server address, but only while they look like domain
/// names. If neither does, the transport host is used regardless: an IP there
/// is at least what the link asked for.
fn server_name(node: &Node) -> String {
    if !node.sni.is_empty() {
        return node.sni.clone();
    }
    let transport_host = match node.network.as_str() {
        "grpc" => &node.authority,
        _ => &node.host,
    };
    // A comma-separated Host list means the first entry.
    let transport_host = transport_host.split(',').next().unwrap_or("").trim();

    if looks_like_domain(transport_host) {
        return transport_host.to_string();
    }
    if looks_like_domain(&node.server) {
        return node.server.clone();
    }
    // Nothing here is a domain. Other clients leave the field empty and let
    // Xray substitute the destination address; writing that address out says
    // the same thing, and says it where someone reading the config can see it.
    if !transport_host.is_empty() {
        return transport_host.to_string();
    }
    node.server.clone()
}

/// Whether a string is a hostname rather than an address literal.
///
/// Deliberately simple: it only has to separate `cdn.example.com` from
/// `1.2.3.4` and `2001:db8::1`, which is the whole job here.
fn looks_like_domain(s: &str) -> bool {
    if s.is_empty() || s.contains(':') || !s.contains('.') {
        return false;
    }
    // An IPv4 literal is four numeric labels; a domain has at least one that
    // is not.
    !s.split('.').all(|label| {
        !label.is_empty() && label.chars().all(|c| c.is_ascii_digit())
    })
}

/// Splits a comma-separated URI value into the array Xray expects.
///
/// Xray's `StringList` accepts either a bare string or an array, but arrays
/// leave no doubt about where one entry ends, and a link that wrote
/// `alpn=h2, http/1.1` with a space should not produce an entry beginning with
/// one.
fn csv(s: &str) -> Vec<&str> {
    s.split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Where the daemon keeps its runtime files.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Generated Xray config. Lives on tmpfs to spare the router's flash.
    pub config: PathBuf,
    /// Where a candidate config is validated before it replaces `config`.
    ///
    /// Keeps the `.json` extension deliberately: Xray infers the config format
    /// from the file name, so `config.json.next` makes `run -test` fail with
    /// "Failed to get format" regardless of the contents.
    pub staged: PathBuf,
    /// Xray's stdout/stderr.
    pub log: PathBuf,
}

impl Paths {
    pub fn new(runtime_dir: &Path) -> Self {
        Self {
            config: runtime_dir.join("config.json"),
            staged: runtime_dir.join("config.staged.json"),
            log: runtime_dir.join("xray.log"),
        }
    }
}

/// Owns the Xray child process.
pub struct Supervisor {
    paths: Paths,
    child: Option<Child>,
    /// Reason the last `apply` or `stop` failed; empty when healthy.
    pub last_error: String,
    /// Unix seconds when the current process started.
    pub started_at: u64,
    /// Node id the running process was built for.
    pub running_node: String,
    /// When the log was last emptied, for the age-based cap.
    log_rotated_at: Instant,
    /// Serialized config the running process was started with, so an `apply`
    /// that changes nothing does not restart it.
    applied: Option<Vec<u8>>,
}

impl Supervisor {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            child: None,
            last_error: String::new(),
            started_at: 0,
            running_node: String::new(),
            log_rotated_at: Instant::now(),
            applied: None,
        }
    }

    /// Empties the log once it is too big or too old.
    ///
    /// Called from a background thread. Both caps exist for different reasons:
    /// size is what actually protects the router's RAM, age is what stops a
    /// slow trickle of lines sitting around for days. Returns whether it
    /// truncated, so the caller can log the event once rather than per tick.
    pub fn tidy_log(&mut self, max_bytes: u64, max_age: Duration) -> bool {
        let Ok(meta) = fs::metadata(&self.paths.log) else {
            return false; // no log file: logging is off, nothing to do
        };
        if meta.len() == 0 {
            return false;
        }
        let too_big = meta.len() > max_bytes;
        let too_old = self.log_rotated_at.elapsed() >= max_age;
        if !(too_big || too_old) {
            return false;
        }
        // Truncates the inode Xray is holding. Safe because that handle is
        // O_APPEND -- see the comment in `apply`.
        if File::create(&self.paths.log).is_ok() {
            self.log_rotated_at = Instant::now();
            return true;
        }
        false
    }

    /// True if the child is alive. Reaps it if it has exited.
    pub fn is_running(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                // Exited on its own -- record why so the panel can show it.
                self.last_error = format!("xray exited ({status})");
                self.child = None;
                self.started_at = 0;
                self.running_node.clear();
                false
            }
            Ok(None) => true,
            Err(e) => {
                self.last_error = format!("cannot poll xray: {e}");
                false
            }
        }
    }

    /// Regenerates the config and restarts Xray to match `state`.
    ///
    /// With no node selected this stops Xray and succeeds -- "off" is a valid
    /// state, not an error.
    pub fn apply(&mut self, state: &State) -> Result<(), String> {
        let Some(config) = build_config(state) else {
            self.stop();
            self.last_error.clear();
            return Ok(());
        };

        let bin = &state.settings.xray_bin;
        if !Path::new(bin).exists() {
            let msg = format!("xray binary not found at {bin}");
            self.last_error = msg.clone();
            return Err(msg);
        }

        if let Some(dir) = self.paths.config.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }

        // Stage and validate before touching the running instance. Xray's own
        // parser is the only thing that knows whether a config is acceptable,
        // and asking it costs about a second -- far better than killing a
        // working tunnel to discover the replacement was rejected. Every mature
        // OpenWrt proxy app does this (`xray run -test`, `sing-box check`,
        // `mihomo -t`); the earlier version here did not, so a bad node
        // dropped your connection before the error surfaced.
        let body = serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?;

        // Nothing changed and it is already running: leave it alone. Renaming a
        // node, removing an unused one or refreshing a subscription that
        // returned identical content all reach this point, and restarting for
        // them drops every live connection -- which in transparent mode is the
        // whole LAN's traffic, for a cosmetic edit.
        if self.child.is_some() && self.applied.as_deref() == Some(body.as_slice()) && self.is_running()
        {
            return Ok(());
        }

        // Must still end in `.json`: Xray infers the config format from the
        // file extension, so a staging name like `config.json.next` makes
        // `run -test` fail with "Failed to get format" no matter what is
        // inside it.
        let staged = self.paths.staged.clone();
        debug_assert_eq!(staged.extension().and_then(|e| e.to_str()), Some("json"));
        write_atomic(&staged, &body).map_err(|e| format!("cannot write config: {e}"))?;

        if let Err(e) = test_config(bin, &staged) {
            let _ = fs::remove_file(&staged);
            self.last_error = e.clone();
            return Err(e); // the previous instance is untouched and still running
        }

        fs::rename(&staged, &self.paths.config)
            .map_err(|e| format!("cannot install config: {e}"))?;
        self.applied = Some(body);

        self.stop();

        let mut cmd = Command::new(bin);
        cmd.arg("run")
            .arg("-c")
            .arg(&self.paths.config)
            .stdin(Stdio::null());
        set_die_with_parent(&mut cmd);

        // Two layers of memory containment, for different failure shapes.
        //
        // GOMEMLIMIT is a *soft* ceiling: Go collects more aggressively as it
        // approaches, trading CPU for memory, and never fails an allocation.
        // It is the right default because the worst case is a slower router,
        // not a dead one.
        if state.settings.go_mem_limit_mb > 0 {
            cmd.env(
                "GOMEMLIMIT",
                format!("{}MiB", state.settings.go_mem_limit_mb),
            );
        }
        // RLIMIT_DATA is the *hard* backstop for a genuine runaway. Xray dies
        // with an allocation failure and this supervisor restarts it, instead
        // of the kernel OOM-killer picking a victim at random -- which on a
        // router is as likely to be dnsmasq or the network stack.
        set_memory_cap(&mut cmd, state.settings.mem_hard_cap_mb);

        if state.settings.log_enabled {
            // O_APPEND is load-bearing, not a style choice. The janitor
            // truncates this file while Xray holds it open; without O_APPEND
            // the child keeps writing at its old offset and the "truncated"
            // file immediately becomes a sparse file that reports the old
            // size. With it, every write seeks to the real end first.
            let log = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.paths.log)
                .map_err(|e| format!("cannot open {}: {e}", self.paths.log.display()))?;
            let log_err = log
                .try_clone()
                .map_err(|e| format!("cannot duplicate log handle: {e}"))?;
            cmd.stdout(Stdio::from(log)).stderr(Stdio::from(log_err));
        } else {
            // Nothing is written anywhere. `build_config` also forces
            // `loglevel: none`, so Xray does not even format the lines.
            let _ = fs::remove_file(&self.paths.log);
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
        self.log_rotated_at = Instant::now();

        let child = cmd.spawn().map_err(|e| format!("cannot start xray: {e}"))?;

        self.child = Some(child);
        self.started_at = now_secs();
        self.running_node = state.active.clone();
        self.last_error.clear();

        self.wait_until_settled()
    }

    /// Confirms the child is still alive a moment after spawning.
    ///
    /// Xray parses its config and binds its inbounds during startup, so a bad
    /// node, an unusable DNS entry or a port clash all show up as an exit
    /// within a few hundred milliseconds. Returning straight from `spawn`
    /// would report those as a successful start, and the panel would show
    /// "connected" for a process that is already gone.
    fn wait_until_settled(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + SETTLE;
        while Instant::now() < deadline {
            thread::sleep(POLL);
            if !self.is_running() {
                // `is_running` already recorded the exit status; prefer the
                // log line, which says *why*.
                let detail = last_error_line(&self.log_tail(40));
                let msg = if detail.is_empty() {
                    self.last_error.clone()
                } else {
                    detail
                };
                self.last_error = msg.clone();
                return Err(msg);
            }
        }
        Ok(())
    }

    /// Stops Xray if it is running. Safe to call when it is not.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            terminate(&mut child);
            // Reap it so we do not leave a zombie behind.
            let _ = child.wait();
        }
        self.started_at = 0;
        self.running_node.clear();
    }

    /// Tail of the Xray log, most recent `lines` lines.
    ///
    /// Reads only the last [`TAIL_BYTES`] rather than the whole file. Slurping
    /// the file would mean that if the size cap were ever misconfigured or the
    /// janitor stalled, one click on "view log" allocates the entire file --
    /// and on a router with ~260MB free that is how a log viewer OOM-kills the
    /// daemon it was meant to help debug.
    pub fn log_tail(&self, lines: usize) -> String {
        let Ok(mut file) = File::open(&self.paths.log) else {
            return String::new();
        };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let from = len.saturating_sub(TAIL_BYTES);
        if from > 0 && file.seek(SeekFrom::Start(from)).is_err() {
            return String::new();
        }

        let mut buf = Vec::with_capacity(TAIL_BYTES.min(len) as usize);
        if file.take(TAIL_BYTES).read_to_end(&mut buf).is_err() {
            return String::new();
        }
        let text = String::from_utf8_lossy(&buf);
        // A mid-file seek almost certainly lands inside a line; drop the
        // fragment so the first line shown is a real one.
        let text = if from > 0 {
            text.split_once('\n').map(|(_, rest)| rest).unwrap_or("")
        } else {
            &text
        };

        let all: Vec<&str> = text.lines().collect();
        let start = all.len().saturating_sub(lines);
        all[start..].join("\n")
    }

    /// Directory holding the generated config and log.
    pub fn runtime_dir(&self) -> &Path {
        self.paths.config.parent().unwrap_or(Path::new("/tmp"))
    }

    pub fn config_path(&self) -> &Path {
        &self.paths.config
    }
}

#[cfg(unix)]
fn terminate(child: &mut Child) {
    let pid = child.id().to_string();
    let _ = Command::new("kill")
        .args(["-TERM", &pid])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate(child: &mut Child) {
    let _ = child.kill();
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Asks Xray whether it would accept this config, without starting it.
///
/// Every mature OpenWrt proxy app does this before restarting its core
/// (`xray run -test`, `sing-box check`, `mihomo -t`). It costs about a second
/// and it is what lets a rejected config leave the running tunnel alone.
pub fn test_config(bin: &str, config: &Path) -> Result<(), String> {
    let out = Command::new(bin)
        .arg("run")
        .arg("-test")
        .arg("-c")
        .arg(config)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run xray: {e}"))?;

    if out.status.success() {
        return Ok(());
    }
    // Xray prints the reason to stdout, not stderr.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let detail = last_error_line(&text);
    Err(if detail.is_empty() {
        "xray rejected the generated config".into()
    } else {
        detail
    })
}

/// Caps the child's address space, so a runaway allocation fails in Xray
/// instead of inviting the kernel's OOM killer to shoot something else.
///
/// `0` disables it. This is the hard backstop; [`Settings::go_mem_limit_mb`]
/// is the soft one that should normally do the work.
#[cfg(target_os = "linux")]
fn set_memory_cap(cmd: &mut Command, megabytes: u64) {
    use std::os::unix::process::CommandExt;

    if megabytes == 0 {
        return;
    }
    let soft = megabytes.saturating_mul(1024 * 1024);
    // A little headroom above the soft limit so the allocator can fail
    // gracefully rather than being cut off mid-teardown.
    let hard = soft.saturating_add(soft / 8);

    // SAFETY: runs between fork and exec. setrlimit is a single syscall and
    // therefore async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            let lim = libc::rlimit {
                rlim_cur: soft as libc::rlim_t,
                rlim_max: hard as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_DATA, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn set_memory_cap(_cmd: &mut Command, _megabytes: u64) {}

/// Picks the most informative line out of an Xray log for error reporting.
///
/// Xray prints its failure reason on the last non-empty line; the banner it
/// writes on every start would otherwise mask it.
fn last_error_line(log: &str) -> String {
    log.lines()
        .rev()
        .map(str::trim)
        .find(|l| {
            !l.is_empty()
                && !l.starts_with("Xray ")
                && !l.starts_with("A unified platform")
        })
        .unwrap_or_default()
        .to_string()
}

/// Asks the kernel to signal the child if this process dies.
///
/// [`Drop`] and a SIGTERM handler only cover orderly shutdown. A SIGKILL, an
/// OOM kill or a panic-abort would otherwise leave Xray running unsupervised
/// with the proxy ports held, so the next start fails with "address in use".
/// `PR_SET_PDEATHSIG` closes that gap in the kernel.
#[cfg(target_os = "linux")]
pub fn set_die_with_parent(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    let parent = std::process::id() as libc::pid_t;
    // SAFETY: the closure runs between fork and exec, so it must only make
    // async-signal-safe calls. prctl and getppid are both single syscalls.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The parent can die between fork and the prctl above, and the
            // signal would then never arrive. Detect that and refuse to exec
            // rather than leak the very process this is meant to prevent.
            if libc::getppid() != parent {
                return Err(std::io::Error::other(
                    "parent exited before xray could be supervised",
                ));
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn set_die_with_parent(_cmd: &mut Command) {}

/// Writes via a temp file and rename, so a crash mid-write cannot leave a
/// truncated config that Xray would refuse to start with.
///
/// The file is created `0600`. Both files written through here -- the state
/// file and the generated Xray config -- contain node UUIDs and REALITY keys,
/// and `File::create`'s default `0644` would leave them readable by every other
/// process on the router.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = create_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<File> {
    File::create(path)
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_uri;

    fn state_with(uri: &str) -> State {
        let node = parse_uri(uri).unwrap();
        let mut s = State::default();
        s.active = node.id.clone();
        s.nodes.push(node);
        s
    }

    #[test]
    fn no_selection_yields_no_config() {
        assert!(build_config(&State::default()).is_none());
    }

    #[test]
    fn reality_outbound_has_required_fields() {
        let s = state_with(
            "vless://uu@ex.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12&sni=www.apple.com\
             &flow=xtls-rprx-vision&type=tcp#n",
        );
        let cfg = build_config(&s).unwrap();
        let ob = &cfg["outbounds"][0];
        assert_eq!(ob["protocol"], "vless");
        assert_eq!(ob["settings"]["vnext"][0]["address"], "ex.com");
        assert_eq!(ob["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        let r = &ob["streamSettings"]["realitySettings"];
        assert_eq!(r["publicKey"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(r["shortId"], "ab12");
        assert_eq!(r["serverName"], "www.apple.com");
        assert_eq!(r["fingerprint"], "chrome", "must default, xray rejects empty");
        assert_eq!(r["spiderX"], "/");
    }

    #[test]
    fn flow_is_omitted_when_absent() {
        let s = state_with("vless://uu@ex.com:443?type=ws&security=tls#n");
        let cfg = build_config(&s).unwrap();
        let user = &cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0];
        assert!(user.get("flow").is_none());
    }

    #[test]
    fn ws_tls_stream_is_complete() {
        let s = state_with(
            "vless://uu@ex.com:8443?type=ws&security=tls&path=%2Fabc&host=cdn.example.com\
             &alpn=h2%2Chttp%2F1.1&fp=firefox#n",
        );
        let st = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"];
        assert_eq!(st["network"], "ws");
        assert_eq!(st["wsSettings"]["path"], "/abc");
        assert_eq!(st["wsSettings"]["host"], "cdn.example.com");
        assert_eq!(st["tlsSettings"]["serverName"], "cdn.example.com");
        assert_eq!(st["tlsSettings"]["alpn"][0], "h2");
        assert_eq!(st["tlsSettings"]["alpn"][1], "http/1.1");
        assert_eq!(st["tlsSettings"]["fingerprint"], "firefox");
    }

    #[test]
    fn tls_sni_falls_back_to_host_then_address() {
        let s = state_with("vless://uu@1.2.3.4:443?type=tcp&security=tls#n");
        let st = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"];
        assert_eq!(st["tlsSettings"]["serverName"], "1.2.3.4");
    }

    #[test]
    fn grpc_multi_mode_is_derived_from_mode() {
        let s = state_with("vless://uu@ex.com:443?type=grpc&serviceName=svc&mode=multi#n");
        let st = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"];
        assert_eq!(st["grpcSettings"]["serviceName"], "svc");
        assert_eq!(st["grpcSettings"]["multiMode"], true);
    }

    #[test]
    fn private_ranges_route_direct() {
        let s = state_with("vless://uu@ex.com:443?type=tcp#n");
        let cfg = build_config(&s).unwrap();
        let rule = &cfg["routing"]["rules"][0];
        assert_eq!(rule["outboundTag"], "direct");
        let ips = rule["ip"].as_array().unwrap();
        assert!(ips.iter().any(|v| v == "192.168.0.0/16"));
    }

    #[test]
    fn transparent_mode_is_off_by_default() {
        let s = state_with("vless://uu@ex.com:443?type=tcp#n");
        let cfg = build_config(&s).unwrap();
        let tags: Vec<&str> = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["tag"].as_str().unwrap())
            .collect();
        assert_eq!(tags, ["socks-in", "http-in"]);
    }

    #[test]
    fn transparent_mode_adds_the_tproxy_inbound() {
        let mut s = state_with("vless://uu@ex.com:443?type=tcp#n");
        s.settings.transparent = true;
        s.settings.tproxy_port = 12345;
        let cfg = build_config(&s).unwrap();

        let tproxy = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["tag"] == "tproxy-in")
            .expect("tproxy inbound");
        assert_eq!(tproxy["port"], 12345);
        assert_eq!(tproxy["protocol"], "dokodemo-door");
        assert_eq!(tproxy["streamSettings"]["sockopt"]["tproxy"], "tproxy");
        assert_eq!(
            tproxy["settings"]["followRedirect"], true,
            "without this the original destination is lost"
        );
        assert_eq!(tproxy["settings"]["network"], "tcp,udp");
    }

    /// The mark on xray's own sockets is what the nftables `intercept` chain
    /// returns on. Without it, xray's connection to the server is itself
    /// intercepted and the router recurses to death.
    #[test]
    fn transparent_mode_marks_xray_own_sockets() {
        let mut s = state_with("vless://uu@ex.com:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#n");
        s.settings.transparent = true;
        let cfg = build_config(&s).unwrap();

        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["sockopt"]["mark"],
            crate::tproxy::XRAY_MARK
        );
        assert_eq!(
            cfg["outbounds"][1]["streamSettings"]["sockopt"]["mark"],
            crate::tproxy::XRAY_MARK,
            "the direct outbound needs it too, or direct traffic loops"
        );
    }

    #[test]
    fn marking_does_not_disturb_the_rest_of_the_stream_config() {
        let mut s = state_with(
            "vless://uu@ex.com:443?type=ws&security=tls&path=%2Fx&host=cdn.example.com#n",
        );
        s.settings.transparent = true;
        let st = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"];
        assert_eq!(st["network"], "ws");
        assert_eq!(st["wsSettings"]["path"], "/x");
        assert_eq!(st["tlsSettings"]["serverName"], "cdn.example.com");
        assert_eq!(st["sockopt"]["mark"], crate::tproxy::XRAY_MARK);
    }

    /// Eight of the user's servers reported unreachable while working in
    /// v2rayNG on the same network. They all carried `headerType=http`, which
    /// was parsed away, so Xray sent raw VLESS bytes to a server waiting for a
    /// request line.
    #[test]
    fn tcp_with_an_http_header_gets_one() {
        let s = state_with(
            "vless://uu@ex.com:443?type=tcp&headerType=http&host=play.google.com&path=%2F#n",
        );
        let h = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["tcpSettings"]["header"];
        assert_eq!(h["type"], "http");
        assert_eq!(h["request"]["method"], "GET");
        assert_eq!(h["request"]["path"][0], "/");
        assert_eq!(h["request"]["headers"]["Host"][0], "play.google.com");
    }

    /// The trap: Xray fills in `Host: www.baidu.com, www.bing.com` when
    /// `request.headers` is missing. A config emitting only `{"type":"http"}`
    /// is valid, starts cleanly, and still cannot connect.
    #[test]
    fn the_host_header_is_never_left_to_xrays_default() {
        let s = state_with("vless://uu@ex.com:443?type=tcp&headerType=http&host=cdn.test#n");
        let h = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["tcpSettings"]["header"];
        let headers = &h["request"]["headers"];
        assert!(headers.is_object(), "headers must be written, not defaulted");
        assert_eq!(headers["Host"][0], "cdn.test");
        let text = h.to_string();
        assert!(!text.contains("baidu") && !text.contains("bing"));
    }

    /// A link that sets the disguise but omits `host` still has to send a
    /// plausible one, so fall back to the address rather than to Xray's.
    #[test]
    fn a_missing_host_falls_back_to_the_server_address() {
        let s = state_with("vless://uu@ex.com:443?type=tcp&headerType=http#n");
        let h = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["tcpSettings"]["header"];
        assert_eq!(h["request"]["headers"]["Host"][0], "ex.com");
    }

    /// Both fields may carry lists; Xray's StringList takes arrays.
    #[test]
    fn comma_separated_hosts_and_paths_become_arrays() {
        let s = state_with(
            "vless://uu@ex.com:443?type=tcp&headerType=http&host=a.com,b.com&path=/x,/y#n",
        );
        let r = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["tcpSettings"]["header"]
            ["request"];
        assert_eq!(r["headers"]["Host"].as_array().unwrap().len(), 2);
        assert_eq!(r["headers"]["Host"][1], "b.com");
        assert_eq!(r["path"].as_array().unwrap().len(), 2);
        assert_eq!(r["path"][1], "/y");
    }

    /// Bare TCP must stay bare. Emitting a header block where the link asked
    /// for none would break the 22 nodes that currently work.
    #[test]
    fn tcp_without_the_disguise_gets_no_settings_block() {
        for uri in [
            "vless://uu@ex.com:443?type=tcp#n",
            "vless://uu@ex.com:443?type=tcp&headerType=none#n",
        ] {
            let cfg = build_config(&state_with(uri)).unwrap();
            assert!(
                cfg["outbounds"][0]["streamSettings"].get("tcpSettings").is_none(),
                "{uri} should produce no tcpSettings"
            );
        }
    }

    /// The disguise belongs to raw TCP only; a ws node carries its host in
    /// wsSettings and must not grow a second copy here.
    #[test]
    fn the_http_disguise_is_not_applied_to_other_transports() {
        let s = state_with("vless://uu@ex.com:443?type=ws&headerType=http&host=a.com#n");
        let st = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"];
        assert!(st.get("tcpSettings").is_none());
        assert_eq!(st["wsSettings"]["host"], "a.com");
    }

    /// Xray removed `allowInsecure`, and removed means the config does not
    /// load -- not a warning, a refusal. One link carrying `insecure=1` would
    /// stop the core and take every other server down with it. The link's
    /// request is recorded on the node so the panel can explain itself; it
    /// must never reach the JSON.
    #[test]
    fn allow_insecure_never_reaches_the_config() {
        let s = state_with("vless://uu@ex.com:443?type=ws&security=tls&insecure=1#n");
        assert!(
            s.nodes[0].allow_insecure,
            "the link asked for it, and that is worth remembering"
        );
        let cfg = build_config(&s).unwrap();
        assert!(
            !cfg.to_string().contains("allowInsecure"),
            "emitting it would stop the core from starting at all"
        );
    }

    /// What Xray offers instead. Both still verify the certificate chain, so
    /// neither is a way back to trusting anything that answers.
    #[test]
    fn the_sanctioned_replacements_are_emitted_as_arrays() {
        let s = state_with(
            "vless://uu@ex.com:443?type=ws&security=tls&vcn=a.com,%20b.com&pcs=AA,BB&ech=cfg#n",
        );
        let t = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["tlsSettings"];
        assert_eq!(t["verifyPeerCertByName"][1], "b.com", "whitespace trimmed");
        assert_eq!(t["pinnedPeerCertSha256"].as_array().unwrap().len(), 2);
        assert_eq!(t["echConfigList"], "cfg");
    }

    /// REALITY has no alpn, no allowInsecure, no pinned certificates. Xray
    /// drops unknown keys silently, so extras are invisible noise in a config
    /// someone may end up reading over SSH.
    #[test]
    fn reality_carries_only_the_keys_reality_has() {
        let s = state_with(
            "vless://uu@ex.com:443?type=tcp&security=reality\
             &pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=a.com&alpn=h2&pqv=xyz#n",
        );
        let r = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["realitySettings"];
        let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
        for absent in ["alpn", "allowInsecure", "echConfigList", "pinnedPeerCertSha256"] {
            assert!(!keys.iter().any(|k| *k == absent), "{absent} does not belong here");
        }
        assert_eq!(r["mldsa65Verify"], "xyz");
    }

    /// VLESS and VMess address a server through `vnext` with a user account;
    /// Trojan and Shadowsocks through `servers` with the password on the
    /// server. Getting the shape wrong is a config Xray will not load.
    #[test]
    fn each_protocol_gets_the_settings_shape_xray_expects() {
        let vmess = state_with(&format!(
            "vmess://{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                r#"{"add":"a.com","port":"443","id":"the-uuid","aid":"0","scy":"auto","net":"tcp"}"#
            )
        ));
        let o = &build_config(&vmess).unwrap()["outbounds"][0];
        assert_eq!(o["protocol"], "vmess");
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["id"], "the-uuid");
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["security"], "auto");

        let trojan = state_with("trojan://the-password@a.com:443#t");
        let o = &build_config(&trojan).unwrap()["outbounds"][0];
        assert_eq!(o["protocol"], "trojan");
        assert_eq!(o["settings"]["servers"][0]["password"], "the-password");
        assert!(
            o["settings"]["servers"][0].get("flow").is_none(),
            "a Trojan flow is a removed-feature error in Xray"
        );

        let ss = state_with("ss://aes-256-gcm:the-key@a.com:8388#s");
        let o = &build_config(&ss).unwrap()["outbounds"][0];
        assert_eq!(o["protocol"], "shadowsocks");
        assert_eq!(o["settings"]["servers"][0]["method"], "aes-256-gcm");
        assert_eq!(o["settings"]["servers"][0]["password"], "the-key");
    }

    /// Level 0 is the only bucket this config defines. Any other value falls
    /// back to Xray's default 300-second idle timeout, silently discarding the
    /// conn_idle_secs setting -- which is what v2rayNG's level 8 does.
    #[test]
    fn every_protocol_stays_on_the_policy_level_we_define() {
        for uri in [
            "vless://u@a.com:443#v",
            "trojan://pw@a.com:443#t",
            "ss://aes-256-gcm:pw@a.com:8388#s",
        ] {
            let s = state_with(uri);
            let text = build_config(&s).unwrap()["outbounds"][0]["settings"].to_string();
            assert!(text.contains("\"level\":0"), "{uri}: {text}");
        }
    }

    #[test]
    fn arm_buffer_is_explicit_and_small() {
        let s = state_with("vless://u@a.com:443#v");
        let config = build_config(&s).unwrap();
        assert_eq!(config["policy"]["levels"]["0"]["bufferSize"], 4);
    }

    #[test]
    fn hysteria2_keeps_its_credential_in_the_transport() {
        let s = state_with("hysteria2://the-pw@hy.example.com:443?sni=hy.example.com#H");
        let o = &build_config(&s).unwrap()["outbounds"][0];
        assert_eq!(o["protocol"], "hysteria", "Xray has no protocol called hysteria2");
        assert_eq!(o["settings"]["version"], 2);
        assert!(
            o["settings"].get("password").is_none(),
            "the password belongs in hysteriaSettings, not settings"
        );
        let st = &o["streamSettings"];
        assert_eq!(st["hysteriaSettings"]["auth"], "the-pw");
        assert_eq!(st["security"], "tls", "the dialer fails without it");
        assert_eq!(st["tlsSettings"]["alpn"][0], "h3");
    }

    /// Obfuscation and port hopping moved under finalmask; the older
    /// in-transport spellings are ignored with only a warning, which would
    /// look like they worked.
    #[test]
    fn hysteria2_obfuscation_and_port_hopping_go_under_finalmask() {
        let s = state_with(
            "hysteria2://pw@hy.com:443?obfs=salamander&obfs-password=sp&mport=20000-50000#H",
        );
        let m = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["finalmask"];
        assert_eq!(m["udp"][0]["type"], "salamander");
        assert_eq!(m["udp"][0]["settings"]["password"], "sp");
        assert_eq!(m["quicParams"]["udpHop"]["ports"], "20000-50000");
    }

    /// The one that matters on a router. Running as root, Xray would otherwise
    /// create a real wg interface, zero rp_filter and install its own routes
    /// on top of the policy routing the transparent proxy depends on.
    #[test]
    fn wireguard_is_kept_out_of_the_kernel() {
        let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let s = state_with(&format!(
            "wireguard://{k}@wg.example.com:2408?publickey={k}&address=172.16.0.2%2F32&reserved=1,2,3&mtu=1420#W"
        ));
        let o = &build_config(&s).unwrap()["outbounds"][0];
        assert_eq!(o["protocol"], "wireguard");
        assert_eq!(o["settings"]["noKernelTun"], true);
        assert_eq!(o["settings"]["peers"][0]["endpoint"], "wg.example.com:2408");
        assert_eq!(o["settings"]["reserved"], json!([1, 2, 3]));
        assert_eq!(o["settings"]["address"][0], "172.16.0.2/32");
        assert!(
            o["streamSettings"].get("network").is_none(),
            "wireguard has no transport"
        );
    }

    #[test]
    fn socks_sends_credentials_only_when_it_has_them() {
        let anon = state_with("socks://1.2.3.4:1080#S");
        let o = &build_config(&anon).unwrap()["outbounds"][0];
        assert_eq!(o["protocol"], "socks");
        assert!(o["settings"]["servers"][0].get("users").is_none());

        let auth = state_with("socks://alice:s3cret@1.2.3.4:1080#S");
        let u = &build_config(&auth).unwrap()["outbounds"][0]["settings"]["servers"][0]["users"][0];
        assert_eq!(u["user"], "alice");
        assert_eq!(u["pass"], "s3cret");
    }

    /// An empty serverName is not neutral: Xray substitutes the destination
    /// address, so an IP-addressed server announces that IP in the handshake
    /// and REALITY rejects it.
    #[test]
    fn server_name_prefers_a_domain_over_an_address() {
        // sni wins outright
        let s = state_with("vless://u@1.2.3.4:443?type=ws&security=tls&sni=a.com&host=b.com#n");
        assert_eq!(sni_of(&s), "a.com");
        // no sni: the transport host, when it is a domain
        let s = state_with("vless://u@1.2.3.4:443?type=ws&security=tls&host=b.com#n");
        assert_eq!(sni_of(&s), "b.com");
        // host is an address, but the server is a domain
        let s = state_with("vless://u@real.example.com:443?type=ws&security=tls&host=9.9.9.9#n");
        assert_eq!(sni_of(&s), "real.example.com");
        // nothing is a domain: say so rather than leave it blank
        let s = state_with("vless://u@1.2.3.4:443?type=ws&security=tls#n");
        assert_eq!(sni_of(&s), "1.2.3.4");
    }

    /// gRPC carries its host in `authority`, not `host`.
    #[test]
    fn grpc_authority_is_emitted_and_used_as_the_sni_fallback() {
        let s = state_with(
            "vless://u@1.2.3.4:443?type=grpc&security=tls&authority=g.example.com&serviceName=Gun#n",
        );
        let st = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"];
        assert_eq!(st["grpcSettings"]["authority"], "g.example.com");
        assert_eq!(st["grpcSettings"]["serviceName"], "Gun");
        assert_eq!(st["tlsSettings"]["serverName"], "g.example.com");
    }

    /// `extra` is the only way a link can reach xmux and the padding knobs.
    /// A malformed one is dropped rather than passed on: Xray refuses the
    /// whole config over it, and losing one tuning value beats losing the core.
    #[test]
    fn xhttp_extra_is_embedded_when_it_is_really_json() {
        let s = state_with(
            "vless://u@a.com:443?type=xhttp&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%228-16%22%7D%7D#n",
        );
        let x = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["xhttpSettings"];
        assert_eq!(x["extra"]["xmux"]["maxConcurrency"], "8-16");

        let s = state_with("vless://u@a.com:443?type=xhttp&extra=not-json#n");
        let x = &build_config(&s).unwrap()["outbounds"][0]["streamSettings"]["xhttpSettings"];
        assert!(x.get("extra").is_none());
    }

    fn sni_of(s: &crate::model::State) -> String {
        build_config(s).unwrap()["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// Writes one config per protocol so the real Xray binary on the router can
    /// be asked whether it accepts what this code actually generates -- rather
    /// than whether it accepts JSON hand-written to look like it.
    ///
    /// Ignored by default; run with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_sample_configs() {
        let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        for (name, uri) in [
            ("vless-reality", "vless://u@a.com:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12&sni=www.apple.com&flow=xtls-rprx-vision#n"),
            ("vless-tcp-http", "vless://u@a.com:80?type=tcp&headerType=http&host=play.google.com&path=%2F#n"),
            ("trojan-ws", "trojan://pw@t.com:443?type=ws&security=tls&path=%2Ftj&host=t.com#n"),
            ("ss-aead", "ss://aes-256-gcm:pw@s.com:8388#n"),
            ("ss-2022", "ss://2022-blake3-aes-256-gcm:OGNlZmE3YmE2NGJkZWYxYmE2NGJkZWYxYmE2NGJkZWY=@s.com:443#n"),
            ("vmess-ws", "vmess://u@v.com:443?type=ws&security=tls&host=v.com&path=%2Fws#n"),
            ("hysteria2", "hysteria2://pw@hy.com:443?sni=hy.com&obfs=salamander&obfs-password=sp&mport=20000-50000#n"),
            ("socks", "socks://alice:s3cret@1.2.3.4:1080#n"),
            ("grpc", "vless://u@a.com:443?type=grpc&security=tls&authority=g.com&serviceName=Gun&mode=multi#n"),
            ("xhttp", "vless://u@a.com:443?type=xhttp&security=tls&host=x.com&mode=stream-one#n"),
        ] {
            let cfg = build_config(&state_with(uri)).unwrap();
            println!("===CONFIG {name}===");
            println!("{}", serde_json::to_string(&cfg).unwrap());
        }
        let wg = format!(
            "wireguard://{k}@wg.com:2408?publickey={k}&address=172.16.0.2%2F32&reserved=1,2,3&mtu=1420#n"
        );
        let cfg = build_config(&state_with(&wg)).unwrap();
        println!("===CONFIG wireguard===");
        println!("{}", serde_json::to_string(&cfg).unwrap());
    }

    #[test]
    fn no_mark_when_transparent_is_off() {
        let s = state_with("vless://uu@ex.com:443?type=tcp#n");
        let cfg = build_config(&s).unwrap();
        assert!(cfg["outbounds"][0]["streamSettings"].get("sockopt").is_none());
    }

    #[test]
    fn logging_off_forces_loglevel_none() {
        let s = state_with("vless://uu@ex.com:443?type=tcp#n");
        assert!(!s.settings.log_enabled, "logging must default to off on a router");
        assert_eq!(build_config(&s).unwrap()["log"]["loglevel"], "none");
    }

    #[test]
    fn logging_on_uses_the_chosen_level() {
        let mut s = state_with("vless://uu@ex.com:443?type=tcp#n");
        s.settings.log_enabled = true;
        s.settings.log_level = "debug".into();
        assert_eq!(build_config(&s).unwrap()["log"]["loglevel"], "debug");
    }

    #[cfg(unix)]
    #[test]
    fn tidy_log_enforces_the_size_cap() {
        let dir = scratch("tidy-size");
        let mut sup = Supervisor::new(Paths::new(&dir));
        let log = dir.join("xray.log");
        fs::write(&log, vec![b'x'; 4096]).unwrap();

        // Under the cap and freshly rotated: nothing to do.
        assert!(!sup.tidy_log(8192, Duration::from_secs(3600)));
        assert_eq!(fs::metadata(&log).unwrap().len(), 4096);

        // Over the cap: emptied.
        assert!(sup.tidy_log(1024, Duration::from_secs(3600)));
        assert_eq!(fs::metadata(&log).unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn tidy_log_enforces_the_age_cap() {
        let dir = scratch("tidy-age");
        let mut sup = Supervisor::new(Paths::new(&dir));
        fs::write(dir.join("xray.log"), b"some lines\n").unwrap();

        // A zero max_age makes every call overdue, standing in for elapsed time.
        assert!(sup.tidy_log(u64::MAX, Duration::from_secs(0)));
        assert_eq!(fs::metadata(dir.join("xray.log")).unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn tidy_log_is_a_no_op_without_a_log() {
        let dir = scratch("tidy-none");
        let mut sup = Supervisor::new(Paths::new(&dir));
        let _ = fs::remove_file(dir.join("xray.log"));
        assert!(!sup.tidy_log(0, Duration::from_secs(0)), "no file, nothing to rotate");
    }

    /// Truncating a file the child holds open only works if that handle is
    /// O_APPEND; otherwise the child writes at its old offset and recreates
    /// the size as a sparse hole. This asserts the behaviour we depend on.
    #[cfg(unix)]
    #[test]
    fn appending_after_truncation_restarts_at_zero() {
        use std::io::Write as _;

        let dir = scratch("tidy-append");
        let path = dir.join("append-probe.log");
        let mut holder = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        holder.write_all(&vec![b'x'; 5000]).unwrap();
        holder.flush().unwrap();

        File::create(&path).unwrap(); // truncate underneath the open handle
        holder.write_all(b"after").unwrap();
        holder.flush().unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            5,
            "with O_APPEND the file restarts at zero; without it this would be 5005"
        );
    }

    #[test]
    fn transparent_mode_serves_dns_through_the_tunnel() {
        let mut s = state_with("vless://uu@ex.com:443?type=tcp#n");
        s.settings.transparent = true;
        s.settings.dns_port = 5353;
        let cfg = build_config(&s).unwrap();

        let dns_in = cfg["inbounds"].as_array().unwrap().iter()
            .find(|i| i["tag"] == "dns-in").expect("dns inbound");
        assert_eq!(dns_in["port"], 5353);
        assert_eq!(dns_in["listen"], "127.0.0.1",
            "a LAN client must not be able to reach it directly");
        assert_eq!(dns_in["settings"]["network"], "tcp,udp");

        assert!(cfg["outbounds"].as_array().unwrap().iter()
            .any(|o| o["tag"] == "dns-out" && o["protocol"] == "dns"));

        // The DNS rule has to come first: an Iranian resolver like 10.202.10.10
        // is inside RFC1918 and the private-range rule would send it direct.
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inboundTag"][0], "dns-in");
        assert_eq!(rules[0]["outboundTag"], "dns-out");
    }

    #[test]
    fn no_dns_inbound_without_transparent_mode() {
        let s = state_with("vless://uu@ex.com:443?type=tcp#n");
        let cfg = build_config(&s).unwrap();
        assert!(!cfg["inbounds"].as_array().unwrap().iter().any(|i| i["tag"] == "dns-in"));
        assert!(!cfg["outbounds"].as_array().unwrap().iter().any(|o| o["tag"] == "dns-out"));
    }

    #[test]
    fn error_line_skips_the_startup_banner() {
        let banner = "Xray 26.7.28 (Xray, Penetrates Everything.)\n\
                      A unified platform for anti-censorship.\n";
        assert_eq!(last_error_line(banner), "");
        assert_eq!(
            last_error_line(&format!("{banner}failed to listen: address already in use\n")),
            "failed to listen: address already in use"
        );
    }

    #[cfg(unix)]
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("xrayop-{name}-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    /// The whole point of the settle window: a core that dies on startup must
    /// surface as an error, not as "connected".
    #[cfg(unix)]
    #[test]
    fn a_core_that_exits_immediately_is_a_failed_start() {
        let dir = scratch("settle-fail");
        let mut s = state_with("vless://uu@ex.com:443?type=tcp#n");
        s.settings.xray_bin = "/bin/false".into();

        let mut sup = Supervisor::new(Paths::new(&dir));
        let err = sup.apply(&s).expect_err("a core that exits must not report success");
        assert!(!err.is_empty(), "the failure needs a reason");
        assert!(!sup.is_running());
    }

    #[cfg(unix)]
    #[test]
    fn a_core_that_keeps_running_is_a_successful_start() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("settle-ok");
        let fake = dir.join("fake-xray");
        // Mimics the real binary closely enough to be useful: it answers
        // `run -test` immediately, and it *rejects a config whose name does not
        // end in .json*, because Xray reads the format from the extension. An
        // earlier double ignored that and let a staging filename of
        // `config.json.next` ship -- which made every start fail on the router
        // while the tests stayed green.
        fs::write(
            &fake,
            "#!/bin/sh\n\
             test_mode=0\n\
             for a in \"$@\"; do\n\
               case \"$a\" in\n\
                 -test) test_mode=1 ;;\n\
                 *.json) cfg=1 ;;\n\
                 /*) cfg=0 ;;\n\
               esac\n\
             done\n\
             [ \"$cfg\" = 1 ] || { echo 'Failed to get format'; exit 23; }\n\
             [ \"$test_mode\" = 1 ] && exit 0\n\
             exec sleep 30\n",
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();

        let mut s = state_with("vless://uu@ex.com:443?type=tcp#n");
        s.settings.xray_bin = fake.display().to_string();

        let mut sup = Supervisor::new(Paths::new(&dir));
        sup.apply(&s).expect("a live core should start cleanly");
        assert!(sup.is_running());
        assert_eq!(sup.running_node, s.active);
        assert!(sup.last_error.is_empty());

        sup.stop();
        assert!(!sup.is_running());
    }

    /// Regression: the staging file was once `config.json.next`, whose
    /// extension Xray cannot map to a format, so `run -test` rejected every
    /// config and the core never started.
    #[test]
    fn staged_config_keeps_a_json_extension() {
        let p = Paths::new(Path::new("/var/etc/xrayop"));
        assert_eq!(p.staged.extension().and_then(|e| e.to_str()), Some("json"));
        assert_ne!(p.staged, p.config, "staging must not overwrite the live config");
    }

    #[test]
    fn missing_binary_is_reported_clearly() {
        let mut s = state_with("vless://uu@ex.com:443?type=tcp#n");
        s.settings.xray_bin = "/definitely/not/here/xray".into();
        let dir = std::env::temp_dir().join("xrayop-missing-bin");
        let _ = fs::create_dir_all(&dir);
        let err = Supervisor::new(Paths::new(&dir)).apply(&s).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn lan_binding_follows_setting() {
        let mut s = state_with("vless://uu@ex.com:443?type=tcp#n");
        s.settings.allow_lan = false;
        let cfg = build_config(&s).unwrap();
        assert_eq!(cfg["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(cfg["inbounds"][0]["port"], 1080);
        assert_eq!(cfg["inbounds"][1]["port"], 1081);
    }
}
