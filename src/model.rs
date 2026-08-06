//! Persisted data model.
//!
//! Optional fields are modelled as empty `String` rather than `Option<String>`.
//! Xray's own JSON is full of "omit when empty" semantics, the panel treats
//! missing and blank identically, and it keeps `serde` output flat for the
//! frontend. `latency` uses sentinels instead of `Option<u32>` for the same
//! reason -- see [`Node::LATENCY_UNTESTED`].

use serde::{Deserialize, Serialize};

/// A single proxy server.
///
/// Only VLESS is populated today; `protocol` exists so that adding VMess or
/// Trojan later is a parser change rather than a schema migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Stable id derived from the connection identity -- see [`Node::compute_id`].
    pub id: String,
    pub name: String,
    #[serde(default = "d_vless")]
    pub protocol: String,

    pub server: String,
    pub port: u16,
    pub uuid: String,

    /// XTLS flow, e.g. `xtls-rprx-vision`.
    #[serde(default)]
    pub flow: String,
    #[serde(default = "d_none")]
    pub encryption: String,

    // --- stream settings ---
    /// `tcp` | `ws` | `grpc` | `xhttp` | `httpupgrade`
    #[serde(default = "d_tcp")]
    pub network: String,
    /// `none` | `tls` | `reality`
    #[serde(default = "d_none")]
    pub security: String,
    #[serde(default)]
    pub sni: String,
    /// uTLS fingerprint, e.g. `chrome`.
    #[serde(default)]
    pub fingerprint: String,
    /// Comma-separated, as it arrives in the URI.
    #[serde(default)]
    pub alpn: String,
    /// REALITY public key (`pbk`).
    #[serde(default)]
    pub public_key: String,
    /// REALITY short id (`sid`).
    #[serde(default)]
    pub short_id: String,
    /// REALITY spiderX (`spx`).
    #[serde(default)]
    pub spider_x: String,
    /// ws/xhttp/httpupgrade path.
    #[serde(default)]
    pub path: String,
    /// Host header for ws/httpupgrade.
    #[serde(default)]
    pub host: String,
    /// gRPC service name.
    #[serde(default)]
    pub service_name: String,
    /// gRPC (`gun`/`multi`) or xhttp (`auto`/`packet-up`/`stream-up`) mode.
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub allow_insecure: bool,

    /// Owning subscription id; empty means the node was added by hand.
    #[serde(default)]
    pub sub_id: String,
    /// Measured TCP handshake latency in ms, or one of the sentinels below.
    #[serde(default = "d_untested")]
    pub latency: i32,
    /// The URI this node was parsed from, kept for round-tripping and export.
    #[serde(default)]
    pub raw: String,
}

fn d_vless() -> String {
    "vless".into()
}
fn d_none() -> String {
    "none".into()
}
fn d_tcp() -> String {
    "tcp".into()
}
fn d_untested() -> i32 {
    Node::LATENCY_UNTESTED
}

impl Default for Node {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            protocol: d_vless(),
            server: String::new(),
            port: 0,
            uuid: String::new(),
            flow: String::new(),
            encryption: d_none(),
            network: d_tcp(),
            security: d_none(),
            sni: String::new(),
            fingerprint: String::new(),
            alpn: String::new(),
            public_key: String::new(),
            short_id: String::new(),
            spider_x: String::new(),
            path: String::new(),
            host: String::new(),
            service_name: String::new(),
            mode: String::new(),
            allow_insecure: false,
            sub_id: String::new(),
            latency: Node::LATENCY_UNTESTED,
            raw: String::new(),
        }
    }
}

impl Node {
    /// Never probed, or invalidated by an edit.
    pub const LATENCY_UNTESTED: i32 = -1;
    /// Probed and unreachable.
    pub const LATENCY_FAILED: i32 = -2;

    /// Derives [`Node::id`] from the fields that define *which server this is*.
    ///
    /// Deliberately excludes `name`: subscription providers rename nodes
    /// constantly, and a name-sensitive id would drop the user's selection on
    /// every refresh. Two entries that differ only by remark collapse into one,
    /// which is the desired behaviour.
    pub fn compute_id(&self) -> String {
        let ident = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.protocol,
            self.server,
            self.port,
            self.uuid,
            self.network,
            self.security,
            self.path,
            self.service_name,
            self.short_id,
        );
        fnv1a_hex(ident.as_bytes())
    }

    /// Display host for the panel: SNI when it differs from the raw address.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

/// A remote list of nodes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    /// Unix seconds of the last successful fetch; 0 if never.
    #[serde(default)]
    pub last_update: u64,
    #[serde(default)]
    pub node_count: usize,
    /// Message from the most recent failed fetch; empty when healthy.
    #[serde(default)]
    pub last_error: String,
}

impl Subscription {
    pub fn compute_id(url: &str) -> String {
        fnv1a_hex(url.trim().as_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// SOCKS5 inbound that clients point at.
    pub socks_port: u16,
    /// HTTP inbound, for clients that cannot do SOCKS.
    pub http_port: u16,
    /// Bind the proxy inbounds to 0.0.0.0 rather than 127.0.0.1.
    pub allow_lan: bool,
    /// Key into [`crate::dnscfg::PRESETS`], or `custom`.
    pub dns_preset: String,
    /// Comma-separated servers, used when `dns_preset == "custom"`.
    pub dns_custom: String,
    pub xray_bin: String,
    pub log_level: String,

    // --- logging ---
    //
    // The log lives on tmpfs, which is RAM. On a 512MB router an unbounded log
    // at loglevel info is a slow out-of-memory, so it is off by default and
    // bounded twice over when on: by size and by age.
    /// Write Xray's output to a file at all. Off means Xray runs with
    /// `loglevel: none` and its output goes to `/dev/null` -- no file exists.
    #[serde(default)]
    pub log_enabled: bool,
    /// Truncate once the log passes this size.
    #[serde(default = "d_log_max_kb")]
    pub log_max_kb: u64,
    /// Truncate at least this often, even if the size cap is never reached.
    #[serde(default = "d_log_rotate_secs")]
    pub log_rotate_secs: u64,

    // --- resource containment ---
    //
    // Defaults here come from documented router failures, not guesswork; see
    // the citations on each field.
    /// Soft ceiling for Xray's Go heap, in MiB. 0 disables it.
    ///
    /// A soft limit makes Go collect harder as it approaches, trading CPU for
    /// memory; it never fails an allocation. 70 MiB is the lowest value
    /// reported working for a client config on a 512MB router
    /// (XTLS/Xray-core#3221), so this leaves headroom above that.
    #[serde(default = "d_go_mem_limit")]
    pub go_mem_limit_mb: u64,
    /// Hard address-space ceiling for Xray, in MiB. 0 disables it.
    ///
    /// Off by default: it is a backstop for a genuine runaway, and set too low
    /// it kills a healthy core.
    #[serde(default)]
    pub mem_hard_cap_mb: u64,
    /// Seconds an idle connection is held before Xray reclaims it.
    ///
    /// This is the single most important knob on a transparent-proxy router.
    /// TPROXY UDP has no close signal, so Xray keeps one socket per 4-tuple
    /// until this expires; at the stock 300s a torrent client outruns
    /// reclamation and the router dies of socket exhaustion or OOM
    /// (XTLS/Xray-core#5263, #4586, #4194 — maintainer-diagnosed).
    #[serde(default = "d_conn_idle")]
    pub conn_idle_secs: u32,
    /// Use sniffed domains for routing only, leaving the destination address
    /// alone.
    ///
    /// Overriding the destination breaks Tor, Apple push, and several IoT
    /// devices (Xray inbound docs). Passwall2 ships route-only for the same
    /// reason, and so do we.
    #[serde(default = "d_true")]
    pub sniff_route_only: bool,

    // --- transparent proxy ---
    /// Intercept LAN traffic instead of requiring clients to set a proxy.
    /// Off by default: enabling it rewrites the router's packet path.
    #[serde(default)]
    pub transparent: bool,
    /// Xray's TPROXY inbound port.
    #[serde(default = "d_tproxy_port")]
    pub tproxy_port: u16,
    /// Comma-separated interfaces to intercept, e.g. `br-lan`.
    #[serde(default = "d_lan_interfaces")]
    pub lan_interfaces: String,
    /// Tunnel IPv6 as well as IPv4. Off by default -- the router's current
    /// Passwall2 setup leaves IPv6 direct, and matching that avoids a surprise.
    #[serde(default)]
    pub tunnel_ipv6: bool,
    /// Port of Xray's DNS inbound, which dnsmasq forwards the LAN's queries to.
    #[serde(default = "d_dns_port")]
    pub dns_port: u16,
    /// Key into [`crate::dnscfg::TEST_TARGETS`], or `custom`.
    #[serde(default = "d_test_target")]
    pub test_target: String,
    /// Used when `test_target == "custom"`.
    #[serde(default)]
    pub test_url_custom: String,
    /// First port of the range the latency probe binds, one per node.
    #[serde(default = "d_probe_base_port")]
    pub probe_base_port: u16,
    /// Resolver used for the proxy servers' own hostnames, queried directly
    /// rather than through the tunnel.
    ///
    /// Required to break the resolution deadlock: with `no-resolv`, dnsmasq's
    /// only upstream is Xray, and Xray cannot answer until it has connected to
    /// a server whose address it cannot resolve. See [`crate::dnsmasq::install`].
    #[serde(default = "d_bypass_resolver")]
    pub dns_bypass_resolver: String,
    /// Redirect every LAN query to the router's resolver.
    ///
    /// On by default: a device with a hardcoded public resolver would otherwise
    /// resolve names outside the tunnel, and the tunnel would then faithfully
    /// carry the connection to whatever address it was handed.
    #[serde(default = "d_true")]
    pub dns_redirect: bool,
}

fn d_tproxy_port() -> u16 {
    12345
}
/// 256 KB of tmpfs is a rounding error against 512 MB of RAM, and still holds
/// several thousand lines -- far more than anyone reads when debugging.
fn d_log_max_kb() -> u64 {
    256
}
fn d_log_rotate_secs() -> u64 {
    120
}
fn d_go_mem_limit() -> u64 {
    96
}
/// Well below Xray's 300s default, which is what lets UDP sockets pile up
/// faster than they are reclaimed. Maintainers suggested testing as low as 30.
fn d_conn_idle() -> u32 {
    120
}
fn d_true() -> bool {
    true
}
/// Loopback-only, so the choice just has to avoid the usual suspects.
fn d_dns_port() -> u16 {
    5353
}
fn d_test_target() -> String {
    "google".into()
}
fn d_bypass_resolver() -> String {
    "1.1.1.1".into()
}
/// High and unremarkable; only ever bound on loopback and only during a sweep.
fn d_probe_base_port() -> u16 {
    24000
}
fn d_lan_interfaces() -> String {
    "br-lan".into()
}

impl Settings {
    /// LAN interfaces as a list, blanks removed.
    pub fn lan_list(&self) -> Vec<String> {
        self.lan_interfaces
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            socks_port: 1080,
            http_port: 1081,
            allow_lan: true,
            dns_preset: "cloudflare".into(),
            dns_custom: String::new(),
            xray_bin: "/usr/bin/xray".into(),
            log_level: "warning".into(),
            log_enabled: false,
            log_max_kb: d_log_max_kb(),
            log_rotate_secs: d_log_rotate_secs(),
            go_mem_limit_mb: d_go_mem_limit(),
            mem_hard_cap_mb: 0,
            conn_idle_secs: d_conn_idle(),
            sniff_route_only: true,
            transparent: false,
            tproxy_port: d_tproxy_port(),
            lan_interfaces: d_lan_interfaces(),
            tunnel_ipv6: false,
            dns_port: d_dns_port(),
            dns_redirect: true,
            dns_bypass_resolver: d_bypass_resolver(),
            test_target: d_test_target(),
            test_url_custom: String::new(),
            probe_base_port: d_probe_base_port(),
        }
    }
}

/// Everything that survives a restart.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub subs: Vec<Subscription>,
    #[serde(default)]
    pub settings: Settings,
    /// Id of the selected node; empty when nothing is selected.
    #[serde(default)]
    pub active: String,
    /// Shared secret for the panel, generated on first run.
    ///
    /// Lives on [`State`] rather than [`Settings`] so it cannot be returned by
    /// `/api/state`, which serialises settings wholesale.
    #[serde(default)]
    pub panel_token: String,
}

/// Generates a panel token from the kernel's entropy pool.
///
/// Falls back to nothing on failure rather than to a weak value: an empty
/// token makes the daemon refuse to serve, which is a visible failure instead
/// of a guessable secret.
pub fn generate_token() -> String {
    let mut buf = [0u8; 16];
    match std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
    {
        Ok(()) => buf.iter().map(|b| format!("{b:02x}")).collect(),
        Err(_) => String::new(),
    }
}

impl State {
    pub fn find(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Inserts `incoming`, replacing any node with the same identity.
    ///
    /// Carries the previous latency across so a subscription refresh does not
    /// blank out the whole list's timings.
    pub fn upsert(&mut self, mut incoming: Node) {
        incoming.id = incoming.compute_id();
        if let Some(slot) = self.nodes.iter_mut().find(|n| n.id == incoming.id) {
            incoming.latency = slot.latency;
            *slot = incoming;
        } else {
            self.nodes.push(incoming);
        }
    }
}

/// FNV-1a, 64-bit, hex encoded.
///
/// Ids only need to be stable and collision-resistant enough to distinguish a
/// few hundred servers, so this avoids pulling in a hashing crate.
fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}
