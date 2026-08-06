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
    let node = state.find(&state.active)?;
    let s = &state.settings;
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
/// `bufferSize` is deliberately NOT set. On 32-bit ARM Xray already defaults to
/// no internal buffer, and the value `0` now means *unlimited* rather than
/// *disabled* -- so copying the widely-repeated "set bufferSize low on routers"
/// advice from x86 guides would make memory use worse, not better.
fn build_policy(conn_idle_secs: u32) -> Value {
    json!({
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": conn_idle_secs,
                "uplinkOnly": 2,
                "downlinkOnly": 2
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

/// An outbound for the latency probe: the same server, a different tag, and
/// none of the transparent-mode socket marking (the probe never touches the
/// firewall, so a mark would only confuse things).
pub fn probe_outbound(node: &Node, tag: &str) -> Value {
    json!({
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": node.server,
                "port": node.port,
                "users": [build_user(node)]
            }]
        },
        "streamSettings": build_stream(node)
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
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": node.server,
                "port": node.port,
                "users": [build_user(node)]
            }]
        },
        "streamSettings": stream
    })
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
    let mut stream = Map::new();
    stream.insert("network".into(), json!(node.network));
    stream.insert("security".into(), json!(non_empty(&node.security, "none")));

    match node.security.as_str() {
        "reality" => {
            let mut r = Map::new();
            r.insert("serverName".into(), json!(node.sni));
            r.insert("publicKey".into(), json!(node.public_key));
            r.insert("shortId".into(), json!(node.short_id));
            r.insert("spiderX".into(), json!(non_empty(&node.spider_x, "/")));
            // Xray rejects an empty fingerprint for REALITY.
            r.insert(
                "fingerprint".into(),
                json!(non_empty(&node.fingerprint, "chrome")),
            );
            stream.insert("realitySettings".into(), Value::Object(r));
        }
        "tls" => {
            let mut t = Map::new();
            // Fall back to the Host header, then the address, mirroring what
            // clients do when a link omits `sni`.
            let sni = if !node.sni.is_empty() {
                &node.sni
            } else if !node.host.is_empty() {
                &node.host
            } else {
                &node.server
            };
            t.insert("serverName".into(), json!(sni));
            t.insert("allowInsecure".into(), json!(node.allow_insecure));
            if !node.fingerprint.is_empty() {
                t.insert("fingerprint".into(), json!(node.fingerprint));
            }
            let alpn: Vec<&str> = node
                .alpn
                .split(',')
                .map(|a| a.trim())
                .filter(|a| !a.is_empty())
                .collect();
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
            stream.insert("grpcSettings".into(), Value::Object(g));
        }
        "xhttp" | "splithttp" => {
            let mut x = Map::new();
            x.insert("path".into(), json!(non_empty(&node.path, "/")));
            if !node.host.is_empty() {
                x.insert("host".into(), json!(node.host));
            }
            x.insert("mode".into(), json!(non_empty(&node.mode, "auto")));
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
        // Plain TCP needs no extra block.
        _ => {}
    }

    Value::Object(stream)
}

fn non_empty<'a>(v: &'a str, default: &'a str) -> &'a str {
    if v.is_empty() {
        default
    } else {
        v
    }
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
            let _ = child.kill();
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
            "vless://uu@ex.com:443?security=reality&pbk=KEY&sid=ab12&sni=www.apple.com\
             &flow=xtls-rprx-vision&type=tcp#n",
        );
        let cfg = build_config(&s).unwrap();
        let ob = &cfg["outbounds"][0];
        assert_eq!(ob["protocol"], "vless");
        assert_eq!(ob["settings"]["vnext"][0]["address"], "ex.com");
        assert_eq!(ob["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        let r = &ob["streamSettings"]["realitySettings"];
        assert_eq!(r["publicKey"], "KEY");
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
        let mut s = state_with("vless://uu@ex.com:443?type=tcp&security=reality&pbk=K#n");
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
