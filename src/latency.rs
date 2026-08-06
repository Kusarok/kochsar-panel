//! Real-delay measurement: how long a request to a real destination actually
//! takes *through* each server.
//!
//! ## Why not a TCP handshake
//!
//! The obvious test -- open a TCP connection to the server's address and time
//! it -- is worse than useless on a censored network. The server's hostname
//! resolves to a nearby interception box that completes the handshake
//! instantly, so every server reports about 0 ms and the list looks perfect
//! while nothing works. That is a measurement of the censor, not the server.
//!
//! ## How this works
//!
//! One throwaway Xray instance is started with a SOCKS inbound per node and a
//! routing rule pinning each inbound to its own outbound. Every node is then
//! exercised concurrently with a real HTTPS request through its own port.
//! A number that comes back is proof the whole path works: handshake,
//! encryption, the remote server, and the destination.
//!
//! One process with N inbounds rather than N processes: on a router, starting
//! a Go binary per node would cost more than the measurement is worth.

use crate::model::{Node, Settings};
use crate::xray;
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Concurrent requests. Each is mostly network wait, but every one also drives
/// an encrypted tunnel, and the router has four cores.
const WORKERS: usize = 8;

/// Upper bound on nodes measured in one sweep.
///
/// Each costs an inbound and a listening port in the probe instance. Anything
/// past this is reported as skipped rather than silently dropped.
pub const MAX_NODES: usize = 120;

/// How long Xray gets to bind every inbound before requests start.
const STARTUP_GRACE: Duration = Duration::from_millis(700);

#[derive(Debug)]
pub struct Outcome {
    /// `(node id, milliseconds)`; negative values use [`Node`]'s sentinels.
    pub results: Vec<(String, i32)>,
    /// Nodes beyond [`MAX_NODES`] that were not measured.
    pub skipped: usize,
}

/// Measures every node against `url`.
///
/// Errors only when the sweep could not be set up at all. An individual node
/// that fails is reported as [`Node::LATENCY_FAILED`], which is the useful
/// answer -- "this server does not work" is exactly what the user asked.
pub fn measure(
    nodes: &[Node],
    settings: &Settings,
    runtime_dir: &Path,
    url: &str,
    timeout: Duration,
) -> Result<Outcome, String> {
    if nodes.is_empty() {
        return Err("there are no nodes to test".into());
    }
    let skipped = nodes.len().saturating_sub(MAX_NODES);
    let nodes = &nodes[..nodes.len().min(MAX_NODES)];

    let ports = reserve_ports(nodes.len(), settings.probe_base_port)?;
    let config = build_probe_config(nodes, &ports);

    // Same extension rule as the live config: Xray reads the format from it.
    let path = runtime_dir.join("probe.json");
    std::fs::create_dir_all(runtime_dir).map_err(|e| e.to_string())?;
    let body = serde_json::to_vec(&config).map_err(|e| e.to_string())?;
    xray::write_atomic(&path, &body).map_err(|e| format!("cannot write probe config: {e}"))?;

    let mut child = Probe::start(&settings.xray_bin, &path)?;
    thread::sleep(STARTUP_GRACE);

    let jobs: Vec<(String, u16)> = nodes
        .iter()
        .zip(&ports)
        .map(|(n, p)| (n.id.clone(), *p))
        .collect();
    let results = run_all(jobs, url, timeout);

    child.stop();
    let _ = std::fs::remove_file(&path);

    Ok(Outcome { results, skipped })
}

/// Finds `count` consecutive free ports starting at `base`.
///
/// Verified by actually binding them. There is a small window between the check
/// and Xray binding, but the alternative -- assuming a range is free -- fails
/// silently and reports every node as broken.
fn reserve_ports(count: usize, base: u16) -> Result<Vec<u16>, String> {
    for offset in (0..40u16).step_by(8) {
        let start = base.saturating_add(offset);
        if start.checked_add(count as u16).is_none() {
            break;
        }
        let ports: Vec<u16> = (start..start + count as u16).collect();
        let held: Vec<_> = ports
            .iter()
            .filter_map(|p| TcpListener::bind(("127.0.0.1", *p)).ok())
            .collect();
        let ok = held.len() == ports.len();
        drop(held);
        if ok {
            return Ok(ports);
        }
    }
    Err(format!(
        "cannot find {count} free ports near {base}; change the probe port in settings"
    ))
}

/// A config whose only job is to expose one SOCKS port per node.
fn build_probe_config(nodes: &[Node], ports: &[u16]) -> Value {
    let mut inbounds = Vec::with_capacity(nodes.len());
    let mut outbounds = Vec::with_capacity(nodes.len() + 1);
    let mut rules = Vec::with_capacity(nodes.len());

    for (i, (node, port)) in nodes.iter().zip(ports).enumerate() {
        let inb = format!("p{i}");
        let outb = format!("o{i}");
        inbounds.push(json!({
            "tag": inb,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            // No UDP and no sniffing: this only ever carries one HTTPS request,
            // and both would cost memory per inbound for nothing.
            "settings": { "auth": "noauth", "udp": false }
        }));
        outbounds.push(xray::probe_outbound(node, &outb));
        rules.push(json!({ "type": "field", "inboundTag": [inb], "outboundTag": outb }));
    }
    // Anything unrouted is dropped rather than leaking out directly, which
    // would make a broken node look like a working one.
    outbounds.push(json!({ "tag": "block", "protocol": "blackhole", "settings": {} }));

    json!({
        "log": { "loglevel": "none", "access": "none" },
        // Short timeouts: these connections live for one request.
        "policy": { "levels": { "0": { "handshake": 4, "connIdle": 30 } } },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "domainStrategy": "AsIs", "rules": rules }
    })
}

/// The throwaway Xray instance, stopped on drop so a panic cannot leak it.
struct Probe(Option<Child>);

impl Probe {
    fn start(bin: &str, config: &Path) -> Result<Self, String> {
        let mut cmd = Command::new(bin);
        cmd.arg("run")
            .arg("-c")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Keep the measurement from becoming the thing that OOMs the
            // router; this instance is short-lived and carries no real traffic.
            .env("GOMEMLIMIT", "64MiB");
        xray::set_die_with_parent(&mut cmd);

        let child = cmd
            .spawn()
            .map_err(|e| format!("cannot start the probe instance: {e}"))?;
        Ok(Probe(Some(child)))
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Runs every request through a bounded worker pool.
fn run_all(jobs: Vec<(String, u16)>, url: &str, timeout: Duration) -> Vec<(String, i32)> {
    let worker_count = WORKERS.min(jobs.len());
    let queue = Arc::new(Mutex::new(jobs.into_iter()));
    let (tx, rx) = mpsc::channel();

    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let url = url.to_string();
        handles.push(thread::spawn(move || loop {
            let job = {
                let Ok(mut q) = queue.lock() else { return };
                q.next()
            };
            let Some((id, port)) = job else { return };
            let ms = request_through(port, &url, timeout);
            if tx.send((id, ms)).is_err() {
                return;
            }
        }));
    }
    drop(tx);

    let results: Vec<(String, i32)> = rx.iter().collect();
    for h in handles {
        let _ = h.join();
    }
    results
}

/// One HTTPS request through a SOCKS port, in milliseconds.
///
/// `--socks5-hostname` matters: it hands the *name* to the proxy so the remote
/// server resolves it. Resolving locally would measure the censor's answer
/// again, which is the whole thing this module exists to avoid.
fn request_through(port: u16, url: &str, timeout: Duration) -> i32 {
    let out = Command::new("curl")
        .args([
            "--silent",
            "--output",
            "/dev/null",
            "--socks5-hostname",
            &format!("127.0.0.1:{port}"),
            "--max-time",
            &timeout.as_secs().max(1).to_string(),
            "--proto",
            "=http,https",
            "--write-out",
            "%{http_code} %{time_total}",
        ])
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .output();

    let Ok(out) = out else {
        return Node::LATENCY_FAILED;
    };
    if !out.status.success() {
        return Node::LATENCY_FAILED;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.split_whitespace();
    let code: u32 = parts.next().and_then(|c| c.parse().ok()).unwrap_or(0);
    let secs: f64 = parts.next().and_then(|t| t.parse().ok()).unwrap_or(0.0);

    // Any 2xx/3xx means the request completed end to end. A 4xx/5xx came from
    // somewhere -- often an interception page -- so it is not a working path.
    if !(200..400).contains(&code) {
        return Node::LATENCY_FAILED;
    }
    let ms = (secs * 1000.0).round();
    // A real request through a tunnel cannot take zero time; clamping to 1
    // keeps the display honest rather than showing the "0 ms" that a
    // handshake-only test produced against interception boxes.
    ms.clamp(1.0, i32::MAX as f64) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_uri;

    fn nodes(n: usize) -> Vec<Node> {
        (0..n)
            .map(|i| parse_uri(&format!("vless://u@h{i}.example:443?type=tcp#n{i}")).unwrap())
            .collect()
    }

    #[test]
    fn each_node_gets_its_own_port_and_route() {
        let ns = nodes(3);
        let ports = vec![24000, 24001, 24002];
        let cfg = build_probe_config(&ns, &ports);

        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 3);
        assert_eq!(inbounds[1]["port"], 24001);
        assert_eq!(inbounds[1]["tag"], "p1");
        assert_eq!(
            inbounds[1]["listen"], "127.0.0.1",
            "probe ports must not be reachable from the LAN"
        );

        // Rule i must pin inbound i to outbound i, or every node would be
        // measured through whichever server happens to be the default.
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        for i in 0..3 {
            assert_eq!(rules[i]["inboundTag"][0], format!("p{i}"));
            assert_eq!(rules[i]["outboundTag"], format!("o{i}"));
        }
        assert_eq!(cfg["outbounds"][1]["settings"]["vnext"][0]["address"], "h1.example");
    }

    /// Unrouted traffic must be blackholed. Letting it out directly would make
    /// a dead server report the latency of the router's own connection.
    #[test]
    fn unrouted_traffic_is_blocked_not_direct() {
        let cfg = build_probe_config(&nodes(2), &[24000, 24001]);
        let outs = cfg["outbounds"].as_array().unwrap();
        let last = outs.last().unwrap();
        assert_eq!(last["protocol"], "blackhole");
        assert!(!outs.iter().any(|o| o["protocol"] == "freedom"));
    }

    #[test]
    fn probe_config_is_quiet() {
        let cfg = build_probe_config(&nodes(1), &[24000]);
        assert_eq!(cfg["log"]["loglevel"], "none");
        assert_eq!(cfg["log"]["access"], "none");
    }

    #[test]
    fn reserving_ports_returns_a_contiguous_free_range() {
        let ports = reserve_ports(4, 24000).expect("should find four free ports");
        assert_eq!(ports.len(), 4);
        for w in ports.windows(2) {
            assert_eq!(w[1], w[0] + 1);
        }
        // And they really are bindable.
        for p in &ports {
            TcpListener::bind(("127.0.0.1", *p)).expect("port should be free");
        }
    }

    #[test]
    fn empty_input_is_an_error_not_an_empty_sweep() {
        let dir = std::env::temp_dir();
        let err = measure(&[], &Settings::default(), &dir, "https://x", Duration::from_secs(1))
            .unwrap_err();
        assert!(err.contains("no nodes"));
    }
}
