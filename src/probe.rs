//! Latency probing.
//!
//! Measures the TCP handshake to each server, which is the same "tcping" signal
//! v2rayNG and Passwall2 show by default. It costs one round trip per node and
//! needs no running proxy, so the whole list can be ranked before connecting.
//!
//! It does *not* measure end-to-end proxy latency -- a reachable server can
//! still fail to authenticate. Real-delay probing belongs with the transparent
//! proxy work.

use crate::model::Node;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Concurrent probes. Chosen to keep a 4-core router responsive while still
/// finishing a 100-node subscription in a few seconds.
const WORKERS: usize = 16;

#[derive(Debug, Clone)]
pub struct Job {
    pub id: String,
    pub host: String,
    pub port: u16,
}

impl From<&Node> for Job {
    fn from(n: &Node) -> Self {
        Job {
            id: n.id.clone(),
            host: n.server.clone(),
            port: n.port,
        }
    }
}

/// Probes every job and returns `(node id, latency)` pairs.
///
/// Latency is milliseconds, or [`Node::LATENCY_FAILED`] when the server is
/// unreachable within `timeout`.
pub fn probe_many(jobs: Vec<Job>, timeout: Duration) -> Vec<(String, i32)> {
    if jobs.is_empty() {
        return Vec::new();
    }

    let worker_count = WORKERS.min(jobs.len());
    let queue = Arc::new(Mutex::new(jobs.into_iter()));
    let (tx, rx) = mpsc::channel();

    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        handles.push(thread::spawn(move || loop {
            // Scoped so the lock is released before the (slow) probe runs.
            let job = {
                let mut q = match queue.lock() {
                    Ok(q) => q,
                    // A poisoned queue means another worker panicked; stop
                    // rather than risk probing the same job twice.
                    Err(_) => return,
                };
                q.next()
            };
            let Some(job) = job else { return };
            let result = probe_one(&job.host, job.port, timeout);
            if tx.send((job.id, result)).is_err() {
                return; // receiver dropped
            }
        }));
    }
    // Drop the original sender or the receive loop below never terminates.
    drop(tx);

    let results: Vec<(String, i32)> = rx.iter().collect();
    for h in handles {
        let _ = h.join();
    }
    results
}

/// Every address a hostname resolves to.
///
/// Used to bypass the proxy server in the transparent-proxy ruleset, so it must
/// return *all* addresses -- missing one leaves a path where Xray's own traffic
/// gets intercepted and the router recurses.
pub fn resolve_all(host: &str) -> Vec<std::net::IpAddr> {
    // A literal address needs no lookup, and `to_socket_addrs` on one still
    // costs a getaddrinfo round trip.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip];
    }
    // Port 0 is a placeholder; only the addresses matter.
    (host, 0u16)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// One TCP handshake, in milliseconds.
fn probe_one(host: &str, port: u16, timeout: Duration) -> i32 {
    // Resolve first so DNS time is excluded from the measurement -- otherwise a
    // cold cache makes a fast server look slow.
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return Node::LATENCY_FAILED;
    };

    let mut best = Node::LATENCY_FAILED;
    for addr in addrs {
        let start = Instant::now();
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            let ms = start.elapsed().as_millis().min(i32::MAX as u128) as i32;
            // A dual-stack host may resolve to several addresses; report the
            // best, since that is the one a client would end up using.
            if best == Node::LATENCY_FAILED || ms < best {
                best = ms;
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn empty_input_returns_empty() {
        assert!(probe_many(Vec::new(), Duration::from_millis(100)).is_empty());
    }

    #[test]
    fn reachable_port_reports_latency() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let jobs = vec![Job {
            id: "ok".into(),
            host: "127.0.0.1".into(),
            port,
        }];
        let out = probe_many(jobs, Duration::from_secs(2));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "ok");
        assert!(out[0].1 >= 0, "expected a latency, got {}", out[0].1);
    }

    #[test]
    fn unresolvable_host_reports_failure() {
        let jobs = vec![Job {
            id: "bad".into(),
            host: "no-such-host.invalid".into(),
            port: 443,
        }];
        let out = probe_many(jobs, Duration::from_millis(500));
        assert_eq!(out[0].1, Node::LATENCY_FAILED);
    }

    #[test]
    fn all_jobs_are_reported_exactly_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let jobs: Vec<Job> = (0..40)
            .map(|i| Job {
                id: format!("n{i}"),
                host: "127.0.0.1".into(),
                port,
            })
            .collect();

        let out = probe_many(jobs, Duration::from_secs(2));
        assert_eq!(out.len(), 40, "every job must produce exactly one result");
        let mut ids: Vec<_> = out.into_iter().map(|(id, _)| id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 40, "no job may be probed twice");
    }
}
