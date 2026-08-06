//! Application state: persistence plus the operations the API exposes.
//!
//! Everything here is fast and synchronous. Slow work -- fetching a
//! subscription, probing latency -- is deliberately *not* a method on [`App`],
//! because [`App`] lives behind a mutex and holding it across the network would
//! freeze the panel. Those flows snapshot what they need, release the lock, do
//! the slow part, then hand results back through [`App::apply_sub_body`] and
//! [`App::apply_latencies`].

use crate::model::{Node, State, Subscription};
use crate::parse;
use crate::xray::{self, Paths, Supervisor};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// What a subscription refresh produced, for display in the panel.
#[derive(Debug, Default)]
pub struct SubSummary {
    pub imported: usize,
    pub removed: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

pub struct App {
    pub state: State,
    pub sup: Supervisor,
    /// Reverts an unconfirmed transparent-proxy change. See
    /// [`crate::tproxy::Watchdog`].
    pub tproxy_guard: crate::tproxy::Watchdog,
    /// Unix seconds by which a pending transparent-proxy change must be
    /// confirmed; 0 when nothing is pending.
    pub tproxy_deadline: u64,
    /// Whether our nftables table is loaded.
    ///
    /// Cached because answering it forks `nft`, and the panel polls state every
    /// six seconds. Refreshed by the handlers that can change it.
    pub tproxy_applied: bool,
    /// Whether dnsmasq is currently forwarding the LAN's queries to Xray.
    pub dns_via_tunnel: bool,
    /// Liveness counters kept by [`crate::health`].
    pub health: crate::health::Status,
    /// Set while a latency sweep is running, so a user hammering "test all"
    /// cannot pin every worker thread at once.
    pub probing: Arc<AtomicBool>,
    state_path: PathBuf,
}

impl App {
    /// Loads persisted state, or starts from defaults if there is none.
    ///
    /// A corrupt state file is reported but not fatal: the daemon comes up
    /// empty rather than refusing to start, which on a router is the difference
    /// between a fixable panel and an unreachable one.
    pub fn load(state_path: PathBuf, runtime_dir: &Path) -> (Self, Option<String>) {
        let mut warning = None;
        let state = match fs::read_to_string(&state_path) {
            Ok(text) => match serde_json::from_str::<State>(&text) {
                Ok(s) => s,
                Err(e) => {
                    warning = Some(format!(
                        "{} is not valid JSON ({e}); starting with empty state",
                        state_path.display()
                    ));
                    State::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => {
                warning = Some(format!("cannot read {}: {e}", state_path.display()));
                State::default()
            }
        };

        let mut state = state;
        // State written before `mode` existed carries only `transparent`.
        if state.settings.mode.is_empty() {
            state.settings.mode = if state.settings.transparent { "global" } else { "proxy" }.into();
        }
        // `mode` is what the user sets; `transparent` is what the rules read.
        // Deriving one from the other here means there is only ever one answer.
        state.settings.transparent = state.settings.mode == "global";

        let app = App {
            state,
            sup: Supervisor::new(Paths::new(runtime_dir)),
            tproxy_guard: crate::tproxy::Watchdog::new(),
            tproxy_deadline: 0,
            tproxy_applied: false,
            dns_via_tunnel: false,
            health: crate::health::Status::default(),
            probing: Arc::new(AtomicBool::new(false)),
            state_path,
        };
        (app, warning)
    }

    /// Hostname of the active server, for the caller to resolve.
    ///
    /// Returns the name rather than the addresses because resolving blocks --
    /// on musl for up to five seconds against a flaky upstream -- and this
    /// method is reached while the state lock is held. Resolve with
    /// [`crate::probe::resolve_all`] after dropping the guard.
    pub fn active_server_host(&self) -> Option<String> {
        self.state.find(&self.state.active).map(|n| n.server.clone())
    }

    /// Hostnames of every configured server, for the DNS bypass rules.
    ///
    /// All of them, not just the active one: switching servers must not require
    /// a DNS round trip that cannot complete.
    pub fn server_hostnames(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .state
            .nodes
            .iter()
            .map(|n| n.server.clone())
            .filter(|h| is_resolvable_hostname(h))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Builds the ruleset plan. `server_ips` comes from
    /// [`App::active_server_ips`], resolved outside the lock.
    pub fn tproxy_plan(&self, server_ips: Vec<std::net::IpAddr>) -> crate::tproxy::Plan {
        let s = &self.state.settings;
        crate::tproxy::Plan {
            port: s.tproxy_port,
            lan_interfaces: s.lan_list(),
            server_ips,
            tunnel_ipv6: s.tunnel_ipv6,
            dns_redirect: s.dns_redirect,
            route_router_traffic: s.route_router_traffic,
            dns_bypass_resolver: s.bypass_resolver().parse().ok(),
        }
    }

    /// Path of the previous-generation backup.
    pub fn backup_path(&self) -> PathBuf {
        self.state_path.with_extension("json.bak")
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(dir) = self.state_path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }

        // Retyping a server list is miserable, so keep one generation back.
        // Only overwrite the backup when the outgoing state still had nodes:
        // that way a wipe cannot cascade into the backup on the next save and
        // destroy the only remaining copy.
        if let Ok(previous) = fs::read(&self.state_path) {
            let had_nodes = serde_json::from_slice::<State>(&previous)
                .map(|s| !s.nodes.is_empty())
                .unwrap_or(false);
            if had_nodes {
                let _ = fs::write(self.backup_path(), &previous);
            }
            // Losing every node is either a bug or a mistake, and both are
            // easier to deal with if the moment is on the record.
            if had_nodes && self.state.nodes.is_empty() {
                eprintln!(
                    "xrayop: node list went from populated to empty; previous state kept at {}",
                    self.backup_path().display()
                );
            }
        }

        let body = serde_json::to_vec_pretty(&self.state).map_err(|e| e.to_string())?;
        xray::write_atomic(&self.state_path, &body)
            .map_err(|e| format!("cannot write {}: {e}", self.state_path.display()))
    }

    /// Replaces live state with the backup generation.
    pub fn restore_backup(&mut self) -> Result<usize, String> {
        let text = fs::read_to_string(self.backup_path())
            .map_err(|e| format!("no backup to restore: {e}"))?;
        let restored: State =
            serde_json::from_str(&text).map_err(|e| format!("backup is not valid JSON: {e}"))?;
        let count = restored.nodes.len();
        self.state = restored;
        Ok(count)
    }

    /// Persists, then rebuilds and restarts Xray.
    ///
    /// Saving first means a failure to start still leaves the user's choice on
    /// disk, so the panel reflects what they picked and shows why it failed.
    pub fn save_and_apply(&mut self) -> Result<(), String> {
        self.save()?;
        let state = self.state.clone();
        self.sup.apply(&state)
    }

    // --- subscriptions ---

    /// Registers a subscription without fetching it. Returns its id.
    ///
    /// Re-adding a known URL is a no-op that returns the existing id, so the
    /// caller can treat "add" as idempotent and just refresh afterwards.
    pub fn add_sub(&mut self, url: &str, name: &str) -> Result<String, String> {
        let url = url.trim();
        if url.is_empty() {
            return Err("subscription URL is empty".into());
        }
        let id = Subscription::compute_id(url);
        if let Some(existing) = self.state.subs.iter_mut().find(|s| s.id == id) {
            if !name.trim().is_empty() {
                existing.name = name.trim().to_string();
            }
            return Ok(id);
        }
        let display = if name.trim().is_empty() {
            short_label(url)
        } else {
            name.trim().to_string()
        };
        self.state.subs.push(Subscription {
            id: id.clone(),
            name: display,
            url: url.to_string(),
            ..Default::default()
        });
        Ok(id)
    }

    pub fn sub_url(&self, id: &str) -> Option<String> {
        self.state.subs.iter().find(|s| s.id == id).map(|s| s.url.clone())
    }

    /// Merges a freshly fetched subscription body into the node list.
    ///
    /// Nodes that vanished upstream are dropped, nodes that are still there
    /// keep their measured latency, and manually added nodes are untouched.
    pub fn apply_sub_body(&mut self, sub_id: &str, body: &str) -> SubSummary {
        let parsed = parse::parse_subscription(body);
        let mut summary = SubSummary {
            skipped: parsed.skipped,
            errors: parsed
                .errors
                .iter()
                .map(|(line, msg)| format!("line {line}: {msg}"))
                .collect(),
            ..Default::default()
        };

        let mut incoming: Vec<Node> = Vec::with_capacity(parsed.nodes.len());
        let mut fresh_ids: HashSet<String> = HashSet::new();
        for mut n in parsed.nodes {
            n.sub_id = sub_id.to_string();
            n.id = n.compute_id();
            // Guard against a provider listing the same server twice.
            if fresh_ids.insert(n.id.clone()) {
                incoming.push(n);
            }
        }

        let before = self.state.nodes.len();
        self.state
            .nodes
            .retain(|n| n.sub_id != sub_id || fresh_ids.contains(&n.id));
        summary.removed = before.saturating_sub(self.state.nodes.len());

        summary.imported = incoming.len();
        for n in incoming {
            self.state.upsert(n);
        }

        if let Some(sub) = self.state.subs.iter_mut().find(|s| s.id == sub_id) {
            sub.node_count = summary.imported;
            sub.last_update = xray::now_secs();
            sub.last_error.clear();
        }
        summary
    }

    pub fn set_sub_error(&mut self, sub_id: &str, error: &str) {
        if let Some(sub) = self.state.subs.iter_mut().find(|s| s.id == sub_id) {
            sub.last_error = error.to_string();
        }
    }

    /// Removes a subscription and every node that came from it.
    pub fn remove_sub(&mut self, id: &str) -> bool {
        let before = self.state.subs.len();
        self.state.subs.retain(|s| s.id != id);
        if self.state.subs.len() == before {
            return false;
        }
        self.state.nodes.retain(|n| n.sub_id != id);
        self.clear_active_if_gone();
        true
    }

    // --- nodes ---

    /// Imports one or more share links pasted by hand.
    ///
    /// Accepts a multi-line paste and a raw base64 blob, since that is what
    /// people copy out of chat apps.
    pub fn add_nodes_from_text(&mut self, text: &str) -> SubSummary {
        let parsed = parse::parse_subscription(text);
        let mut summary = SubSummary {
            skipped: parsed.skipped,
            errors: parsed
                .errors
                .iter()
                .map(|(line, msg)| format!("line {line}: {msg}"))
                .collect(),
            ..Default::default()
        };
        for mut n in parsed.nodes {
            n.sub_id = String::new(); // manual
            self.state.upsert(n);
            summary.imported += 1;
        }
        summary
    }

    pub fn remove_node(&mut self, id: &str) -> bool {
        let before = self.state.nodes.len();
        self.state.nodes.retain(|n| n.id != id);
        if self.state.nodes.len() == before {
            return false;
        }
        self.clear_active_if_gone();
        true
    }

    pub fn select(&mut self, id: &str) -> Result<(), String> {
        if self.state.find(id).is_none() {
            return Err("no such node".into());
        }
        self.state.active = id.to_string();
        Ok(())
    }

    /// Writes probe results back. Unknown ids are ignored, since the list may
    /// have changed while the sweep was running.
    pub fn apply_latencies(&mut self, results: Vec<(String, i32)>) {
        for (id, latency) in results {
            if let Some(node) = self.state.nodes.iter_mut().find(|n| n.id == id) {
                node.latency = latency;
            }
        }
    }

    /// Picks the reachable node with the lowest latency.
    pub fn fastest(&self) -> Option<&Node> {
        self.state
            .nodes
            .iter()
            .filter(|n| n.latency >= 0)
            .min_by_key(|n| n.latency)
    }

    fn clear_active_if_gone(&mut self) {
        if !self.state.active.is_empty() && self.state.find(&self.state.active).is_none() {
            self.state.active.clear();
        }
    }
}

/// Whether `host` is something worth writing a dnsmasq rule for.
///
/// Subscriptions carry entries that are not servers at all -- providers put
/// notices in the node list, and one on this router parses to a server field of
/// `1405-06-12`. A rule for a name that cannot exist is harmless but it is
/// noise in a generated config, and noise is where real problems hide.
///
/// A literal address is excluded for the opposite reason: it needs no
/// resolution, so a rule for it would be meaningless.
fn is_resolvable_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.len() <= 253
        && host
            .split('.')
            .all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
        // A trailing all-numeric label means it is an address-like string, not
        // a hostname.
        && !host
            .rsplit('.')
            .next()
            .map(|tld| tld.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(true)
}

/// A readable label for a subscription URL: host plus the last path segment.
fn short_label(url: &str) -> String {
    let rest = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url);
    let host = rest.split(['/', '?']).next().unwrap_or(rest);
    if host.is_empty() {
        "subscription".to_string()
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let dir = std::env::temp_dir().join(format!("xrayop-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        App::load(dir.join("state.json"), &dir).0
    }

    const A: &str = "vless://u@a.com:443?type=tcp#A";
    const B: &str = "vless://u@b.com:443?type=tcp#B";
    const C: &str = "vless://u@c.com:443?type=tcp#C";

    #[test]
    fn adding_a_subscription_is_idempotent() {
        let mut app = app();
        let id1 = app.add_sub("https://ex.com/sub", "First").unwrap();
        let id2 = app.add_sub("https://ex.com/sub", "Renamed").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(app.state.subs.len(), 1);
        assert_eq!(app.state.subs[0].name, "Renamed");
    }

    #[test]
    fn refresh_drops_nodes_that_vanished_upstream() {
        let mut app = app();
        let id = app.add_sub("https://ex.com/sub", "").unwrap();

        let first = app.apply_sub_body(&id, &format!("{A}\n{B}"));
        assert_eq!(first.imported, 2);
        assert_eq!(app.state.nodes.len(), 2);

        let second = app.apply_sub_body(&id, &format!("{A}\n{C}"));
        assert_eq!(second.imported, 2);
        assert_eq!(second.removed, 1, "B disappeared upstream");
        let names: Vec<_> = app.state.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"A") && names.contains(&"C") && !names.contains(&"B"));
    }

    #[test]
    fn refresh_preserves_measured_latency() {
        let mut app = app();
        let id = app.add_sub("https://ex.com/sub", "").unwrap();
        app.apply_sub_body(&id, A);
        let node_id = app.state.nodes[0].id.clone();
        app.apply_latencies(vec![(node_id.clone(), 42)]);

        app.apply_sub_body(&id, A);
        assert_eq!(app.state.nodes[0].latency, 42, "refresh must not reset timings");
    }

    #[test]
    fn refresh_leaves_manual_nodes_alone() {
        let mut app = app();
        app.add_nodes_from_text(C);
        let id = app.add_sub("https://ex.com/sub", "").unwrap();
        app.apply_sub_body(&id, A);
        app.apply_sub_body(&id, B);

        let manual: Vec<_> = app.state.nodes.iter().filter(|n| n.sub_id.is_empty()).collect();
        assert_eq!(manual.len(), 1, "manual node must survive refreshes");
        assert_eq!(manual[0].name, "C");
    }

    #[test]
    fn duplicate_entries_in_one_body_collapse() {
        let mut app = app();
        let id = app.add_sub("https://ex.com/sub", "").unwrap();
        let s = app.apply_sub_body(&id, &format!("{A}\n{A}"));
        assert_eq!(s.imported, 1);
        assert_eq!(app.state.nodes.len(), 1);
    }

    #[test]
    fn removing_a_subscription_removes_its_nodes_and_selection() {
        let mut app = app();
        let id = app.add_sub("https://ex.com/sub", "").unwrap();
        app.apply_sub_body(&id, &format!("{A}\n{B}"));
        let first = app.state.nodes[0].id.clone();
        app.select(&first).unwrap();

        assert!(app.remove_sub(&id));
        assert!(app.state.nodes.is_empty());
        assert!(app.state.active.is_empty(), "stale selection must be cleared");
    }

    #[test]
    fn removing_the_active_node_clears_selection() {
        let mut app = app();
        app.add_nodes_from_text(&format!("{A}\n{B}"));
        let id = app.state.nodes[0].id.clone();
        app.select(&id).unwrap();
        assert!(app.remove_node(&id));
        assert!(app.state.active.is_empty());
    }

    #[test]
    fn selecting_an_unknown_node_fails() {
        assert!(app().select("nope").is_err());
    }

    #[test]
    fn fastest_ignores_failed_and_untested() {
        let mut app = app();
        app.add_nodes_from_text(&format!("{A}\n{B}\n{C}"));
        let ids: Vec<_> = app.state.nodes.iter().map(|n| n.id.clone()).collect();
        app.apply_latencies(vec![
            (ids[0].clone(), Node::LATENCY_FAILED),
            (ids[1].clone(), 120),
            // ids[2] stays untested
        ]);
        assert_eq!(app.fastest().unwrap().id, ids[1]);
    }

    #[test]
    fn stale_latency_results_are_ignored() {
        let mut app = app();
        app.add_nodes_from_text(A);
        app.apply_latencies(vec![("gone".into(), 10)]);
        assert_eq!(app.state.nodes[0].latency, Node::LATENCY_UNTESTED);
    }

    #[test]
    fn manual_import_reports_bad_lines() {
        let mut app = app();
        let s = app.add_nodes_from_text(&format!("{A}\nvless://broken\ntrojan://x@h:1#t"));
        assert_eq!(s.imported, 1);
        assert_eq!(s.errors.len(), 1);
        assert_eq!(s.skipped, 1);
    }

    fn app_at(dir: &std::path::Path) -> App {
        let _ = fs::create_dir_all(dir);
        App::load(dir.join("state.json"), dir).0
    }

    #[test]
    fn save_keeps_one_generation_of_backup() {
        let dir = std::env::temp_dir().join("xrayop-backup-test");
        let _ = fs::remove_dir_all(&dir);
        let mut app = app_at(&dir);

        app.add_nodes_from_text(&format!("{A}\n{B}"));
        app.save().unwrap();
        assert!(!app.backup_path().exists(), "nothing to back up on first save");

        app.add_nodes_from_text(C);
        app.save().unwrap();
        let backup: State =
            serde_json::from_str(&fs::read_to_string(app.backup_path()).unwrap()).unwrap();
        assert_eq!(backup.nodes.len(), 2, "backup holds the previous generation");
    }

    /// The backup is worthless if a wipe overwrites it on the following save.
    #[test]
    fn a_wipe_cannot_cascade_into_the_backup() {
        let dir = std::env::temp_dir().join("xrayop-cascade-test");
        let _ = fs::remove_dir_all(&dir);
        let mut app = app_at(&dir);

        app.add_nodes_from_text(&format!("{A}\n{B}\n{C}"));
        app.save().unwrap();
        app.state.nodes.clear();
        app.save().unwrap(); // backup now holds the 3 nodes
        app.save().unwrap(); // a second empty save must not clobber it
        app.save().unwrap();

        let backup: State =
            serde_json::from_str(&fs::read_to_string(app.backup_path()).unwrap()).unwrap();
        assert_eq!(backup.nodes.len(), 3, "the last populated state must survive");
    }

    #[test]
    fn backup_can_be_restored() {
        let dir = std::env::temp_dir().join("xrayop-restore-test");
        let _ = fs::remove_dir_all(&dir);
        let mut app = app_at(&dir);

        app.add_nodes_from_text(&format!("{A}\n{B}"));
        app.save().unwrap();
        app.state.nodes.clear();
        app.save().unwrap();

        assert_eq!(app.restore_backup().unwrap(), 2);
        assert_eq!(app.state.nodes.len(), 2);
    }

    #[test]
    fn restoring_without_a_backup_is_an_error_not_a_wipe() {
        let dir = std::env::temp_dir().join("xrayop-nobackup-test");
        let _ = fs::remove_dir_all(&dir);
        let mut app = app_at(&dir);
        app.add_nodes_from_text(A);
        assert!(app.restore_backup().is_err());
        assert_eq!(app.state.nodes.len(), 1, "live state must be untouched");
    }

    #[test]
    fn corrupt_state_file_does_not_prevent_startup() {
        let dir = std::env::temp_dir().join("xrayop-corrupt-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("state.json");
        fs::write(&path, b"{not json").unwrap();
        let (app, warning) = App::load(path, &dir);
        assert!(warning.is_some(), "should report the problem");
        assert!(app.state.nodes.is_empty(), "and start clean");
    }

    /// Subscriptions carry entries that are not servers. One on the target
    /// router parses to a server field of `1405-06-12`, which produced a
    /// nonsense dnsmasq rule.
    #[test]
    fn only_real_hostnames_get_dns_rules() {
        for good in ["a.example.com", "node.example.net", "x.co"] {
            assert!(is_resolvable_hostname(good), "{good} should be kept");
        }
        for bad in [
            "1405-06-12",   // a date from a provider notice
            "",
            "localhost",    // no dot
            "1.2.3.4",      // literal, needs no resolution
            "2001:db8::1",
            "a..b",
            "a.b.123",      // numeric TLD
        ] {
            assert!(!is_resolvable_hostname(bad), "{bad:?} should be dropped");
        }
    }

    #[test]
    fn hostname_list_is_sorted_and_deduped() {
        let mut app = app();
        app.add_nodes_from_text(
            "vless://u@b.example.com:443#B
vless://u@a.example.com:443#A
vless://u@a.example.com:444#A2",
        );
        assert_eq!(app.server_hostnames(), ["a.example.com", "b.example.com"]);
    }

    #[test]
    fn label_falls_back_to_host() {
        assert_eq!(short_label("https://sub.example.com/x/y?z=1"), "sub.example.com");
    }
}
