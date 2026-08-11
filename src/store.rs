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
    /// The server hostnames currently written into the dnsmasq drop-in.
    ///
    /// Held so the drop-in can be rewritten exactly when the set changes and
    /// not otherwise: installing it restarts dnsmasq, which empties the DNS
    /// cache for every device on the network.
    pub dns_domains: Vec<String>,
    /// Liveness counters kept by [`crate::health`].
    pub health: crate::health::Status,
    /// Automatic-failover counters kept by [`crate::switcher`].
    pub switcher: crate::switcher::Status,
    /// Set while a latency sweep is running, so a user hammering "test all"
    /// cannot pin every worker thread at once.
    pub probing: Arc<AtomicBool>,
    /// Set by `/api/service stop`: the user asked for the core to stay down,
    /// so [`crate::health`] must not resurrect it and [`crate::switcher`] must
    /// not switch -- switching restarts it. Cleared by any explicit start,
    /// selection or mode change. In-memory only: mode "off" is the persisted
    /// way to stop.
    pub core_paused: bool,
    state_path: PathBuf,
}

impl App {
    /// Loads persisted state, or starts from defaults if there is none.
    ///
    /// A corrupt state file is reported but not fatal: the daemon comes up
    /// empty rather than refusing to start, which on a router is the difference
    /// between a fixable panel and an unreachable one.
    /// Re-derives every node from the URI it was imported from.
    ///
    /// The stored fields are a cache of what the parser made of `raw`, and the
    /// parser gains capabilities over time. `headerType` is the case that
    /// forced this: it was added after these nodes were written, so eight of
    /// them had been emitted without their HTTP disguise and reported as
    /// unreachable while working fine in other clients. Migrating field by
    /// field on every such fix does not scale -- the URI is the source of
    /// truth, so re-read it.
    ///
    /// The name, the last measurement and the owning subscription are kept:
    /// providers rename servers, and a latency table that emptied itself on
    /// every upgrade would be worse than the bug. If a fix changes a field that
    /// feeds the identity, the selection is carried across to the new id rather
    /// than silently pointing at nothing.
    fn reparse_nodes(state: &mut State) {
        let mut moved: Vec<(String, String)> = Vec::new();
        for node in &mut state.nodes {
            if node.raw.is_empty() {
                continue;
            }
            let Ok(mut fresh) = crate::parse::parse_uri(&node.raw) else {
                continue; // keep what we have; a link we can no longer read is not an improvement
            };
            fresh.name = node.name.clone();
            fresh.latency = node.latency;
            fresh.sub_id = node.sub_id.clone();
            if fresh.id != node.id {
                moved.push((node.id.clone(), fresh.id.clone()));
            }
            *node = fresh;
        }
        for (old, new) in moved {
            if state.active == old {
                state.active = new;
            }
        }
    }

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

        Self::reparse_nodes(&mut state);

        let app = App {
            state,
            sup: Supervisor::new(Paths::new(runtime_dir)),
            tproxy_guard: crate::tproxy::Watchdog::new(),
            tproxy_deadline: 0,
            tproxy_applied: false,
            dns_via_tunnel: false,
            dns_domains: Vec::new(),
            health: crate::health::Status::default(),
            switcher: crate::switcher::Status::default(),
            probing: Arc::new(AtomicBool::new(false)),
            core_paused: false,
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

    /// Writes the state, and only the state.
    ///
    /// No previous generation is kept. A subscription is the source of truth
    /// for the servers it provides: a list that is lost is one refresh away
    /// from coming back, and a second copy on the router's flash buys nothing
    /// that the provider does not already hold.
    pub fn save(&self) -> Result<(), String> {
        if let Some(dir) = self.state_path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }

        // Losing every node is either a bug or a mistake. Nothing is kept, but
        // the moment is worth having in the log so it is not a silent one.
        if self.state.nodes.is_empty() {
            if let Ok(previous) = fs::read(&self.state_path) {
                let had_nodes = serde_json::from_slice::<State>(&previous)
                    .map(|s| !s.nodes.is_empty())
                    .unwrap_or(false);
                if had_nodes {
                    eprintln!(
                        "xrayop: the node list went from populated to empty; \
                         refresh a subscription to repopulate it"
                    );
                }
            }
        }

        let body = serde_json::to_vec_pretty(&self.state).map_err(|e| e.to_string())?;
        xray::write_atomic(&self.state_path, &body)
            .map_err(|e| format!("cannot write {}: {e}", self.state_path.display()))
    }

    /// Persists, then rebuilds and restarts Xray.
    ///
    /// Saving first means a failure to start still leaves the user's choice on
    /// disk, so the panel reflects what they picked and shows why it failed.
    ///
    /// A paused core is only saved, not started: the paths that legitimately
    /// run it again -- start, select, mode change -- lift the pause first.
    pub fn save_and_apply(&mut self) -> Result<(), String> {
        if self.core_paused {
            return self.save();
        }
        let state = self.state.clone();
        // Validation and startup happen before persistence.  A rejected node
        // therefore cannot become the configuration restored at next boot;
        // Supervisor::apply leaves the currently running instance untouched
        // when Xray rejects the staged config.
        self.sup.apply(&state)?;
        self.save()
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

    /// Selects a server. Also lifts any pause and clears the failure counter:
    /// choosing a server -- by hand or by failover -- is a fresh start for it.
    /// A stale count used to let a pending failover fire *after* a manual pick
    /// and mark the server the user had just chosen as failed.
    pub fn select(&mut self, id: &str) -> Result<(), String> {
        if self.state.find(id).is_none() {
            return Err("no such node".into());
        }
        self.state.active = id.to_string();
        self.health.probe_failures = 0;
        self.core_paused = false;
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

    /// The fastest server that is *not* `exclude`.
    ///
    /// For failover, where the excluded one is the server the LAN cannot
    /// currently reach through. It may still hold the best stored latency --
    /// that is exactly the case that made failover fail before, since a
    /// throttled server measures fine from a fresh probe.
    pub fn fastest_other(&self, exclude: &str) -> Option<&Node> {
        self.state
            .nodes
            .iter()
            .filter(|n| n.latency >= 0 && n.id != exclude)
            .min_by_key(|n| n.latency)
    }

    /// Records that a server did not work, so it is not immediately re-elected.
    ///
    /// Used when leaving a server the live tunnel could not carry traffic
    /// through. Its stored latency came from a separate probe instance and says
    /// nothing about that; without this the very next sweep would pick it again
    /// on the strength of a number we have just watched be wrong.
    pub fn mark_failed(&mut self, id: &str) {
        if let Some(n) = self.state.nodes.iter_mut().find(|n| n.id == id) {
            n.latency = Node::LATENCY_FAILED;
        }
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

    /// A selection is a fresh start: the failure counter the switcher triggers
    /// on, and any pause the user asked for, both reset. Without the first, a
    /// failover already counting down fired against the server the user had
    /// just picked by hand.
    #[test]
    fn selecting_a_server_clears_failures_and_a_pause() {
        let mut app = app();
        app.add_nodes_from_text(&format!("{A}\n{B}"));
        let id = app.state.nodes[0].id.clone();
        app.health.probe_failures = 3;
        app.core_paused = true;
        app.select(&id).unwrap();
        assert_eq!(app.health.probe_failures, 0);
        assert!(!app.core_paused);
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

    /// Failover's whole difficulty: the server it is escaping usually still
    /// holds the best stored number, because that number came from a separate
    /// probe instance that had no trouble reaching it.
    #[test]
    fn fastest_other_skips_the_server_being_escaped() {
        let mut app = app();
        app.add_nodes_from_text(&format!("{A}\n{B}\n{C}"));
        let ids: Vec<_> = app.state.nodes.iter().map(|n| n.id.clone()).collect();
        app.apply_latencies(vec![
            (ids[0].clone(), 90), // the failing one, and the fastest on paper
            (ids[1].clone(), 120),
            (ids[2].clone(), Node::LATENCY_FAILED),
        ]);
        assert_eq!(app.fastest().unwrap().id, ids[0], "still the fastest");
        assert_eq!(
            app.fastest_other(&ids[0]).unwrap().id,
            ids[1],
            "but not what failover should pick"
        );
    }

    #[test]
    fn fastest_other_gives_up_rather_than_returning_a_dead_server() {
        let mut app = app();
        app.add_nodes_from_text(&format!("{A}\n{B}"));
        let ids: Vec<_> = app.state.nodes.iter().map(|n| n.id.clone()).collect();
        app.apply_latencies(vec![
            (ids[0].clone(), 90),
            (ids[1].clone(), Node::LATENCY_FAILED),
        ]);
        assert!(app.fastest_other(&ids[0]).is_none());
    }

    /// Without this the next sweep re-elects the server we just watched fail,
    /// on the strength of a measurement we have proof is not representative.
    #[test]
    fn marking_a_server_failed_takes_it_out_of_contention() {
        let mut app = app();
        app.add_nodes_from_text(&format!("{A}\n{B}"));
        let ids: Vec<_> = app.state.nodes.iter().map(|n| n.id.clone()).collect();
        app.apply_latencies(vec![(ids[0].clone(), 90), (ids[1].clone(), 120)]);

        app.mark_failed(&ids[0]);
        assert_eq!(app.fastest().unwrap().id, ids[1]);
        // An unknown id is a no-op, not a panic.
        app.mark_failed("no-such-node");
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
        let s = app.add_nodes_from_text(&format!("{A}\nvless://broken\ntuic://k@h:1#t"));
        assert_eq!(s.imported, 1);
        assert_eq!(s.errors.len(), 1);
        assert_eq!(s.skipped, 1, "tuic has no Xray outbound at all");
    }

    fn app_at(dir: &std::path::Path) -> App {
        let _ = fs::create_dir_all(dir);
        App::load(dir.join("state.json"), dir).0
    }

    /// Saving keeps exactly one file. A subscription can be refreshed; a
    /// duplicate of the node list on the router's flash cannot earn its space.
    #[test]
    fn saving_leaves_no_second_copy_behind() {
        let dir = std::env::temp_dir().join("xrayop-nocopy-test");
        let _ = fs::remove_dir_all(&dir);
        let mut app = app_at(&dir);

        app.add_nodes_from_text(&format!("{A}\n{B}"));
        app.save().unwrap();
        app.add_nodes_from_text(C);
        app.save().unwrap();

        let files: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(files, vec!["state.json"], "found {files:?}");
    }

    /// State written before `headerType` was understood still holds the URI
    /// that carries it, so an upgrade fixes those nodes without the user
    /// touching anything.
    #[test]
    fn nodes_are_re_derived_from_their_uri_on_load() {
        let mut state = State::default();
        let mut stale = crate::parse::parse_uri(
            "vless://uu@ex.com:443?type=tcp&headerType=http&host=a.com#Server",
        )
        .unwrap();
        // What an older build would have persisted: the field did not exist.
        stale.header_type = String::new();
        stale.latency = 123;
        stale.name = "Renamed by the provider".into();
        state.active = stale.id.clone();
        state.nodes.push(stale);

        App::reparse_nodes(&mut state);

        let n = &state.nodes[0];
        assert_eq!(n.header_type, "http", "the fix must reach existing nodes");
        assert_eq!(n.latency, 123, "measurements are not thrown away");
        assert_eq!(n.name, "Renamed by the provider", "nor is the display name");
        assert_eq!(state.active, n.id, "and the selection still points at it");
    }

    /// A hand-added node with no URI, or one whose link no longer parses, must
    /// survive rather than be silently emptied.
    #[test]
    fn nodes_without_a_usable_uri_are_left_alone() {
        let mut state = State::default();
        let mut manual = Node {
            name: "no raw".into(),
            server: "keep.me".into(),
            ..Default::default()
        };
        manual.id = manual.compute_id();
        let mut broken = manual.clone();
        broken.raw = "not-a-link".into();
        broken.server = "also.keep".into();
        state.nodes.push(manual);
        state.nodes.push(broken);

        App::reparse_nodes(&mut state);

        assert_eq!(state.nodes[0].server, "keep.me");
        assert_eq!(state.nodes[1].server, "also.keep");
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
