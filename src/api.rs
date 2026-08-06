//! HTTP panel: static frontend plus a small JSON API.
//!
//! ## Concurrency
//!
//! A fixed pool of blocking workers share one [`tiny_http::Server`]. Slow
//! operations (subscription fetch, latency sweep) never hold the [`App`] mutex
//! across the network -- see the `handle_*` functions for the snapshot / work /
//! merge pattern.
//!
//! ## Access control
//!
//! There is none yet: anyone who can reach the port can drive the panel. It is
//! meant for a trusted LAN, same as an unauthenticated LuCI would be. Two
//! things are done regardless:
//!
//! * every mutating route requires `Content-Type: application/json`, which
//!   stops a hostile web page from driving the panel through a form POST --
//!   that content type forces a CORS preflight, and no CORS headers are sent;
//! * no response ever includes a node's UUID unless the panel asked for that
//!   node's detail.

use crate::dnscfg;
use crate::dnsmasq;
use crate::net;
use crate::latency;
use crate::probe;
use crate::store::{App, SubSummary};
use crate::tproxy;
use crate::xray;
use serde_json::{json, Value};
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Request, Response, Server};

const INDEX_HTML: &str = include_str!("../web/index.html");

/// Cap on request bodies. Generous enough for a large pasted node list, small
/// enough that a hostile client cannot exhaust the router's RAM.
const MAX_BODY: usize = 4 * 1024 * 1024;

const SUB_TIMEOUT_SECS: u32 = 25;
/// Per-node budget for the real-delay request. Generous enough for a distant
/// server on a slow link, short enough that a dead one does not stall a sweep.
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

type Body = Response<Cursor<Vec<u8>>>;

pub fn serve(app: Arc<Mutex<App>>, addr: &str, workers: usize) -> Result<(), String> {
    let server = Server::http(addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;
    let server = Arc::new(server);

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let server = Arc::clone(&server);
        let app = Arc::clone(&app);
        handles.push(thread::spawn(move || loop {
            let request = match server.recv() {
                Ok(r) => r,
                Err(e) => {
                    // tiny_http's listener thread terminates on the first
                    // accept error of any kind -- EMFILE, ECONNABORTED, all of
                    // them. Returning here would leave the other workers
                    // blocked on a queue with no producer: the process stays
                    // alive, so procd never respawns it, and the panel is dead
                    // until someone restarts it by hand. Exiting is blunt but
                    // correct on a router, where procd rebuilds everything in
                    // seconds.
                    eprintln!("xrayop: cannot accept connections ({e}); exiting for a restart");
                    std::process::exit(1);
                }
            };
            // A panic in one handler must not kill the worker and shrink the
            // pool; catch it and return a 500 instead.
            let url = request.url().to_string();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dispatch(&app, request)
            }));
            if outcome.is_err() {
                eprintln!("xrayop: handler panicked while serving {url}");
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn dispatch(app: &Arc<Mutex<App>>, mut request: Request) {
    let method = request.method().as_str().to_uppercase();
    // Strip any query string; no route uses one.
    let path = request.url().split('?').next().unwrap_or("/").to_string();

    // The panel itself is a static file with no data in it, so it is served
    // before the gate -- otherwise there would be nowhere to type the token.
    if method == "GET" && (path == "/" || path == "/index.html") {
        let _ = request.respond(html(INDEX_HTML));
        return;
    }

    if let Err(denied) = gate(&request, app) {
        let _ = request.respond(denied);
        return;
    }

    let response = match (method.as_str(), path.as_str()) {
        ("GET", "/api/state") => handle_state(app),
        ("GET", "/api/log") => handle_log(app),

        ("POST", _) => match read_json(&mut request) {
            Err(e) => error(400, &e),
            Ok(body) => match path.as_str() {
                "/api/subs/add" => handle_sub_add(app, &body),
                "/api/subs/refresh" => handle_sub_refresh(app, &body),
                "/api/subs/remove" => handle_sub_remove(app, &body),
                "/api/nodes/add" => handle_nodes_add(app, &body),
                "/api/nodes/remove" => handle_node_remove(app, &body),
                "/api/select" => handle_select(app, &body),
                "/api/test" => handle_test(app),
                "/api/dns" => handle_dns(app, &body),
                "/api/settings" => handle_settings(app, &body),
                "/api/service" => handle_service(app, &body),
                "/api/tproxy/enable" => handle_tproxy_enable(app),
                "/api/tproxy/confirm" => handle_tproxy_confirm(app),
                "/api/tproxy/disable" => handle_tproxy_disable(app),
                "/api/nodes/restore" => handle_restore(app),
                "/api/mode" => handle_mode(app, &body),
                "/api/network-changed" => handle_network_changed(app, &body),
                _ => error(404, "no such endpoint"),
            },
        },
        _ => error(404, "no such endpoint"),
    };

    let _ = request.respond(response);
}

// --- routes ---

fn handle_state(app: &Arc<Mutex<App>>) -> Body {
    let mut app = lock(app);
    let running = app.sup.is_running();
    // Deliberately NOT calling tproxy::is_applied() here: it forks `nft`, and
    // the panel polls this route every 6 seconds. The cached value is refreshed
    // by the tproxy handlers, which are the only things that change it.
    let tproxy_applied = app.tproxy_applied;
    let dns_via_tunnel = app.dns_via_tunnel;
    let health = app.health.clone();
    let switcher = app.switcher.clone();
    let state = &app.state;

    let nodes: Vec<Value> = state
        .nodes
        .iter()
        .map(|n| {
            json!({
                "id": n.id,
                "name": n.name,
                "server": n.server,
                "port": n.port,
                "network": n.network,
                "security": n.security,
                "flow": n.flow,
                "sub_id": n.sub_id,
                "latency": n.latency,
                "active": n.id == state.active,
            })
        })
        .collect();

    // A subscription URL usually embeds a per-user token. Handing it back would
    // undo the node list's credential redaction below: anyone holding the URL
    // can fetch the full list -- UUIDs, REALITY keys and all -- straight from
    // the provider.
    let subs: Vec<Value> = state
        .subs
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "name": s.name,
                "host": sub_host(&s.url),
                "last_update": s.last_update,
                "node_count": s.node_count,
                "last_error": s.last_error,
            })
        })
        .collect();

    json_ok(json!({
        "nodes": nodes,
        "subs": subs,
        "settings": state.settings,
        "active": state.active,
        "dns_presets": dnscfg::PRESETS,
        "test_targets": dnscfg::TEST_TARGETS,
        "test_url": dnscfg::test_url(&state.settings),
        "dns_resolvers": dnscfg::resolvers(&state.settings),
        "status": {
            "running": running,
            "started_at": app.sup.started_at,
            "running_node": app.sup.running_node,
            "last_error": app.sup.last_error,
            "config_path": app.sup.config_path().display().to_string(),
        },
        "health": {
            "restarts": health.restarts,
            "failures": health.failures,
            "degraded": health.degraded,
            "reachable": health.reachable,
            "probe_failures": health.probe_failures,
            "last_failure": health.last_failure,
        },
        "switcher": {
            "enabled": state.settings.auto_switch,
            "minutes": state.settings.auto_switch_minutes,
            "switches": switcher.switches,
            "last_switch": switcher.last_switch,
            "last_switch_to": switcher.last_switch_to,
            "last_switch_reason": switcher.last_switch_reason,
            "last_sweep": switcher.last_sweep,
        },
        "tproxy": {
            "enabled": state.settings.transparent,
            "applied": tproxy_applied,
            "dns_via_tunnel": dns_via_tunnel,
            // Non-zero means a change is on probation and will roll back.
            "deadline": app.tproxy_deadline,
            "armed": app.tproxy_guard.is_armed(),
            "now": xray::now_secs(),
            "port": state.settings.tproxy_port,
            "interfaces": state.settings.lan_list(),
            "interfaces_auto": state.settings.lan_interfaces.trim().is_empty(),
            "bypass_resolver": state.settings.bypass_resolver(),
            "bypass_resolver_auto": state.settings.dns_bypass_resolver.trim().is_empty(),
            "tunnel_ipv6": state.settings.tunnel_ipv6,
        }
    }))
}

fn handle_log(app: &Arc<Mutex<App>>) -> Body {
    let app = lock(app);
    json_ok(json!({ "log": app.sup.log_tail(200) }))
}

fn handle_sub_add(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let url = str_field(body, "url");
    let name = str_field(body, "name");

    let id = {
        let mut a = lock(app);
        match a.add_sub(&url, &name) {
            Ok(id) => id,
            Err(e) => return error(400, &e),
        }
    };
    // Fall through to a refresh so adding a subscription actually loads it.
    refresh_one(app, &id)
}

fn handle_sub_refresh(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let id = str_field(body, "id");
    if !id.is_empty() {
        return refresh_one(app, &id);
    }

    // No id: refresh everything.
    let ids: Vec<String> = lock(app).state.subs.iter().map(|s| s.id.clone()).collect();
    if ids.is_empty() {
        return error(400, "no subscriptions to refresh");
    }
    let mut total = SubSummary::default();
    let mut failed = 0usize;
    for id in ids {
        match fetch_and_merge(app, &id) {
            Ok(s) => {
                total.imported += s.imported;
                total.removed += s.removed;
                total.skipped += s.skipped;
                total.errors.extend(s.errors);
            }
            Err(_) => failed += 1,
        }
    }
    finish_write(app, summary_json(&total, failed))
}

fn refresh_one(app: &Arc<Mutex<App>>, id: &str) -> Body {
    match fetch_and_merge(app, id) {
        Ok(summary) => finish_write(app, summary_json(&summary, 0)),
        Err(e) => {
            lock(app).set_sub_error(id, &e);
            let _ = lock(app).save();
            error(502, &e)
        }
    }
}

/// Fetch outside the lock, merge inside it.
fn fetch_and_merge(app: &Arc<Mutex<App>>, id: &str) -> Result<SubSummary, String> {
    let url = lock(app).sub_url(id).ok_or("no such subscription")?;
    let body = net::fetch(&url, SUB_TIMEOUT_SECS)?;
    let summary = lock(app).apply_sub_body(id, &body);
    if summary.imported == 0 {
        let detail = summary
            .errors
            .first()
            .cloned()
            .unwrap_or_else(|| "no VLESS links found in the response".into());
        return Err(detail);
    }
    Ok(summary)
}

fn handle_sub_remove(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let id = str_field(body, "id");
    let mut a = lock(app);
    if !a.remove_sub(&id) {
        return error(404, "no such subscription");
    }
    drop(a);
    finish_write(app, json!({ "ok": true }))
}

fn handle_nodes_add(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let text = str_field(body, "text");
    if text.trim().is_empty() {
        return error(400, "paste at least one vless:// link");
    }
    let summary = lock(app).add_nodes_from_text(&text);
    if summary.imported == 0 {
        let detail = summary
            .errors
            .first()
            .cloned()
            .unwrap_or_else(|| "no VLESS links found".into());
        return error(400, &detail);
    }
    finish_write(app, summary_json(&summary, 0))
}

fn handle_node_remove(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let id = str_field(body, "id");
    if !lock(app).remove_node(&id) {
        return error(404, "no such node");
    }
    finish_write(app, json!({ "ok": true }))
}

/// Rolls the node list back to the previous saved generation.
///
/// The backup is written on every save that had nodes, so this undoes an
/// accidental "delete all" without needing the subscription URLs again.
fn handle_restore(app: &Arc<Mutex<App>>) -> Body {
    let restored = {
        let mut a = lock(app);
        match a.restore_backup() {
            Ok(n) => n,
            Err(e) => return error(404, &e),
        }
    };
    finish_write(app, json!({ "restored": restored }))
}

fn handle_select(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let id = str_field(body, "id");
    // "fastest" lets the panel offer one-click auto-selection.
    let id = if id == "fastest" {
        match lock(app).fastest().map(|n| n.id.clone()) {
            Some(id) => id,
            None => return error(400, "no node has a successful latency test yet"),
        }
    } else {
        id
    };
    if let Err(e) = lock(app).select(&id) {
        return error(404, &e);
    }
    finish_write(app, json!({ "ok": true, "active": id }))
}

fn handle_test(app: &Arc<Mutex<App>>) -> Body {
    let (nodes, settings, runtime, gate) = {
        let a = lock(app);
        (
            a.state.nodes.clone(),
            a.state.settings.clone(),
            a.sup.runtime_dir().to_path_buf(),
            Arc::clone(&a.probing),
        )
    };
    if nodes.is_empty() {
        return error(400, "there are no nodes to test");
    }

    // One sweep at a time. A large list takes tens of seconds and starts a
    // second xray instance; a user clicking a stalled button would otherwise
    // pin every worker thread and stack probe instances.
    if gate.swap(true, Ordering::SeqCst) {
        return error(409, "a latency test is already running");
    }
    let _release = ReleaseOnDrop(Arc::clone(&gate));

    let url = dnscfg::test_url(&settings);
    let outcome = match latency::measure(&nodes, &settings, &runtime, &url, PROBE_TIMEOUT) {
        Ok(o) => o,
        Err(e) => return error(500, &e),
    };

    let mut a = lock(app);
    a.apply_latencies(outcome.results);
    let reachable = a.state.nodes.iter().filter(|n| n.latency >= 0).count();
    let best = a
        .fastest()
        .map(|n| json!({ "id": n.id, "name": n.name, "latency": n.latency }));
    let total = a.state.nodes.len();
    let _ = a.save();
    drop(a);

    json_ok(json!({
        "ok": true,
        "tested": total.min(latency::MAX_NODES),
        "reachable": reachable,
        "skipped": outcome.skipped,
        "url": url,
        "best": best,
    }))
}

fn handle_dns(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let preset = str_field(body, "preset");
    if preset != "custom" && dnscfg::find(&preset).is_none() {
        return error(400, "unknown DNS preset");
    }

    // Validate on a candidate before touching live state -- see `apply_settings`.
    let mut next = lock(app).state.settings.clone();
    next.dns_preset = preset.clone();
    if preset == "custom" {
        next.dns_custom = str_field(body, "custom");
        let entries = dnscfg::split_custom(&next.dns_custom);
        if entries.is_empty() {
            return error(400, "enter at least one DNS server");
        }
        if let Some(bad) = entries.iter().find(|e| !dnscfg::is_valid_resolver(e)) {
            return error(400, &format!("{bad:?} is not a valid DNS server address"));
        }
    }

    let resolvers = dnscfg::resolvers(&next);
    lock(app).state.settings = next;
    finish_write(app, json!({ "ok": true, "resolvers": resolvers }))
}

fn handle_settings(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let current = lock(app).state.settings.clone();
    let next = match apply_settings(current.clone(), body) {
        Ok(next) => next,
        Err(e) => return error(400, &e),
    };
    // Several settings are baked into the nftables ruleset, not the Xray
    // config, so `save_and_apply` alone would persist them and leave the kernel
    // running the previous rules -- the panel would show one thing and the
    // router would do another.
    let rules_changed = next.route_router_traffic != current.route_router_traffic
        || next.dns_redirect != current.dns_redirect
        || next.tunnel_ipv6 != current.tunnel_ipv6
        || next.lan_interfaces != current.lan_interfaces
        || next.tproxy_port != current.tproxy_port
        || next.dns_bypass_resolver != current.dns_bypass_resolver
        || next.dns_port != current.dns_port;

    lock(app).state.settings = next;
    let response = finish_write(app, json!({ "ok": true }));

    if rules_changed && lock(app).state.settings.transparent {
        reapply_rules(app);
    }
    response
}

/// Rebuilds the firewall rules and the resolver hand-off in place.
///
/// No probation handshake here: transparent mode is already confirmed and
/// working, and the change is a refinement of it rather than a leap. A failure
/// leaves the previous rules removed, which [`crate::health`] will notice and
/// unwind properly.
fn reapply_rules(app: &Arc<Mutex<App>>) {
    let host = lock(app).active_server_host();
    let ips = host.map(|h| probe::resolve_all(&h)).unwrap_or_default();

    let (plan, dns_port, bypass, resolver) = {
        let a = lock(app);
        (
            a.tproxy_plan(ips),
            a.state.settings.dns_port,
            a.server_hostnames(),
            a.state.settings.bypass_resolver(),
        )
    };
    if let Err(e) = tproxy::apply(&plan) {
        eprintln!("xrayop: settings changed but the rules would not re-apply: {e}");
        lock(app).tproxy_applied = false;
        return;
    }
    let installed = match dnsmasq::install(dns_port, &bypass, &resolver) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("xrayop: settings changed but the resolver would not re-apply: {e}");
            false
        }
    };
    let mut a = lock(app);
    a.tproxy_applied = true;
    a.dns_via_tunnel = true;
    if installed {
        a.dns_domains = bypass;
    }
}

/// Folds a settings patch onto `next`, validating as it goes.
///
/// Split out and pure so it can be tested, but mainly so validation happens on
/// a *copy*: an earlier version mutated live settings and then bailed out on
/// error, which left the rejected values in memory for the next successful
/// write to persist. That shipped a config with two inbounds on one port.
fn apply_settings(mut next: crate::model::Settings, body: &Value) -> Result<crate::model::Settings, String> {
    if let Some(raw) = body.get("socks_port") {
        next.socks_port = port_of(raw).ok_or("socks_port must be between 1 and 65535")?;
    }
    if let Some(raw) = body.get("http_port") {
        next.http_port = port_of(raw).ok_or("http_port must be between 1 and 65535")?;
    }
    if let Some(raw) = body.get("allow_lan") {
        next.allow_lan = raw.as_bool().ok_or("allow_lan must be true or false")?;
    }
    if let Some(raw) = body.get("xray_bin") {
        let v = raw.as_str().unwrap_or_default().trim();
        if v.is_empty() {
            return Err("xray_bin must not be empty".into());
        }
        // This path is executed as root. Confining it to the directories a
        // package manager installs into turns "run anything on the box" into
        // "choose between the xray builds that are actually installed".
        const ALLOWED: &[&str] = &["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/"];
        if !ALLOWED.iter().any(|p| v.starts_with(p)) || v.contains("..") {
            return Err(format!(
                "xray binary must live under one of {}",
                ALLOWED.join(", ")
            ));
        }
        next.xray_bin = v.to_string();
    }
    if let Some(raw) = body.get("log_level") {
        let v = raw.as_str().unwrap_or_default();
        if !["debug", "info", "warning", "error", "none"].contains(&v) {
            return Err(format!("unknown log level {v:?}"));
        }
        next.log_level = v.to_string();
    }
    if let Some(raw) = body.get("log_enabled") {
        next.log_enabled = raw.as_bool().ok_or("log_enabled must be true or false")?;
    }
    if let Some(raw) = body.get("log_max_kb") {
        let v = raw.as_u64().ok_or("log_max_kb must be a number")?;
        // The log lives in RAM. An upper bound here is what stops a typo in
        // the panel from turning into an out-of-memory on the router.
        if !(16..=4096).contains(&v) {
            return Err("log size cap must be between 16 and 4096 KB".into());
        }
        next.log_max_kb = v;
    }
    if let Some(raw) = body.get("log_rotate_secs") {
        let v = raw.as_u64().ok_or("log_rotate_secs must be a number")?;
        if !(10..=3600).contains(&v) {
            return Err("log rotation must be between 10 and 3600 seconds".into());
        }
        next.log_rotate_secs = v;
    }
    if let Some(raw) = body.get("transparent_ipv6") {
        next.tunnel_ipv6 = raw.as_bool().ok_or("transparent_ipv6 must be true or false")?;
    }
    if let Some(raw) = body.get("lan_interfaces") {
        let v = raw.as_str().unwrap_or_default().trim();
        // Empty is meaningful here: it hands the choice back to discovery
        // rather than being a validation failure.
        if v.is_empty() {
            next.lan_interfaces = String::new();
        } else {
        // This string is interpolated straight into an nftables script that is
        // fed to `nft -f` as root. A quote, brace or newline here would escape
        // the intended rule -- and since `disable` only deletes our own table,
        // an injected second table would outlive it.
            for name in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let ok = name.len() <= 15
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
                if !ok {
                    return Err(format!("{name:?} is not a valid interface name"));
                }
            }
            next.lan_interfaces = v.to_string();
        }
    }
    if let Some(raw) = body.get("go_mem_limit_mb") {
        let v = raw.as_u64().ok_or("go_mem_limit_mb must be a number")?;
        if v != 0 && !(32..=512).contains(&v) {
            return Err("Go memory limit must be 0 (off) or between 32 and 512 MB".into());
        }
        next.go_mem_limit_mb = v;
    }
    if let Some(raw) = body.get("mem_hard_cap_mb") {
        let v = raw.as_u64().ok_or("mem_hard_cap_mb must be a number")?;
        if v != 0 && !(64..=512).contains(&v) {
            return Err("hard memory cap must be 0 (off) or between 64 and 512 MB".into());
        }
        next.mem_hard_cap_mb = v;
    }
    if let Some(raw) = body.get("conn_idle_secs") {
        let v = raw.as_u64().ok_or("conn_idle_secs must be a number")?;
        if !(30..=600).contains(&v) {
            return Err("idle timeout must be between 30 and 600 seconds".into());
        }
        next.conn_idle_secs = v as u32;
    }
    if let Some(raw) = body.get("test_target") {
        let v = raw.as_str().unwrap_or_default();
        if v != "custom" && dnscfg::find_target(v).is_none() {
            return Err(format!("unknown test target {v:?}"));
        }
        next.test_target = v.to_string();
        if v == "custom" {
            let u = body
                .get("test_url_custom")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if !dnscfg::is_valid_test_url(u) {
                return Err("the test URL must be http(s) and not point at the router".into());
            }
            next.test_url_custom = u.to_string();
        }
    }
    if let Some(raw) = body.get("route_router_traffic") {
        next.route_router_traffic = raw
            .as_bool()
            .ok_or("route_router_traffic must be true or false")?;
    }
    if let Some(raw) = body.get("dns_bypass_resolver") {
        let v = raw.as_str().unwrap_or_default().trim();
        // Empty hands it back to discovery: the router's own upstream.
        if v.is_empty() {
            next.dns_bypass_resolver = String::new();
        } else {
            // Must be a plain address: this one is queried directly, outside
            // the tunnel, so a DoH URL here would need its own name resolved
            // first and reintroduce the deadlock it exists to prevent.
            if v.parse::<std::net::IpAddr>().is_err() {
                return Err("the bypass resolver must be a plain IP address".into());
            }
            next.dns_bypass_resolver = v.to_string();
        }
    }
    if let Some(raw) = body.get("auto_switch") {
        next.auto_switch = raw.as_bool().ok_or("auto_switch must be true or false")?;
    }
    if let Some(raw) = body.get("auto_switch_minutes") {
        let v = raw.as_u64().ok_or("auto_switch_minutes must be a number")?;
        // A sweep briefly runs a second core and reconnects if it acts, so a
        // one-minute interval would cost more than it saves. The upper bound is
        // a week, past which it is not really automatic.
        if !(5..=10080).contains(&v) {
            return Err("the interval must be between 5 minutes and a week".into());
        }
        next.auto_switch_minutes = v as u32;
    }
    if let Some(raw) = body.get("probe_base_port") {
        next.probe_base_port = port_of(raw).ok_or("probe_base_port must be between 1 and 65535")?;
    }
    if let Some(raw) = body.get("sniff_route_only") {
        next.sniff_route_only = raw.as_bool().ok_or("sniff_route_only must be true or false")?;
    }

    if next.socks_port == next.http_port {
        return Err("SOCKS and HTTP ports must differ".into());
    }
    Ok(next)
}

fn handle_service(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    match str_field(body, "action").as_str() {
        "stop" => {
            let mut a = lock(app);
            a.sup.stop();
            a.sup.last_error.clear();
            json_ok(json!({ "ok": true, "running": false }))
        }
        "start" | "restart" => {
            let mut a = lock(app);
            if a.state.active.is_empty() {
                return error(400, "select a node first");
            }
            match a.save_and_apply() {
                Ok(()) => {
                    let running = a.sup.is_running();
                    json_ok(json!({ "ok": true, "running": running }))
                }
                Err(e) => error(500, &e),
            }
        }
        other => error(400, &format!("unknown action {other:?}")),
    }
}

/// The WAN came back. Called by the hotplug script.
///
/// Two different events, two different weights, following Passwall2's split:
/// `ifupdate` is an address change on a link that stayed up, so the rules need
/// refreshing but the core's connections are probably fine. `ifup` means the
/// link went away and returned, and everything Xray held is dead -- it has to
/// reconnect, and it will not work that out on its own.
fn handle_network_changed(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let event = str_field(body, "event");
    let (enabled, transparent) = {
        let a = lock(app);
        (a.state.settings.core_enabled(), a.state.settings.transparent)
    };
    if !enabled {
        return json_ok(json!({ "ok": true, "action": "none" }));
    }

    // A link that just came back needs the core restarted; its sockets point
    // at a route that no longer exists.
    if event != "ifupdate" {
        let mut a = lock(app);
        let state = a.state.clone();
        match a.sup.apply(&state) {
            Ok(()) => a.health.restarts += 1,
            Err(e) => {
                a.health.last_failure = e.clone();
                drop(a);
                return error(500, &format!("could not restart xray after {event}: {e}"));
            }
        }
    }

    // The server may resolve somewhere new on the other side of a reconnect,
    // and the bypass set has to follow or Xray's own traffic gets intercepted.
    if transparent {
        reapply_rules(app);
    }

    json_ok(json!({ "ok": true, "action": event, "transparent": transparent }))
}

/// Switches between off / proxy / global.
///
/// One endpoint rather than three settings, because the transitions are not
/// symmetric: leaving `global` has to tear down firewall rules, and entering it
/// has to go through the confirm-or-revert handshake. Expressing that as a
/// boolean the user could set from the settings form would make it possible to
/// half-apply it.
fn handle_mode(app: &Arc<Mutex<App>>, body: &Value) -> Body {
    let mode = str_field(body, "mode");
    if !crate::model::MODES.contains(&mode.as_str()) {
        return error(400, "mode must be off, proxy or global");
    }
    let current = lock(app).state.settings.mode.clone();
    if mode == current && mode != "global" {
        return json_ok(json!({ "ok": true, "mode": mode }));
    }

    // Always leave the intercepting state cleanly before entering the new one.
    // Going proxy -> off -> proxy must not leave rules behind, and going
    // global -> global has to start from a known ruleset rather than layering.
    if current == "global" || lock(app).tproxy_applied {
        rollback_tproxy(app);
    }

    {
        let mut a = lock(app);
        a.state.settings.mode = mode.clone();
        a.state.settings.transparent = mode == "global";
        // Reset the health counters: a mode change is a fresh start, and a
        // "degraded" badge from the previous mode would be misleading.
        a.health.degraded = false;
        a.health.failures = 0;
        a.health.last_failure.clear();
    }

    if mode == "global" {
        // Reuses the probation handshake: apply, then confirm within the
        // window or it rolls back on its own.
        return handle_tproxy_enable(app);
    }

    // "off" stops the core because `build_config` returns nothing for it;
    // "proxy" starts it with SOCKS and HTTP only.
    finish_write(app, json!({ "mode": mode }))
}

// --- transparent proxy ---

/// How long the panel has to confirm before the ruleset is rolled back.
///
/// Long enough to switch tabs and actually load a page, short enough that a
/// router which just lost its network heals itself before anyone reaches for
/// the power cable.
const CONFIRM_SECS: u64 = 90;

/// Applies the transparent-proxy ruleset on probation.
///
/// Order matters in both directions. Xray has to be listening on the TPROXY
/// port *before* nftables starts redirecting to it, or the first intercepted
/// packets are black-holed. The revert path does the opposite: stop redirecting
/// first, then reconfigure Xray.
fn handle_tproxy_enable(app: &Arc<Mutex<App>>) -> Body {
    // Take the hostname, drop the guard, *then* resolve. Holding the lock
    // across getaddrinfo stalls every other route for up to musl's five-second
    // resolver timeout, and flaky upstream DNS is the normal condition here.
    let host = lock(app).active_server_host();
    let Some(host) = host else {
        return error(400, "select a node first");
    };
    let server_ips = probe::resolve_all(&host);

    {
        let a = lock(app);
        if a.state.active.is_empty() {
            return error(400, "select a node first");
        }
        if server_ips.is_empty() {
            return error(
                400,
                "cannot resolve the selected server; without its address the tunnel would loop",
            );
        }
        // Validate against the kernel before changing anything at all.
        if let Err(e) = tproxy::check(&a.tproxy_plan(server_ips.clone())) {
            return error(400, &format!("the kernel rejected the ruleset: {e}"));
        }
    }

    // 1. Xray first, so the port is open when the rules point at it.
    {
        let mut a = lock(app);
        a.state.settings.transparent = true;
        let state = a.state.clone();
        if let Err(e) = a.sup.apply(&state) {
            a.state.settings.transparent = false;
            let rollback = a.state.clone();
            let _ = a.sup.apply(&rollback);
            return error(500, &format!("xray would not start with tproxy: {e}"));
        }
    }

    // 2. The ruleset. This has to precede the dnsmasq change, because the
    //    drop-in carries an `nftset` directive naming our table -- dnsmasq
    //    would be pointed at a set that does not exist yet.
    //
    //    Safe to do first: the DNS redirect it installs sends queries to the
    //    router's own resolver, which at this moment is still answering the way
    //    it always did. Traffic is tunnelled, DNS is not, and nothing is
    //    broken in between.
    {
        let plan = lock(app).tproxy_plan(server_ips.clone());
        if let Err(e) = tproxy::apply(&plan) {
            rollback_tproxy(app);
            return error(500, &e);
        }
    }

    // 3. Now point the resolver at Xray.
    let (dns_port, bypass, resolver) = {
        let a = lock(app);
        (
            a.state.settings.dns_port,
            a.server_hostnames(),
            a.state.settings.bypass_resolver(),
        )
    };
    if let Err(e) = dnsmasq::install(dns_port, &bypass, &resolver) {
        rollback_tproxy(app);
        return error(500, &format!("could not route DNS through the tunnel: {e}"));
    }
    {
        let mut a = lock(app);
        a.dns_via_tunnel = true;
        a.dns_domains = bypass;
    }

    // 4. Arm the rollback. Deliberately *not* saved yet: if the router drops
    //    off the network now, a reboot must come back without any of this.
    let deadline = xray::now_secs() + CONFIRM_SECS;
    let guard = {
        let mut a = lock(app);
        a.tproxy_deadline = deadline;
        a.tproxy_applied = true;
        a.tproxy_guard.clone()
    };
    let app2 = Arc::clone(app);
    guard.arm(Duration::from_secs(CONFIRM_SECS), move || {
        eprintln!("xrayop: transparent proxy was not confirmed in time; rolling back");
        rollback_tproxy(&app2);
    });

    json_ok(json!({
        "ok": true,
        "pending": true,
        "confirm_within": CONFIRM_SECS,
        "deadline": deadline,
    }))
}

/// Keeps the ruleset: disarms the watchdog and persists the setting.
fn handle_tproxy_confirm(app: &Arc<Mutex<App>>) -> Body {
    let mut a = lock(app);
    if a.tproxy_deadline == 0 {
        return error(400, "there is nothing awaiting confirmation");
    }
    a.tproxy_guard.disarm();
    a.tproxy_deadline = 0;
    // Only now does this survive a reboot.
    match a.save() {
        Ok(()) => json_ok(json!({ "ok": true, "transparent": true })),
        Err(e) => error(500, &e),
    }
}

fn handle_tproxy_disable(app: &Arc<Mutex<App>>) -> Body {
    rollback_tproxy(app);
    let a = lock(app);
    match a.save() {
        Ok(()) => json_ok(json!({ "ok": true, "transparent": false })),
        Err(e) => error(500, &e),
    }
}

/// Removes the ruleset and puts Xray back to proxy-only.
///
/// Shared by the explicit disable and the watchdog, so both paths tear down in
/// the same order: stop redirecting before reconfiguring Xray, or the gap
/// between the two black-holes traffic.
fn rollback_tproxy(app: &Arc<Mutex<App>>) {
    // Rules first, then DNS. Reversing this order would leave a window where
    // the redirect still points at a resolver that has stopped forwarding.
    let plan = lock(app).tproxy_plan(Vec::new());
    tproxy::revert(&plan);
    if let Err(e) = dnsmasq::remove() {
        eprintln!("xrayop: could not restore dnsmasq: {e}");
    }
    let mut a = lock(app);
    a.dns_via_tunnel = false;
    // The drop-in is gone, so nothing is installed. Clearing this makes the
    // next enable write it rather than compare equal and skip.
    a.dns_domains.clear();
    drop(a);

    let mut a = lock(app);
    a.tproxy_guard.disarm();
    a.tproxy_deadline = 0;
    a.tproxy_applied = false;
    a.state.settings.transparent = false;
    let state = a.state.clone();
    if let Err(e) = a.sup.apply(&state) {
        eprintln!("xrayop: could not restart xray after rollback: {e}");
    }
}

/// Clears a busy flag however the scope is left, including on a panic.
struct ReleaseOnDrop(Arc<AtomicBool>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

// --- access control ---

/// Guards every `/api/*` route. Three independent checks, each closing a
/// different attack.
///
/// 1. **Host must be an IP literal or `localhost`.** DNS rebinding needs the
///    victim's browser to reach us under a *hostname* the attacker controls;
///    refusing hostnames outright removes the technique with no configuration
///    to get wrong.
/// 2. **Origin, when present, must match Host.** Blocks a cross-origin `fetch`
///    from a page the user happens to have open.
/// 3. **A shared token.** Without it, anyone who can open a TCP socket to this
///    port controls a root daemon that can MITM the whole household.
fn gate(request: &Request, app: &Arc<Mutex<App>>) -> Result<(), Body> {
    let host = header_value(request, "Host").unwrap_or_default();
    if !host_is_literal(&host) {
        return Err(error(
            421,
            "reach the panel by IP address, not by hostname",
        ));
    }

    if let Some(origin) = header_value(request, "Origin") {
        // "null" is what a sandboxed iframe or a file:// page sends.
        let ok = origin
            .rsplit_once("//")
            .map(|(_, h)| h.eq_ignore_ascii_case(&host))
            .unwrap_or(false);
        if !ok {
            return Err(error(403, "cross-origin requests are not accepted"));
        }
    }

    let expected = lock(app).state.panel_token.clone();
    if expected.is_empty() {
        // Refusing is the safe failure: an empty token would authenticate
        // everyone. See `model::generate_token`.
        return Err(error(503, "panel token is unset; check the system log"));
    }
    let offered = header_value(request, "X-Xrayop-Token")
        .or_else(|| {
            header_value(request, "Authorization")
                .and_then(|v| v.strip_prefix("Bearer ").map(str::to_string))
        })
        .unwrap_or_default();

    if !constant_time_eq(offered.as_bytes(), expected.as_bytes()) {
        return Err(error(401, "invalid or missing panel token"));
    }
    Ok(())
}

/// Whether `host` is an IP literal (with optional port) or loopback.
fn host_is_literal(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    // [::1]:8088
    let bare = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else {
        host.rsplit_once(':')
            .map(|(h, p)| if p.chars().all(|c| c.is_ascii_digit()) { h } else { host })
            .unwrap_or(host)
    };
    bare.eq_ignore_ascii_case("localhost") || bare.parse::<std::net::IpAddr>().is_ok()
}

/// Compares without an early return on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `name` is `&'static str` because tiny_http's `HeaderField::equiv` requires
/// it; every call site passes a literal anyway.
fn header_value(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
}

// --- shared helpers ---

/// Persists and restarts Xray, folding any failure into the response.
///
/// The write is reported as `ok` even when the restart fails: the user's change
/// *was* saved, and the panel shows `apply_error` separately so the two are not
/// confused.
fn finish_write(app: &Arc<Mutex<App>>, mut payload: Value) -> Body {
    let mut a = lock(app);
    let result = a.save_and_apply();
    let running = a.sup.is_running();
    drop(a);

    sync_dns_domains(app);

    if let Some(obj) = payload.as_object_mut() {
        obj.insert("ok".into(), json!(true));
        obj.insert("running".into(), json!(running));
        if let Err(e) = result {
            obj.insert("apply_error".into(), json!(e));
        }
    }
    json_ok(payload)
}

/// Rewrites the dnsmasq drop-in when the set of server hostnames has changed.
///
/// Every proxy server's hostname needs a rule sending it to a directly
/// reachable resolver. With `no-resolv` in force, dnsmasq's only upstream is
/// Xray, and Xray cannot answer a query until it has connected to a server
/// whose address it cannot resolve. A hostname missing from the drop-in
/// therefore takes the LAN's DNS down the moment that server is selected and
/// the cached answer expires.
///
/// The drop-in used to be written only when settings changed, the transparent
/// proxy was enabled, or the daemon started -- never when the node list did.
/// Adding a subscription introduces hostnames it has never seen, so on a live
/// router 16 of 29 servers had no rule, including the one in use. It worked
/// only for as long as the cache held.
///
/// Written only when the set actually differs. Installing restarts dnsmasq,
/// which empties the cache for every device on the network, and this runs after
/// every write -- including selecting a server, which changes nothing here.
fn sync_dns_domains(app: &Arc<Mutex<App>>) {
    let (needed, dns_port, resolver) = {
        let a = lock(app);
        // Nothing to keep in step if the LAN is not being resolved through us.
        if !a.dns_via_tunnel {
            return;
        }
        let needed = a.server_hostnames();
        if !dns_needs_rewrite(&a.dns_domains, &needed) {
            return;
        }
        (
            needed,
            a.state.settings.dns_port,
            a.state.settings.bypass_resolver(),
        )
    };
    match dnsmasq::install(dns_port, &needed, &resolver) {
        Ok(()) => lock(app).dns_domains = needed,
        // Left for the next write to retry. Not fatal: the servers already in
        // the drop-in keep resolving, so this degrades rather than breaks.
        Err(e) => eprintln!("xrayop: the server list changed but the DNS drop-in would not update: {e}"),
    }
}

/// Whether the drop-in has to be rewritten for `needed`.
///
/// Split out so the rule can be tested without a dnsmasq to restart. Both lists
/// come from [`App::server_hostnames`], which sorts and dedupes, so comparing
/// them directly is a comparison of sets.
fn dns_needs_rewrite(installed: &[String], needed: &[String]) -> bool {
    installed != needed
}

/// Host of a subscription URL, for display without leaking its token.
fn sub_host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', '?']).next().unwrap_or("").to_string()
}

fn summary_json(s: &SubSummary, failed_subs: usize) -> Value {
    json!({
        "imported": s.imported,
        "removed": s.removed,
        "skipped": s.skipped,
        "errors": s.errors,
        "failed_subs": failed_subs,
    })
}

/// A poisoned mutex means a handler panicked mid-update. Recovering the guard
/// is the right call for a router daemon: the alternative is a panel that stays
/// dead until someone power-cycles the router.
fn lock(app: &Arc<Mutex<App>>) -> std::sync::MutexGuard<'_, App> {
    app.lock().unwrap_or_else(|e| e.into_inner())
}

fn read_json(request: &mut Request) -> Result<Value, String> {
    // Compare the *essence* -- type/subtype with parameters stripped -- not a
    // substring. `text/plain;charset=application/json` contains the string
    // "application/json" but its essence is text/plain, which browsers treat
    // as a CORS-safelisted simple request and send with no preflight. A
    // substring check therefore admits exactly the cross-origin POST it was
    // written to block. Fastify shipped this same bug as GHSA-3fjj-p79j-c9hh.
    let essence = header_value(request, "Content-Type")
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if essence != "application/json" {
        return Err("Content-Type must be application/json".into());
    }

    let len = request.body_length().unwrap_or(0);
    if len > MAX_BODY {
        return Err("request body is too large".into());
    }

    let mut buf = Vec::with_capacity(len.min(64 * 1024));
    request
        .as_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read body: {e}"))?;
    if buf.len() > MAX_BODY {
        return Err("request body is too large".into());
    }
    if buf.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&buf).map_err(|e| format!("invalid JSON: {e}"))
}

fn str_field(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn port_of(value: &Value) -> Option<u16> {
    let n = value.as_u64()?;
    // Port 0 would make the OS pick one, which the user could never reach.
    if n == 0 || n > u16::MAX as u64 {
        return None;
    }
    Some(n as u16)
}

fn header(name: &str, value: &str) -> Header {
    // Both are compile-time constants at every call site.
    Header::from_bytes(name.as_bytes(), value.as_bytes())
        .expect("static header is always valid")
}

fn json_ok(value: Value) -> Body {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::from_data(body)
        .with_header(header("Content-Type", "application/json; charset=utf-8"))
        .with_header(header("Cache-Control", "no-store"))
}

fn error(status: u16, message: &str) -> Body {
    let body = serde_json::to_vec(&json!({ "ok": false, "error": message }))
        .unwrap_or_else(|_| b"{}".to_vec());
    Response::from_data(body)
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json; charset=utf-8"))
        .with_header(header("Cache-Control", "no-store"))
}

fn html(text: &str) -> Body {
    Response::from_data(text.as_bytes().to_vec())
        .with_header(header("Content-Type", "text/html; charset=utf-8"))
        // The panel is one self-contained file: no external anything.
        .with_header(header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        ))
        .with_header(header("X-Content-Type-Options", "nosniff"))
}

/// Fields the panel must never receive in a list response.
#[cfg(test)]
fn is_secret(key: &str) -> bool {
    matches!(key, "uuid" | "public_key" | "short_id" | "raw")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Node;
    use crate::parse::parse_uri;

    #[test]
    fn node_list_omits_credentials() {
        let n: Node = parse_uri(
            "vless://secret-uuid@ex.com:443?security=reality&pbk=KEY&sid=ab#n",
        )
        .unwrap();
        let listed = json!({
            "id": n.id, "name": n.name, "server": n.server, "port": n.port,
            "network": n.network, "security": n.security, "flow": n.flow,
            "sub_id": n.sub_id, "latency": n.latency, "active": false,
        });
        for key in listed.as_object().unwrap().keys() {
            assert!(!is_secret(key), "{key} must not be exposed in the node list");
        }
        let text = listed.to_string();
        assert!(!text.contains("secret-uuid"));
        assert!(!text.contains("KEY"));
    }

    #[test]
    fn port_of_rejects_out_of_range() {
        assert_eq!(port_of(&json!(1080)), Some(1080));
        assert_eq!(port_of(&json!(0)), None);
        assert_eq!(port_of(&json!(70000)), None);
        assert_eq!(port_of(&json!("1080")), None);
        assert_eq!(port_of(&json!(null)), None);
    }

    /// Regression: a rejected patch used to leave its values in live settings,
    /// and the next successful write persisted them. That produced a config
    /// with the SOCKS and HTTP inbounds on the same port.
    #[test]
    fn rejected_settings_patch_changes_nothing() {
        let before = crate::model::Settings::default();
        let err = apply_settings(before.clone(), &json!({
            "socks_port": 1080, "http_port": 1080
        }))
        .unwrap_err();
        assert!(err.contains("must differ"), "got: {err}");

        // The caller only commits on Ok, so the original must be untouched.
        assert_eq!(before.socks_port, 1080);
        assert_eq!(before.http_port, 1081);
    }

    #[test]
    fn out_of_range_port_names_the_field() {
        let err = apply_settings(Default::default(), &json!({ "socks_port": 99999 })).unwrap_err();
        assert!(err.contains("socks_port"), "got: {err}");
    }

    #[test]
    fn settings_patch_is_partial() {
        let next = apply_settings(Default::default(), &json!({ "log_level": "debug" })).unwrap();
        assert_eq!(next.log_level, "debug");
        assert_eq!(next.socks_port, 1080, "untouched fields must survive");
        assert_eq!(next.xray_bin, "/usr/bin/xray");
    }

    #[test]
    fn settings_rejects_bad_values_rather_than_ignoring_them() {
        for patch in [
            json!({ "log_level": "verbose" }),
            json!({ "xray_bin": "  " }),
            json!({ "allow_lan": "yes" }),
        ] {
            assert!(
                apply_settings(Default::default(), &patch).is_err(),
                "{patch} should be rejected"
            );
        }
    }

    /// DNS rebinding needs the browser to reach us under a hostname the
    /// attacker controls. Accepting only IP literals removes the technique.
    #[test]
    fn only_ip_literals_are_accepted_as_host() {
        for ok in [
            "192.168.1.1",
            "192.168.1.1:8088",
            "127.0.0.1:8088",
            "localhost",
            "localhost:8088",
            "[::1]:8088",
            "[fdf2:5757:44e3::1]:8088",
        ] {
            assert!(host_is_literal(ok), "{ok} should be accepted");
        }
        for bad in [
            "router.lan",
            "rebind.evil.com",
            "rebind.evil.com:8088",
            "",
            "192.168.1.1.evil.com",
        ] {
            assert!(!host_is_literal(bad), "{bad} should be rejected");
        }
    }

    fn hosts(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The bug this guards: the drop-in was written when settings changed or
    /// the daemon started, but never when the node list did. Adding a
    /// subscription brought in hostnames it had never seen, and a hostname with
    /// no direct-resolution rule cannot be resolved at all -- dnsmasq's only
    /// upstream is Xray, and Xray needs that name to connect.
    #[test]
    fn a_new_subscription_forces_the_dns_dropin_to_be_rewritten() {
        let installed = hosts(&["a.example.com"]);
        let needed = hosts(&["a.example.com", "b.example.net"]);
        assert!(dns_needs_rewrite(&installed, &needed));
    }

    #[test]
    fn dropping_a_server_rewrites_it_too() {
        let installed = hosts(&["a.example.com", "b.example.net"]);
        assert!(dns_needs_rewrite(&installed, &hosts(&["a.example.com"])));
    }

    /// This runs after every write, including selecting a server, which changes
    /// no hostnames. Rewriting restarts dnsmasq and empties the cache for the
    /// whole LAN, so an unchanged list must be left alone.
    #[test]
    fn an_unchanged_server_list_does_not_restart_dnsmasq() {
        let same = hosts(&["a.example.com", "b.example.net"]);
        assert!(!dns_needs_rewrite(&same, &same.clone()));
        assert!(!dns_needs_rewrite(&[], &[]));
    }

    #[test]
    fn token_comparison_is_length_safe() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    /// The bypass that made the old substring check useless: this value
    /// contains "application/json" but its essence is text/plain, which
    /// browsers send cross-origin with no preflight.
    #[test]
    fn content_type_essence_rejects_the_csrf_bypass() {
        let essence = |v: &str| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        };
        assert_eq!(essence("application/json"), "application/json");
        assert_eq!(essence("application/json; charset=utf-8"), "application/json");
        assert_eq!(essence("  APPLICATION/JSON  "), "application/json");

        for bypass in [
            "text/plain;charset=application/json",
            "multipart/form-data; boundary=application/json",
            "text/plain",
        ] {
            assert_ne!(
                essence(bypass),
                "application/json",
                "{bypass} must not pass as JSON"
            );
        }
    }

    #[test]
    fn subscription_tokens_are_not_exposed() {
        assert_eq!(sub_host("https://provider.example/sub/SECRET123"), "provider.example");
        assert_eq!(sub_host("http://a.b:8080/x?t=SECRET"), "a.b:8080");
        assert!(!sub_host("https://p.example/sub/SECRET123").contains("SECRET"));
    }

    #[test]
    fn xray_bin_is_confined_to_system_paths() {
        for bad in ["/tmp/evil", "/etc/xrayop/x", "/usr/bin/../../tmp/x", "relative"] {
            assert!(
                apply_settings(Default::default(), &json!({ "xray_bin": bad })).is_err(),
                "{bad} should be rejected"
            );
        }
        assert!(apply_settings(Default::default(), &json!({ "xray_bin": "/usr/bin/xray" })).is_ok());
    }

    /// This string is interpolated into a root nftables script.
    #[test]
    fn lan_interface_names_are_charset_checked() {
        for bad in [
            "br-lan\" }\naccept\ntable inet backdoor {",
            "br lan",
            "br-lan; rm -rf /",
            "verylonginterfacename",
        ] {
            assert!(
                apply_settings(Default::default(), &json!({ "lan_interfaces": bad })).is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(
            apply_settings(Default::default(), &json!({ "lan_interfaces": "br-lan, br-guest" }))
                .is_ok()
        );
    }

    #[test]
    fn resource_settings_are_range_checked() {
        for bad in [
            json!({ "conn_idle_secs": 5 }),
            json!({ "conn_idle_secs": 9999 }),
            json!({ "go_mem_limit_mb": 8 }),
            json!({ "mem_hard_cap_mb": 4096 }),
        ] {
            assert!(apply_settings(Default::default(), &bad).is_err(), "{bad} allowed");
        }
        // 0 means "off" for both memory caps and must stay allowed.
        assert!(apply_settings(Default::default(), &json!({ "go_mem_limit_mb": 0 })).is_ok());
        assert!(apply_settings(Default::default(), &json!({ "mem_hard_cap_mb": 0 })).is_ok());
    }

    /// The panel is one file compiled into the binary, so a JavaScript syntax
    /// error is not caught by anything the compiler does -- it ships, the page
    /// renders blank, and the router looks fine from every angle except the
    /// browser. That happened: an i18n entry written with a real newline
    /// instead of an escape left a string literal unterminated, and the panel
    /// was locked out entirely until someone thought to check the console.
    ///
    /// This checks the shape that broke rather than trying to parse JS. Real
    /// parsing happens in `scripts/build.sh`, which runs `node --check` when
    /// node is available.
    #[test]
    fn panel_has_no_unterminated_string_literals() {
        let script = INDEX_HTML
            .split_once("<script>")
            .and_then(|(_, rest)| rest.split_once("</script>"))
            .map(|(js, _)| js)
            .expect("the panel must contain a script block");

        for (n, line) in script.lines().enumerate() {
            let trimmed = line.trim();
            // An i18n entry: `key:"value",`. Anything that opens a string on a
            // line like this has to close it on the same line.
            let is_entry = trimmed
                .split_once(":\"")
                .map(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_alphanumeric() || c == '_'))
                .unwrap_or(false);
            if !is_entry {
                continue;
            }
            let quotes = trimmed.matches('"').count() - trimmed.matches("\\\"").count();
            assert!(
                quotes % 2 == 0,
                "line {} opens a string it never closes -- use \n, not a real newline:
  {}",
                n + 1,
                trimmed
            );
        }
    }

    /// Every key the English table defines should exist in Persian, or the UI
    /// silently falls back mid-sentence.
    #[test]
    fn both_languages_cover_the_same_keys() {
        let keys = |marker: &str| -> Vec<String> {
            let start = INDEX_HTML.find(marker).expect("language table");
            let body = &INDEX_HTML[start..];
            let end = body.find("
  },").unwrap_or(body.len());
            body[..end]
                .lines()
                .filter_map(|l| {
                    let t = l.trim();
                    t.split_once(':').and_then(|(k, _)| {
                        let k = k.trim();
                        (!k.is_empty()
                            && k.chars().all(|c| c.is_alphanumeric() || c == '_')
                            && t.contains('"'))
                        .then(|| k.to_string())
                    })
                })
                .collect()
        };
        let en = keys("  en: {");
        let fa = keys("  fa: {");
        assert!(en.len() > 40, "expected a populated table, got {}", en.len());
        let missing: Vec<_> = en.iter().filter(|k| !fa.contains(k)).collect();
        assert!(missing.is_empty(), "Persian is missing: {missing:?}");
    }

    #[test]
    fn str_field_defaults_to_empty() {
        assert_eq!(str_field(&json!({ "a": "x" }), "a"), "x");
        assert_eq!(str_field(&json!({ "a": 5 }), "a"), "");
        assert_eq!(str_field(&json!({}), "a"), "");
    }
}
