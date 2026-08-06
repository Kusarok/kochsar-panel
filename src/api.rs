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
use crate::net;
use crate::probe;
use crate::store::{App, SubSummary};
use crate::tproxy;
use crate::xray;
use serde_json::{json, Value};
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Request, Response, Server};

const INDEX_HTML: &str = include_str!("../web/index.html");

/// Cap on request bodies. Generous enough for a large pasted node list, small
/// enough that a hostile client cannot exhaust the router's RAM.
const MAX_BODY: usize = 4 * 1024 * 1024;

const SUB_TIMEOUT_SECS: u32 = 25;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

type Body = Response<Cursor<Vec<u8>>>;

pub fn serve(app: Arc<Mutex<App>>, addr: &str, workers: usize) -> Result<(), String> {
    let server = Server::http(addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;
    let server = Arc::new(server);

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let server = Arc::clone(&server);
        let app = Arc::clone(&app);
        handles.push(thread::spawn(move || loop {
            let Ok(request) = server.recv() else { return };
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

    let response = match (method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => html(INDEX_HTML),
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

    json_ok(json!({
        "nodes": nodes,
        "subs": state.subs,
        "settings": state.settings,
        "active": state.active,
        "dns_presets": dnscfg::PRESETS,
        "dns_resolvers": dnscfg::resolvers(&state.settings),
        "status": {
            "running": running,
            "started_at": app.sup.started_at,
            "running_node": app.sup.running_node,
            "last_error": app.sup.last_error,
            "config_path": app.sup.config_path().display().to_string(),
        },
        "tproxy": {
            "enabled": state.settings.transparent,
            "applied": tproxy::is_applied(),
            // Non-zero means a change is on probation and will roll back.
            "deadline": app.tproxy_deadline,
            "now": xray::now_secs(),
            "port": state.settings.tproxy_port,
            "interfaces": state.settings.lan_list(),
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
    let jobs = lock(app).probe_jobs();
    if jobs.is_empty() {
        return error(400, "there are no nodes to test");
    }
    // Probing is seconds of network wait -- the lock must be released first.
    let results = probe::probe_many(jobs, PROBE_TIMEOUT);

    let mut a = lock(app);
    a.apply_latencies(results);
    let reachable = a.state.nodes.iter().filter(|n| n.latency >= 0).count();
    let best = a.fastest().map(|n| json!({ "id": n.id, "name": n.name, "latency": n.latency }));
    let total = a.state.nodes.len();
    let _ = a.save();
    drop(a);

    json_ok(json!({
        "ok": true,
        "tested": total,
        "reachable": reachable,
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
    let next = match apply_settings(current, body) {
        Ok(next) => next,
        Err(e) => return error(400, &e),
    };
    lock(app).state.settings = next;
    finish_write(app, json!({ "ok": true }))
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
        if v.is_empty() {
            return Err("at least one LAN interface is required".into());
        }
        next.lan_interfaces = v.to_string();
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
    // Resolve before taking the lock -- this is a DNS round trip.
    let server_ips = lock(app).active_server_ips();

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

    // 2. Then the ruleset.
    {
        let a = lock(app);
        let plan = a.tproxy_plan(server_ips.clone());
        drop(a);
        if let Err(e) = tproxy::apply(&plan) {
            let mut a = lock(app);
            a.state.settings.transparent = false;
            let state = a.state.clone();
            let _ = a.sup.apply(&state);
            return error(500, &e);
        }
    }

    // 3. Arm the rollback. Deliberately *not* saved yet: if the router drops
    //    off the network now, a reboot must come back without any of this.
    let deadline = xray::now_secs() + CONFIRM_SECS;
    let guard = {
        let mut a = lock(app);
        a.tproxy_deadline = deadline;
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
    let mut a = lock(app);
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
    let (plan, _) = {
        let a = lock(app);
        (a.tproxy_plan(Vec::new()), ())
    };
    tproxy::revert(&plan);

    let mut a = lock(app);
    a.tproxy_guard.disarm();
    a.tproxy_deadline = 0;
    a.state.settings.transparent = false;
    let state = a.state.clone();
    if let Err(e) = a.sup.apply(&state) {
        eprintln!("xrayop: could not restart xray after rollback: {e}");
    }
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

    if let Some(obj) = payload.as_object_mut() {
        obj.insert("ok".into(), json!(true));
        obj.insert("running".into(), json!(running));
        if let Err(e) = result {
            obj.insert("apply_error".into(), json!(e));
        }
    }
    json_ok(payload)
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
    // Requiring JSON is what makes a cross-origin form POST impossible.
    let is_json = request
        .headers()
        .iter()
        .any(|h| h.field.equiv("Content-Type") && h.value.as_str().contains("application/json"));
    if !is_json {
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

    #[test]
    fn str_field_defaults_to_empty() {
        assert_eq!(str_field(&json!({ "a": "x" }), "a"), "x");
        assert_eq!(str_field(&json!({ "a": 5 }), "a"), "");
        assert_eq!(str_field(&json!({}), "a"), "");
    }
}
