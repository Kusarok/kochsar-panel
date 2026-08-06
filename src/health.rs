//! Keeping the tunnel alive, and getting out of the way when it cannot be.
//!
//! ## The failure this exists for
//!
//! Xray is a child of this daemon, not of procd, so nothing outside this
//! process notices when it dies. Before this module, a core that crashed at
//! three in the morning stayed dead until somebody opened the panel -- and with
//! transparent proxying on, the nftables rules kept redirecting every LAN
//! packet to a port with nothing behind it. The whole house loses the internet
//! and the router looks fine.
//!
//! ## Two responsibilities
//!
//! **Restart it.** A dead core is restarted within one check interval.
//!
//! **Give up correctly.** If it cannot be kept running, the transparent-proxy
//! rules are torn down so the LAN falls back to a direct connection. Censored
//! internet beats no internet, and it is recoverable without physical access.
//! OpenClash's watchdog does the same thing for the same reason; the mistake to
//! avoid is procd's default, which abandons a crash-looping service while its
//! firewall rules stay loaded.
//!
//! When the core comes back, the rules are re-applied automatically.
//!
//! ## Why a hung core is treated differently
//!
//! A process that is alive but not forwarding is also a real failure, and it is
//! detected here by making a request through the proxy. Acting on it is a
//! judgement call, though: the request also fails when the *server* is down,
//! which restarting Xray cannot fix. So the threshold is high and there is a
//! cooldown -- it will not thrash, and a genuinely dead upstream costs one
//! pointless restart every ten minutes rather than one every minute.

use crate::dnsmasq;
use crate::probe;
use crate::store::App;
use crate::tproxy;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How often liveness is checked. Short enough that a crash is invisible to
/// anyone watching a video, long enough to be free.
const CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Consecutive failed restarts before the transparent-proxy rules are torn
/// down. Four attempts across a minute is enough to distinguish "a transient
/// problem" from "this configuration cannot run".
const UNWIND_AFTER: u32 = 4;

/// How often the deep check runs while the core is alive.
const PROBE_EVERY: Duration = Duration::from_secs(60);
/// Consecutive deep-check failures before restarting a core that is alive but
/// not forwarding.
const PROBE_FAILURES_BEFORE_RESTART: u32 = 5;
/// Minimum gap between two probe-triggered restarts.
const PROBE_RESTART_COOLDOWN: Duration = Duration::from_secs(600);
/// Budget for one deep check. Generous: a slow tunnel is not a broken one.
const PROBE_TIMEOUT_SECS: u32 = 12;

/// Health counters, surfaced by the panel.
#[derive(Debug, Default, Clone)]
pub struct Status {
    /// Times the core has been restarted since the daemon started.
    pub restarts: u64,
    /// Consecutive failed restart attempts; 0 when healthy.
    pub failures: u32,
    /// True when the rules were torn down because the core could not be kept
    /// running. The setting stays on, so this is visibly different from the
    /// user having switched it off.
    pub degraded: bool,
    /// Why, for the panel to show.
    pub last_failure: String,
    /// Consecutive deep-check failures.
    pub probe_failures: u32,
    /// Whether the last deep check succeeded.
    pub reachable: bool,
}

pub fn spawn(app: Arc<Mutex<App>>) {
    thread::spawn(move || {
        let mut last_probe = Instant::now();
        let mut last_probe_restart: Option<Instant> = None;

        loop {
            thread::sleep(CHECK_INTERVAL);
            tick(&app, &mut last_probe, &mut last_probe_restart);
        }
    });
}

fn tick(
    app: &Arc<Mutex<App>>,
    last_probe: &mut Instant,
    last_probe_restart: &mut Option<Instant>,
) {
    // Nothing selected means nothing is supposed to be running.
    let (should_run, transparent, socks_port, test_url) = {
        let a = lock(app);
        (
            !a.state.active.is_empty(),
            a.state.settings.transparent,
            a.state.settings.socks_port,
            crate::dnscfg::test_url(&a.state.settings),
        )
    };
    if !should_run {
        return;
    }

    let alive = lock(app).sup.is_running();

    if !alive {
        handle_dead_core(app, transparent);
        return;
    }

    // Alive. Clear the restart counter and, if we previously gave up, put the
    // rules back now that there is something behind them again.
    let was_degraded = {
        let mut a = lock(app);
        a.health.failures = 0;
        a.health.degraded
    };
    if was_degraded && transparent {
        restore_rules(app);
    }

    if last_probe.elapsed() >= PROBE_EVERY {
        *last_probe = Instant::now();
        run_deep_check(app, socks_port, &test_url, last_probe_restart);
    }
}

/// Restart the core; tear the rules down if it will not stay up.
fn handle_dead_core(app: &Arc<Mutex<App>>, transparent: bool) {
    let (result, failures) = {
        let mut a = lock(app);
        let state = a.state.clone();
        let result = a.sup.apply(&state);
        match &result {
            Ok(()) => {
                a.health.restarts += 1;
                a.health.failures = 0;
                a.health.last_failure.clear();
            }
            Err(e) => {
                a.health.failures += 1;
                a.health.last_failure = e.clone();
            }
        }
        (result, a.health.failures)
    };

    match result {
        Ok(()) => eprintln!("xrayop: xray had died; restarted it"),
        Err(e) => eprintln!("xrayop: could not restart xray (attempt {failures}): {e}"),
    }

    // Still failing, and the firewall is pointing LAN traffic at a core that
    // is not there. Get out of the way.
    let already_degraded = lock(app).health.degraded;
    if failures >= UNWIND_AFTER && transparent && !already_degraded {
        eprintln!(
            "xrayop: xray has failed {failures} restarts; removing the transparent-proxy \
             rules so the LAN keeps working"
        );
        let plan = lock(app).tproxy_plan(Vec::new());
        tproxy::revert(&plan);
        let _ = dnsmasq::remove();

        let mut a = lock(app);
        a.tproxy_applied = false;
        a.dns_via_tunnel = false;
        a.health.degraded = true;
    }
}

/// Put the rules back after the core recovered.
fn restore_rules(app: &Arc<Mutex<App>>) {
    let host = lock(app).active_server_host();
    let ips = host.map(|h| probe::resolve_all(&h)).unwrap_or_default();

    let (plan, dns_port, bypass, resolver) = {
        let a = lock(app);
        (
            a.tproxy_plan(ips),
            a.state.settings.dns_port,
            a.server_hostnames(),
            a.state.settings.dns_bypass_resolver.clone(),
        )
    };

    if let Err(e) = tproxy::apply(&plan) {
        eprintln!("xrayop: xray recovered but the rules would not re-apply: {e}");
        return;
    }
    if let Err(e) = dnsmasq::install(dns_port, &bypass, &resolver) {
        eprintln!("xrayop: xray recovered but tunnelled DNS would not re-apply: {e}");
        tproxy::revert(&plan);
        return;
    }

    let mut a = lock(app);
    a.tproxy_applied = true;
    a.dns_via_tunnel = true;
    a.health.degraded = false;
    a.health.last_failure.clear();
    eprintln!("xrayop: xray recovered; transparent proxy restored");
}

/// Does a request actually complete through the proxy?
fn run_deep_check(
    app: &Arc<Mutex<App>>,
    socks_port: u16,
    url: &str,
    last_restart: &mut Option<Instant>,
) {
    let ok = request_succeeds(socks_port, url);

    let failures = {
        let mut a = lock(app);
        a.health.reachable = ok;
        if ok {
            a.health.probe_failures = 0;
        } else {
            a.health.probe_failures += 1;
        }
        a.health.probe_failures
    };
    if ok || failures < PROBE_FAILURES_BEFORE_RESTART {
        return;
    }

    // The core is alive but nothing gets through. This is also what a dead
    // upstream server looks like, which restarting cannot fix -- hence the
    // cooldown, so a permanently broken node costs one restart every ten
    // minutes instead of one every minute.
    if let Some(when) = last_restart {
        if when.elapsed() < PROBE_RESTART_COOLDOWN {
            return;
        }
    }
    *last_restart = Some(Instant::now());

    eprintln!("xrayop: xray is running but {failures} checks failed; restarting it");
    let mut a = lock(app);
    a.health.probe_failures = 0;
    let state = a.state.clone();
    if let Err(e) = a.sup.apply(&state) {
        a.health.last_failure = e;
    } else {
        a.health.restarts += 1;
    }
}

fn request_succeeds(socks_port: u16, url: &str) -> bool {
    Command::new("curl")
        .args([
            "--silent",
            "--output",
            "/dev/null",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            "--max-time",
            &PROBE_TIMEOUT_SECS.to_string(),
            "--proto",
            "=http,https",
            "--fail",
        ])
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A poisoned mutex means a handler panicked mid-update. Recovering it is right
/// here for the same reason as in the API: a router daemon that stops
/// supervising is worse than one working from slightly stale state.
fn lock(app: &Arc<Mutex<App>>) -> std::sync::MutexGuard<'_, App> {
    app.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unwind threshold has to be reachable in a time a person would
    /// tolerate being offline, but not so eager that one slow start trips it.
    #[test]
    fn unwind_threshold_is_about_a_minute() {
        let worst_case = CHECK_INTERVAL * UNWIND_AFTER;
        assert!(worst_case >= Duration::from_secs(30));
        assert!(worst_case <= Duration::from_secs(120));
    }

    /// A probe-triggered restart is a guess -- the same symptom appears when
    /// the upstream server is simply down. The cooldown is what stops that
    /// guess becoming a restart loop.
    #[test]
    fn probe_restarts_cannot_thrash() {
        let time_to_trip = PROBE_EVERY * PROBE_FAILURES_BEFORE_RESTART;
        assert!(time_to_trip >= Duration::from_secs(300));
        assert!(PROBE_RESTART_COOLDOWN >= time_to_trip);
    }

    /// Liveness is checked far more often than reachability: process death is
    /// unambiguous and cheap to detect, a failed request is neither.
    #[test]
    fn liveness_is_cheaper_than_reachability() {
        assert!(CHECK_INTERVAL < PROBE_EVERY);
        assert!(PROBE_TIMEOUT_SECS as u64 <= PROBE_EVERY.as_secs());
    }

    #[test]
    fn status_starts_healthy() {
        let s = Status::default();
        assert_eq!(s.restarts, 0);
        assert_eq!(s.failures, 0);
        assert!(!s.degraded);
        assert!(s.last_failure.is_empty());
    }
}
