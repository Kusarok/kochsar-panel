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
//! When the core comes back, the rules are re-applied automatically. A tunnel
//! unwind is different: the core never died, so liveness proves nothing, and
//! the rules go back only once a deep check passes again.
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
///
/// This also paces the deep check below, which is gated on it -- so it has to
/// divide [`PROBE_EVERY`] cleanly or the real probe cadence rounds up to the
/// next tick.
const CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Consecutive failed restarts before the transparent-proxy rules are torn
/// down. About a minute of trying is enough to distinguish "a transient
/// problem" from "this configuration cannot run".
const UNWIND_AFTER: u32 = 12;

/// How often the deep check runs while the core is alive.
///
/// This is the dominant term in how long the LAN stays offline after a server
/// dies: failover needs two consecutive failures, so this interval is most of
/// the detection time.
const PROBE_EVERY: Duration = Duration::from_secs(20);
/// Consecutive deep-check failures before restarting a core that is alive but
/// not forwarding. Counts probes, not seconds -- keep it in step with
/// [`PROBE_EVERY`] so the wall-clock threshold stays around five minutes.
const PROBE_FAILURES_BEFORE_RESTART: u32 = 15;
/// Minimum gap between two probe-triggered restarts.
const PROBE_RESTART_COOLDOWN: Duration = Duration::from_secs(600);
/// Budget for one deep check. Generous: a slow tunnel is not a broken one.
const PROBE_TIMEOUT_SECS: u32 = 12;

/// How long the tunnel may carry nothing before the rules come down.
///
/// This is the last resort, reached only after failover has had several
/// chances and the raw WAN is known to be working. A direct connection is not
/// what anyone wants, but a house with no internet at all is worse.
const TUNNEL_UNWIND_AFTER: Duration = Duration::from_secs(600);

/// Budget for the direct check that decides whether the WAN itself is up.
const WAN_CHECK_TIMEOUT: Duration = Duration::from_secs(4);

/// How often the tunnel is checked, so the switcher's tests can reason about
/// their own detection budget without copying the constant and letting the two
/// drift apart.
#[cfg(test)]
pub fn probe_interval() -> Duration {
    PROBE_EVERY
}

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
    /// True when the rules were torn down specifically because the tunnel
    /// carried no traffic ([`unwind_dead_tunnel`]), as opposed to a core that
    /// would not start. The restores differ: a dead core may be put back the
    /// moment it runs again, a dead tunnel only once a probe passes -- the
    /// core being alive is not evidence the tunnel carries traffic.
    pub tunnel_unwound: bool,
}

/// State the health thread carries between ticks.
#[derive(Default)]
struct Watch {
    last_probe: Option<Instant>,
    last_probe_restart: Option<Instant>,
    /// When the tunnel first stopped carrying traffic, cleared on success.
    ///
    /// Kept here rather than derived from `probe_failures`, which the restart
    /// path zeroes: the question "how long has the LAN been offline" has to
    /// survive our own attempts to fix it.
    bad_since: Option<Instant>,
}

pub fn spawn(app: Arc<Mutex<App>>) {
    thread::spawn(move || {
        let mut watch = Watch::default();
        loop {
            thread::sleep(CHECK_INTERVAL);
            tick(&app, &mut watch);
        }
    });
}

fn tick(app: &Arc<Mutex<App>>, watch: &mut Watch) {
    // Nothing selected, switched off, or deliberately paused means nothing is
    // supposed to be running. Without the second and third conditions this
    // thread "restarted" an intentionally stopped core every five seconds --
    // it cannot tell "stopped on purpose" from "died" on its own.
    let (should_run, transparent, socks_port, test_url, resolver) = {
        let a = lock(app);
        (
            !a.state.active.is_empty() && a.state.settings.core_enabled() && !a.core_paused,
            a.state.settings.transparent,
            a.state.settings.socks_port,
            crate::dnscfg::test_url(&a.state.settings),
            a.state.settings.bypass_resolver(),
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

    // Alive. Clear the restart counter and, if we previously gave up because
    // the core would not start, put the rules back now that there is something
    // behind them again. A tunnel unwind is NOT restored here: the core never
    // died in that case, so its being alive says nothing about whether traffic
    // passes. Restoring on liveness anyway was the flap -- the rules went back
    // onto a still-dead tunnel within one tick, the next failed probe took
    // them down again, and dnsmasq restarted twice a cycle forever.
    let (was_degraded, tunnel_unwound) = {
        let mut a = lock(app);
        a.health.failures = 0;
        (a.health.degraded, a.health.tunnel_unwound)
    };
    if was_degraded && transparent && restore_on_liveness(tunnel_unwound) {
        restore_rules(app);
    }

    let due = watch
        .last_probe
        .map(|t| t.elapsed() >= PROBE_EVERY)
        .unwrap_or(true);
    if !due {
        return;
    }
    watch.last_probe = Some(Instant::now());

    let ok = run_deep_check(app, socks_port, &test_url, &mut watch.last_probe_restart);
    if ok {
        if watch.bad_since.take().is_some() {
            eprintln!("xrayop: the tunnel is carrying traffic again");
        }
        // The one piece of evidence a dead-tunnel unwind may be undone on:
        // traffic actually passes again.
        if transparent && lock(app).health.tunnel_unwound {
            restore_rules(app);
        }
        return;
    }

    let down_for = *watch.bad_since.get_or_insert_with(Instant::now);
    // Only interesting once it has lasted; a single failed probe is noise.
    let failures = lock(app).health.probe_failures;
    if failures == 2 {
        eprintln!(
            "xrayop: the tunnel has failed {failures} checks -- the active server \
             is not carrying traffic"
        );
    }

    if transparent && down_for.elapsed() >= TUNNEL_UNWIND_AFTER {
        unwind_dead_tunnel(app, &resolver);
    }
}

/// Last resort: the core is running, the rules are loaded, and nothing gets
/// through any of it.
///
/// `handle_dead_core` already does this for a core that will not start, but
/// that path cannot be reached while the process is alive -- and a live core
/// in front of a dead server strands the LAN exactly as thoroughly. Failover
/// has had ten minutes and several attempts by the time this runs.
///
/// Not done when the user's own internet is down: there would be nothing to
/// fall back *to*, and the rules would have to be rebuilt for nothing.
fn unwind_dead_tunnel(app: &Arc<Mutex<App>>, resolver: &str) {
    if lock(app).health.degraded {
        return;
    }
    if !wan_reachable(resolver) {
        eprintln!(
            "xrayop: the tunnel is down, but so is the WAN -- leaving the rules in place"
        );
        return;
    }

    eprintln!(
        "xrayop: nothing has passed through the tunnel for ten minutes and the WAN is up; \
         removing the transparent-proxy rules so the LAN keeps working"
    );
    let plan = lock(app).tproxy_plan(Vec::new());
    tproxy::revert(&plan);
    let _ = dnsmasq::remove();

    let mut a = lock(app);
    a.tproxy_applied = false;
    a.dns_via_tunnel = false;
    a.dns_domains.clear();
    a.health.degraded = true;
    a.health.tunnel_unwound = true;
    a.health.last_failure = "the tunnel carried no traffic for ten minutes".into();
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
        // Removed, so nothing is installed; the restore path must rewrite it.
        a.dns_domains.clear();
        a.health.degraded = true;
    }
}

/// Whether the rules may go back up purely because the core is alive again.
///
/// True only for a core that would not start: the process running *is* the
/// recovery. A tunnel unwind is different -- the core never died, so its
/// being alive says nothing about whether traffic passes, and restoring on
/// that evidence alone put the rules back onto a still-dead tunnel one tick
/// after they came down.
fn restore_on_liveness(tunnel_unwound: bool) -> bool {
    !tunnel_unwound
}

/// Put the rules back after the core recovered. Also how `/api/service start`
/// re-applies them after a stop in transparent mode took them down.
pub(crate) fn restore_rules(app: &Arc<Mutex<App>>) {
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
    a.dns_domains = bypass;
    a.health.degraded = false;
    a.health.tunnel_unwound = false;
    a.health.last_failure.clear();
    eprintln!("xrayop: transparent proxy restored");
}

/// Does a request actually complete through the proxy? Returns whether it did.
fn run_deep_check(
    app: &Arc<Mutex<App>>,
    socks_port: u16,
    url: &str,
    last_restart: &mut Option<Instant>,
) -> bool {
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
        return ok;
    }

    // The core is alive but nothing gets through. This is also what a dead
    // upstream server looks like, which restarting cannot fix -- hence the
    // cooldown, so a permanently broken node costs one restart every ten
    // minutes instead of one every minute.
    if let Some(when) = last_restart {
        if when.elapsed() < PROBE_RESTART_COOLDOWN {
            return ok;
        }
    }
    *last_restart = Some(Instant::now());

    eprintln!("xrayop: xray is running but {failures} checks failed; restarting it");
    let mut a = lock(app);
    // The counter is deliberately not reset: it is the switcher's failover
    // signal, and only a successful probe may clear it. Zeroing it here
    // postponed a pending failover by two probe cycles for nothing -- the
    // restart does not make the upstream server work.
    let state = a.state.clone();
    if let Err(e) = a.sup.apply(&state) {
        a.health.last_failure = e;
    } else {
        a.health.restarts += 1;
    }
    ok
}

/// Whether the raw WAN carries traffic at all, measured without the tunnel.
///
/// Every symptom this module reacts to -- the probe timing out, the LAN going
/// quiet -- looks identical whether the proxy server died or the user's own
/// internet did. Switching servers cannot fix the second, and trying makes it
/// worse: it cycles through the whole list, restarting the core each time,
/// while the one thing that would help is waiting.
///
/// A TCP connection to the bypass resolver on port 53 answers the question
/// cheaply and, importantly, *directly*. That address is already exempt from
/// interception twice over -- it sits in the `bypass4` set, and the output
/// chain returns early on port 53 -- so this cannot accidentally be measured
/// through the tunnel it is supposed to be independent of.
///
/// An unparseable resolver returns `true`: this check exists to *suppress*
/// failover, and one that cannot run must not be the reason a dead server is
/// kept.
pub fn wan_reachable(resolver: &str) -> bool {
    let Ok(ip) = resolver.trim().parse::<std::net::IpAddr>() else {
        return true;
    };
    let addr = std::net::SocketAddr::new(ip, 53);
    std::net::TcpStream::connect_timeout(&addr, WAN_CHECK_TIMEOUT).is_ok()
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

    /// The deep check is gated on the liveness tick, so a probe interval that
    /// is not a multiple of it silently rounds up -- 20 s asked for, 30 s
    /// delivered, and the detection budget blown by half.
    #[test]
    fn the_probe_cadence_is_not_quietly_rounded_up() {
        assert_eq!(
            PROBE_EVERY.as_secs() % CHECK_INTERVAL.as_secs(),
            0,
            "PROBE_EVERY must be a whole number of ticks"
        );
    }

    /// The restart threshold counts probes, not seconds. Changing the probe
    /// rate without it would move the real threshold with it.
    #[test]
    fn the_restart_threshold_is_still_about_five_minutes() {
        let wall_clock = PROBE_EVERY * PROBE_FAILURES_BEFORE_RESTART;
        assert!(wall_clock >= Duration::from_secs(240));
        assert!(wall_clock <= Duration::from_secs(420));
    }

    /// The last resort has to come after failover has had a real chance,
    /// or the LAN drops to a direct connection over something that would have
    /// been fixed by changing servers.
    #[test]
    fn the_tunnel_unwind_waits_longer_than_failover_needs() {
        assert!(TUNNEL_UNWIND_AFTER >= Duration::from_secs(300));
        assert!(TUNNEL_UNWIND_AFTER > PROBE_EVERY * PROBE_FAILURES_BEFORE_RESTART);
    }

    /// It cannot answer, so it must not be the reason failover is suppressed.
    #[test]
    fn an_unparseable_resolver_reports_the_wan_as_up() {
        assert!(wan_reachable(""));
        assert!(wan_reachable("router.lan"));
        assert!(wan_reachable("  "));
    }

    #[test]
    fn status_starts_healthy() {
        let s = Status::default();
        assert_eq!(s.restarts, 0);
        assert_eq!(s.failures, 0);
        assert!(!s.degraded);
        assert!(!s.tunnel_unwound);
        assert!(s.last_failure.is_empty());
    }

    /// The flap this module once had: a dead-tunnel unwind was undone one tick
    /// later because the core happened to be alive, then the next failed probe
    /// unwound again -- the rules and dnsmasq churned every twenty seconds
    /// forever, and the LAN never got its direct fallback.
    #[test]
    fn a_dead_tunnel_unwind_is_not_undone_by_liveness_alone() {
        assert!(restore_on_liveness(false), "a dead core running again is recovery");
        assert!(
            !restore_on_liveness(true),
            "a live core says nothing about whether the tunnel passes traffic"
        );
    }
}
