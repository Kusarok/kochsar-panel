//! Automatic failover between servers.
//!
//! A subscription's servers do not fail politely. One stops answering, the
//! tunnel stays "connected", and everything is slow or broken until somebody
//! opens the panel and taps a different one. This watches for that and moves.
//!
//! ## Two triggers, deliberately different
//!
//! **On a schedule**, every `auto_switch_minutes`. This catches gradual decay:
//! a server that still works but has become the slowest in the list.
//!
//! **On failure**, as soon as the health probe reports the tunnel is not
//! carrying traffic. Waiting hours for the next scheduled sweep would defeat
//! the point -- the whole reason for this feature is that a dead server should
//! be replaced in minutes, not at the next interval.
//!
//! ## Measured outside the tunnel
//!
//! [`crate::latency`] starts its own Xray with one inbound per server and
//! measures each through its *own* outbound. Nothing is measured through the
//! server currently in use, so a failing active node cannot make the
//! alternatives look bad.
//!
//! ## Why it does not chase the fastest number
//!
//! Latency to a distant server varies by hundreds of milliseconds between
//! measurements. Switching on every improvement would reconnect constantly,
//! and every switch drops live connections. So a working server is only
//! replaced when the alternative is *clearly* better -- see [`is_worth_switching`].

use crate::latency;
use crate::store::App;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How often the conditions are re-examined. Much shorter than any sweep
/// interval, so a failure trigger is acted on promptly.
const TICK: Duration = Duration::from_secs(10);

/// Consecutive health-probe failures before failover is triggered.
///
/// The probe runs every twenty seconds, so this is about forty seconds of the
/// tunnel not carrying traffic -- long enough that a single blip does not
/// reconnect the whole house, short enough that nobody finishes making tea.
const FAILURES_BEFORE_FAILOVER: u32 = 2;

/// Shortest gap between two *quality* switches.
///
/// Every switch restarts the core and drops live connections. Without a floor,
/// a subscription where several servers are borderline would flap between them.
const MIN_GAP: Duration = Duration::from_secs(300);

/// Shortest gap between two attempts to escape a tunnel that is carrying
/// nothing.
///
/// Deliberately far below [`MIN_GAP`]. That floor exists to stop flapping
/// between servers that both work; applying it here would strand the LAN for
/// five minutes whenever the server we just moved to is also down. Long enough
/// for the health probe to reach a verdict on the new server -- two checks --
/// and no longer.
const ESCAPE_GAP: Duration = Duration::from_secs(60);

/// How often latencies are refreshed in the background.
///
/// Separate from `auto_switch_minutes`, which is how often the user asked the
/// panel to *change servers*. Measuring is not switching, and the stored table
/// is what a failover picks a replacement from -- four-hour-old numbers are not
/// something to bet the household's internet on.
const REFRESH_EVERY: Duration = Duration::from_secs(30 * 60);

/// When the first background sweep of a daemon run happens, if nothing has
/// ever been measured.
///
/// Failover picks its replacement from the stored table, so the table has to
/// exist. A fresh install -- every server untested -- otherwise spent up to
/// thirty minutes of a dead tunnel waiting for the first measurement, and
/// "failover never works" was the report. Sixty seconds is long after the
/// core has settled, so the reason a sweep at second zero is ruled out does
/// not apply.
const FIRST_SWEEP_AFTER: Duration = Duration::from_secs(60);

/// A replacement must beat the current server by at least this fraction...
const BETTER_BY: f64 = 0.80;
/// ...and by at least this many milliseconds. Both, so neither a tiny
/// proportional win on fast servers nor a large one on slow servers alone is
/// enough.
const BETTER_BY_MS: i32 = 20;

// These were 0.65 and 250 ms, chosen when [`crate::latency`] reported the cold
// connection time and a subscription spread across 1400-2500 ms. It now reports
// the warm round trip, and the same subscription spreads across 120-270 ms --
// so a 250 ms absolute floor was wider than the entire range and no healthy
// server could ever have been replaced. The feature would have looked enabled
// and quietly never fired.
//
// 20 ms is close to the noise floor -- repeated warm measurements of one server
// land within about 15 ms of each other -- and on its own it would be too eager.
// It is safe only because [`BETTER_BY`] must also hold: above about 100 ms the
// proportional test is the binding one, so the floor matters just for servers
// fast enough that a fifth of their latency is under 20 ms. Lower this further
// only together with a proportional threshold that can still carry the decision.

#[derive(Debug, Default, Clone)]
pub struct Status {
    /// Unix seconds of the last automatic switch; 0 if it has never happened.
    pub last_switch: u64,
    /// What it switched to, for the panel to show.
    pub last_switch_to: String,
    /// Why: `scheduled` or `failover`.
    pub last_switch_reason: String,
    /// Automatic switches so far.
    pub switches: u64,
    /// Unix seconds of the last sweep, automatic or not.
    pub last_sweep: u64,
}

/// Why the switcher woke up.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Reason {
    /// The tunnel is not carrying traffic. Get off this server.
    Failover,
    /// The user's interval elapsed; a clearly better server may be adopted.
    Scheduled,
    /// Keep the measurements current. Never switches a working server.
    Refresh,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Reason::Failover => "failover",
            Reason::Scheduled => "scheduled",
            Reason::Refresh => "refresh",
        }
    }
}

/// Clocks the switcher keeps between ticks.
///
/// The schedule and the refresh are deliberately separate. Sharing one meant a
/// burst of failovers pushed the user's next scheduled sweep out by another
/// four hours each time.
struct Clocks {
    scheduled: Instant,
    refresh: Instant,
    /// When the daemon started, for [`FIRST_SWEEP_AFTER`].
    started: Instant,
    /// Last *quality* switch, for [`MIN_GAP`].
    switch: Option<Instant>,
    /// Last attempt to escape a dead tunnel, for [`ESCAPE_GAP`]. Recorded even
    /// when the attempt changed nothing, or a failed attempt would repeat on
    /// every tick and sweep the whole list every ten seconds.
    escape: Option<Instant>,
}

pub fn spawn(app: Arc<Mutex<App>>) {
    thread::spawn(move || {
        // Not zero: a sweep the instant the daemon starts would run before the
        // core has finished coming up and report everything as failed. The
        // first one runs after [`FIRST_SWEEP_AFTER`] instead of a full
        // [`REFRESH_EVERY`] -- see `due`.
        let now = Instant::now();
        let mut clocks = Clocks {
            scheduled: now,
            refresh: now,
            started: now,
            switch: None,
            escape: None,
        };

        loop {
            thread::sleep(TICK);
            let Some(reason) = due(&app, &clocks) else {
                continue;
            };
            match reason {
                Reason::Failover => {
                    clocks.escape = Some(Instant::now());
                    let swept = clocks.refresh;
                    if escape_dead_tunnel(&app, &mut clocks) {
                        // Refresh afterwards so the next failure has current
                        // numbers to choose from, and so the server we just
                        // left is measured again rather than left guessed at.
                        // Escape already swept when it had to build the table
                        // itself; a second sweep back to back learns nothing.
                        if clocks.refresh == swept && run_sweep(&app, Reason::Refresh, &mut clocks)
                        {
                            clocks.refresh = Instant::now();
                        }
                    }
                }
                Reason::Scheduled => {
                    if run_sweep(&app, reason, &mut clocks) {
                        clocks.scheduled = Instant::now();
                        clocks.refresh = Instant::now();
                    }
                }
                Reason::Refresh => {
                    if run_sweep(&app, reason, &mut clocks) {
                        clocks.refresh = Instant::now();
                    }
                }
            }
        }
    });
}

/// What should happen now, or nothing.
fn due(app: &Arc<Mutex<App>>, clocks: &Clocks) -> Option<Reason> {
    let a = lock(app);
    if !a.state.settings.auto_switch || a.state.nodes.len() < 2 {
        return None;
    }
    // Nothing to fail over from, and nothing to fail over to. A paused core
    // is the user's explicit choice, and switching would restart it.
    if a.state.active.is_empty() || !a.state.settings.core_enabled() || a.core_paused {
        return None;
    }

    let failing = a.health.probe_failures >= FAILURES_BEFORE_FAILOVER;
    let never_swept = a.switcher.last_sweep == 0;
    let interval = Duration::from_secs(a.state.settings.auto_switch_minutes.max(1) as u64 * 60);
    drop(a);

    if failing {
        let blocked = clocks
            .escape
            .map(|t| t.elapsed() < ESCAPE_GAP)
            .unwrap_or(false);
        if !blocked {
            return Some(Reason::Failover);
        }
        // Fall through rather than returning. A blocked escape used to suppress
        // the scheduled sweep as well, so a spell of failures could postpone
        // the user's interval indefinitely.
    }
    if clocks.scheduled.elapsed() >= interval {
        return Some(Reason::Scheduled);
    }
    // The first sweep of a daemon run comes early: until something has been
    // measured, failover has no table to pick from, and thirty minutes is a
    // long time to find that out. Sixty seconds is long after the core has
    // settled, so the startup concern above does not apply.
    let first_sweep_due = never_swept && clocks.started.elapsed() >= FIRST_SWEEP_AFTER;
    if first_sweep_due || clocks.refresh.elapsed() >= REFRESH_EVERY {
        return Some(Reason::Refresh);
    }
    None
}

/// The tunnel is not carrying traffic. Move to another server now.
///
/// This deliberately does **not** consult [`is_worth_switching`], and that is
/// the whole point of it being separate. That rule judges gradual decay, and it
/// asks "is the alternative clearly better?" -- a reasonable question when the
/// current server works, and the wrong one when the LAN has no internet.
///
/// The two measurements disagree here by design. The health probe goes through
/// the *live core*; the latency sweep measures through a *fresh throwaway
/// Xray*, so that a failing active server cannot drag the others down. When a
/// server is throttled, out of quota, or the running core is wedged, the live
/// probe fails while the fresh probe still reports a good number -- and the
/// decay rule then answers "not 20% better, stay". Forever, while nothing
/// works. Asking instead "which other server is known to work" is the fix.
///
/// No sweep first: measuring 31 servers takes twenty seconds the household
/// spends offline. The stored table is refreshed afterwards. The one exception
/// is an empty table -- see below.
fn escape_dead_tunnel(app: &Arc<Mutex<App>>, clocks: &mut Clocks) -> bool {
    let (resolver, active_id) = {
        let a = lock(app);
        (a.state.settings.bypass_resolver(), a.state.active.clone())
    };

    // Every symptom of a dead server is also a symptom of a dead WAN, and
    // switching cannot fix the second -- it just cycles the whole list,
    // restarting the core each time, while waiting is what would help.
    if !crate::health::wan_reachable(&resolver) {
        eprintln!(
            "xrayop: the tunnel is down, but so is the WAN -- staying on the current server"
        );
        return false;
    }

    let mut pick = {
        let a = lock(app);
        a.fastest_other(&active_id)
            .map(|n| (n.id.clone(), n.name.clone(), n.latency))
    };

    if pick.is_none() {
        // The table has nothing to offer: nothing was ever measured, or
        // everything else is already marked failed. "No sweep first" stops
        // applying here -- measuring costs the LAN twenty seconds it is
        // already spending offline, while refusing used to cost it up to
        // thirty minutes: the whole gap until the next refresh. This was the
        // "server died and nothing switched" report.
        if run_sweep(app, Reason::Refresh, clocks) {
            clocks.refresh = Instant::now();
            // The sweep moves on its own when the active server measures
            // dead; if it did, there is nothing left to escape from.
            if lock(app).state.active != active_id {
                return true;
            }
        }
        pick = {
            let a = lock(app);
            a.fastest_other(&active_id)
                .map(|n| (n.id.clone(), n.name.clone(), n.latency))
        };
    }

    let Some((id, name, latency)) = pick else {
        eprintln!(
            "xrayop: the tunnel is down and no other server has a working measurement; \
             leaving it alone"
        );
        return false;
    };

    let mut a = lock(app);
    // The server we are leaving measured fine from a fresh instance and failed
    // through the live one. Recording that is what stops the next sweep
    // cheerfully electing it again; the refresh that follows re-measures it.
    a.mark_failed(&active_id);
    if a.select(&id).is_err() {
        return false;
    }
    a.switcher.switches += 1;
    a.switcher.last_switch = crate::xray::now_secs();
    a.switcher.last_switch_to = name.clone();
    a.switcher.last_switch_reason = Reason::Failover.as_str().to_string();
    let result = a.save_and_apply();
    drop(a);

    clocks.switch = Some(Instant::now());
    match result {
        Ok(()) => eprintln!(
            "xrayop: the tunnel stopped carrying traffic; moved to \"{name}\" ({latency} ms) -- failover"
        ),
        Err(e) => eprintln!("xrayop: moved to \"{name}\" but it would not start: {e}"),
    }
    true
}

/// Measures every server, and adopts a clearly better one when asked to.
///
/// Only ever called for [`Reason::Scheduled`] and [`Reason::Refresh`]; a
/// failover is handled by [`escape_dead_tunnel`] before any of this, because it
/// must not wait for a measurement.
///
/// Returns whether the sweep actually ran.
fn run_sweep(app: &Arc<Mutex<App>>, reason: Reason, clocks: &mut Clocks) -> bool {
    let (nodes, settings, runtime, gate) = {
        let a = lock(app);
        (
            a.state.nodes.clone(),
            a.state.settings.clone(),
            a.sup.runtime_dir().to_path_buf(),
            Arc::clone(&a.probing),
        )
    };
    // A manual test from the panel is already running; let it finish.
    if gate.swap(true, Ordering::SeqCst) {
        return false;
    }
    let _release = ReleaseOnDrop(Arc::clone(&gate));

    let url = crate::dnscfg::test_url(&settings);
    let outcome = match latency::measure(
        &nodes,
        &settings,
        &runtime,
        &url,
        Duration::from_secs(8),
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("xrayop: automatic sweep failed: {e}");
            // Nothing was measured, so nothing was learned. Reporting this as a
            // completed sweep used to reset the user's interval, meaning a
            // setup fault that fails instantly could burn four hours at a time
            // and never actually test anything.
            return false;
        }
    };

    let mut a = lock(app);
    a.apply_latencies(outcome.results);
    a.switcher.last_sweep = crate::xray::now_secs();

    let active = a.state.find(&a.state.active).cloned();
    let best = a.fastest().cloned();
    drop(a);

    let (Some(active), Some(best)) = (active, best) else {
        return true;
    };
    if best.id == active.id {
        return true;
    }

    // A refresh exists to keep the numbers current, not to move anyone. The
    // one exception is a current server that has stopped working outright:
    // leaving the LAN on that until the user's next interval would be perverse.
    let wanted = match reason {
        Reason::Refresh => active.latency < 0,
        _ => is_worth_switching(active.latency, best.latency),
    };
    if !wanted {
        return true;
    }
    // The flap floor applies to taste, not to survival: a dead current server
    // is escaped regardless of how recently something else changed.
    if active.latency >= 0 && clocks.switch.map(|t| t.elapsed() < MIN_GAP).unwrap_or(false) {
        return true;
    }

    let mut a = lock(app);
    if a.select(&best.id).is_err() {
        return true;
    }
    a.switcher.switches += 1;
    a.switcher.last_switch = crate::xray::now_secs();
    a.switcher.last_switch_to = best.name.clone();
    a.switcher.last_switch_reason = reason.as_str().to_string();
    let result = a.save_and_apply();
    drop(a);

    clocks.switch = Some(Instant::now());
    match result {
        Ok(()) => eprintln!(
            "xrayop: switched to \"{}\" ({} ms, was {} ms) -- {}",
            best.name,
            best.latency,
            active.latency,
            reason.as_str()
        ),
        Err(e) => eprintln!("xrayop: switched to \"{}\" but it would not start: {e}", best.name),
    }
    true
}

/// Whether `candidate` is enough better than `current` to be worth the
/// reconnect.
///
/// A dead current server is replaced by anything that works. A working one is
/// only replaced by something clearly better on both a proportional and an
/// absolute measure, because latency to a distant server swings by hundreds of
/// milliseconds between measurements and chasing that would reconnect forever.
fn is_worth_switching(current: i32, candidate: i32) -> bool {
    if candidate < 0 {
        return false; // the candidate does not work either
    }
    if current < 0 {
        return true; // the current one does not work
    }
    let proportional = (candidate as f64) < (current as f64) * BETTER_BY;
    let absolute = current - candidate >= BETTER_BY_MS;
    proportional && absolute
}

struct ReleaseOnDrop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn lock(app: &Arc<Mutex<App>>) -> std::sync::MutexGuard<'_, App> {
    app.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Node;

    #[test]
    fn a_dead_server_is_replaced_by_anything_that_works() {
        assert!(is_worth_switching(Node::LATENCY_FAILED, 3000));
        assert!(is_worth_switching(Node::LATENCY_UNTESTED, 3000));
    }

    #[test]
    fn a_working_server_is_never_replaced_by_a_dead_one() {
        assert!(!is_worth_switching(1500, Node::LATENCY_FAILED));
        assert!(!is_worth_switching(Node::LATENCY_FAILED, Node::LATENCY_FAILED));
    }

    /// Repeated warm measurements of one server land within about 15 ms of each
    /// other. Reacting to that would reconnect on every sweep.
    #[test]
    fn small_improvements_do_not_trigger_a_reconnect() {
        assert!(!is_worth_switching(135, 121)); // two good servers, 14ms apart
        assert!(!is_worth_switching(179, 175));
        assert!(!is_worth_switching(173, 161));
    }

    #[test]
    fn a_clear_improvement_does() {
        assert!(is_worth_switching(173, 121)); // 30% and 52ms
        assert!(is_worth_switching(270, 121));
    }

    /// Both tests must pass, so neither a big proportional win on already-fast
    /// servers nor a big absolute win on slow ones is enough alone.
    #[test]
    fn both_measures_are_required() {
        // A quarter off, but only 12ms saved -- inside measurement noise.
        assert!(!is_worth_switching(50, 38));
        // 100ms saved, but only a tenth off -- the pair are comparable.
        assert!(!is_worth_switching(1000, 900));
    }

    /// The thresholds have to fit the numbers [`crate::latency`] actually
    /// produces. They once did not: an absolute floor wider than the whole
    /// spread of a subscription meant no healthy server could be replaced, and
    /// nothing said so -- the panel showed the feature enabled and it never
    /// fired. Guard the relationship, not just the values.
    #[test]
    fn the_absolute_floor_fits_the_scale_it_judges() {
        // A realistic subscription, warm: fastest to slowest.
        let (fastest, slowest) = (121, 270);
        assert!(
            BETTER_BY_MS < slowest - fastest,
            "a floor of {BETTER_BY_MS}ms cannot be crossed within a {}ms spread",
            slowest - fastest
        );
        // ...and the worst server in that spread must be replaceable by the best.
        assert!(is_worth_switching(slowest, fastest));
    }

    /// Every switch drops live connections, so the floor between them has to be
    /// long enough that a borderline subscription cannot flap.
    #[test]
    fn the_gap_between_switches_is_long_enough_to_matter() {
        assert!(MIN_GAP >= Duration::from_secs(120));
        assert!(TICK < MIN_GAP);
    }

    /// The number the user actually feels: how long the house is offline
    /// before something is done about it. This used to be three to four
    /// minutes and was reported as "it never switches".
    #[test]
    fn a_dead_tunnel_is_acted_on_within_a_minute() {
        let probe_interval = crate::health::probe_interval();
        let detect = probe_interval * FAILURES_BEFORE_FAILOVER + TICK;
        assert!(
            detect <= Duration::from_secs(60),
            "detection takes {detect:?}; the LAN is offline for all of it"
        );
    }

    /// Escaping a dead tunnel and preferring a nicer server are different
    /// questions and must not share a floor. Waiting out the anti-flap gap
    /// while nothing works is how a four-minute outage becomes a nine-minute
    /// one.
    #[test]
    fn escaping_is_not_held_to_the_anti_flap_floor() {
        assert!(ESCAPE_GAP < MIN_GAP);
        // Long enough for the health probe to reach a verdict on the server we
        // just moved to, so a run of dead servers is walked, not thrashed.
        let verdict = crate::health::probe_interval() * FAILURES_BEFORE_FAILOVER;
        assert!(ESCAPE_GAP >= verdict, "we would move again before knowing");
    }

    /// The failover path deliberately does not consult `is_worth_switching`.
    /// This is the bug that left the LAN offline indefinitely: a throttled
    /// server measures fine from a fresh probe, so the decay rule answered
    /// "not clearly better, stay" while nothing was getting through.
    #[test]
    fn the_decay_rule_would_have_refused_the_switch_failover_makes() {
        // Typical numbers from the live router: the failing server still
        // measures 120 ms in isolation, the best alternative is 100 ms.
        assert!(
            !is_worth_switching(120, 100),
            "if this ever passes, the two paths have converged and the \
             separate failover path is no longer proving anything"
        );
    }

    /// Measuring is not switching. The user's interval governs how often the
    /// panel may change servers; the refresh only keeps the numbers current,
    /// so a failover has something recent to choose from.
    #[test]
    fn refreshing_is_far_more_frequent_than_switching() {
        let user_interval = Duration::from_secs(240 * 60);
        assert!(REFRESH_EVERY < user_interval / 4);
        // But not so often that an armv7 router spends its life sweeping.
        assert!(REFRESH_EVERY >= Duration::from_secs(10 * 60));
    }

    /// Failover picks from the stored table, so the table has to exist. A
    /// fresh install measured nothing until the first refresh, thirty minutes
    /// in -- and a dead server in that window was reported as "it never
    /// switches". The first sweep must be early, but not second zero: the
    /// core has to be up first.
    #[test]
    fn the_first_sweep_is_early_but_not_instant() {
        assert!(
            FIRST_SWEEP_AFTER >= Duration::from_secs(30),
            "a sweep at boot measures a core that is still starting"
        );
        assert!(
            FIRST_SWEEP_AFTER <= Duration::from_secs(120),
            "failover needs a table within minutes, not half an hour"
        );
        assert!(FIRST_SWEEP_AFTER < REFRESH_EVERY / 4);
    }

    #[test]
    fn reasons_are_named_for_the_log() {
        assert_eq!(Reason::Failover.as_str(), "failover");
        assert_eq!(Reason::Scheduled.as_str(), "scheduled");
        assert_eq!(Reason::Refresh.as_str(), "refresh");
    }

    /// A WAN check that cannot run must not be the reason a dead server is
    /// kept -- it exists to suppress failover, so it fails open.
    #[test]
    fn an_unusable_wan_check_does_not_block_failover() {
        assert!(crate::health::wan_reachable(""));
        assert!(crate::health::wan_reachable("not-an-address"));
    }
}
