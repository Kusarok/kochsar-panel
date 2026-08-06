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
const TICK: Duration = Duration::from_secs(30);

/// Consecutive health-probe failures before failover is triggered.
///
/// The probe runs once a minute, so this is about three minutes of the tunnel
/// not carrying traffic -- long enough not to react to one bad minute.
const FAILURES_BEFORE_FAILOVER: u32 = 3;

/// Shortest gap between two automatic switches, whatever the trigger.
///
/// Every switch restarts the core and drops live connections. Without a floor,
/// a subscription where several servers are borderline would flap between them.
const MIN_GAP: Duration = Duration::from_secs(300);

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

pub fn spawn(app: Arc<Mutex<App>>) {
    thread::spawn(move || {
        // Not zero: a sweep the instant the daemon starts would run before the
        // core has finished coming up and report everything as failed.
        let mut last_sweep = Instant::now();
        let mut last_switch = None::<Instant>;

        loop {
            thread::sleep(TICK);
            if let Some(reason) = due(&app, last_sweep, last_switch) {
                if run_sweep(&app, reason, &mut last_switch) {
                    // Only a completed sweep resets the schedule; one that was
                    // skipped because a manual test held the gate should be
                    // retried on the next tick.
                    last_sweep = Instant::now();
                }
            }
        }
    });
}

/// Why a sweep should run now, or `None`.
fn due(
    app: &Arc<Mutex<App>>,
    last_sweep: Instant,
    last_switch: Option<Instant>,
) -> Option<&'static str> {
    let a = lock(app);
    if !a.state.settings.auto_switch || a.state.nodes.len() < 2 {
        return None;
    }
    // Nothing to fail over from, and nothing to fail over to.
    if a.state.active.is_empty() || !a.state.settings.core_enabled() {
        return None;
    }

    let failing = a.health.probe_failures >= FAILURES_BEFORE_FAILOVER;
    let interval = Duration::from_secs(a.state.settings.auto_switch_minutes.max(1) as u64 * 60);
    let scheduled = last_sweep.elapsed() >= interval;
    drop(a);

    if failing {
        // The floor still applies: if switching did not help, switching again
        // immediately will not either.
        if last_switch.map(|t| t.elapsed() < MIN_GAP).unwrap_or(false) {
            return None;
        }
        return Some("failover");
    }
    scheduled.then_some("scheduled")
}

/// Measures every server and switches if there is a clear winner.
///
/// Returns whether the sweep actually ran.
fn run_sweep(app: &Arc<Mutex<App>>, reason: &'static str, last_switch: &mut Option<Instant>) -> bool {
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
            return true; // it ran; it just did not produce anything usable
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
    if best.id == active.id || !is_worth_switching(active.latency, best.latency) {
        return true;
    }

    let mut a = lock(app);
    if a.select(&best.id).is_err() {
        return true;
    }
    a.switcher.switches += 1;
    a.switcher.last_switch = crate::xray::now_secs();
    a.switcher.last_switch_to = best.name.clone();
    a.switcher.last_switch_reason = reason.to_string();
    let result = a.save_and_apply();
    drop(a);

    *last_switch = Some(Instant::now());
    match result {
        Ok(()) => eprintln!(
            "xrayop: switched to \"{}\" ({} ms, was {} ms) -- {reason}",
            best.name, best.latency, active.latency
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

    /// Failover is the point of the feature; it must react in minutes, not at
    /// the next scheduled sweep.
    #[test]
    fn failover_reacts_far_faster_than_the_schedule() {
        let probe_interval = Duration::from_secs(60);
        let time_to_failover = probe_interval * FAILURES_BEFORE_FAILOVER + TICK;
        assert!(time_to_failover <= Duration::from_secs(300));
    }
}
