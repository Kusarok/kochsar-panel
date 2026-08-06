//! xrayopd -- an Xray manager with a browser panel, sized for an OpenWrt router.
//!
//! Layout:
//!
//! * [`model`]  -- persisted types
//! * [`parse`]  -- `vless://` and subscription decoding
//! * [`net`]    -- subscription fetching (delegated to curl)
//! * [`probe`]  -- concurrent TCP latency measurement
//! * [`dnscfg`] -- DNS presets
//! * [`xray`]   -- config generation and process supervision
//! * [`store`]  -- application state and its operations
//! * [`api`]    -- HTTP panel and JSON API
//!
//! Shutdown needs no signal handler: the default SIGTERM action terminates the
//! daemon, and the kernel then signals Xray via `PR_SET_PDEATHSIG`. See
//! [`xray::Supervisor`].

mod api;
mod dnscfg;
mod model;
mod net;
mod parse;
mod probe;
mod store;
mod tproxy;
mod xray;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use store::App;

const DEFAULT_LISTEN: &str = "0.0.0.0:8088";
const DEFAULT_STATE: &str = "/etc/xrayop/state.json";
/// Runtime files live on tmpfs so a config rewrite never touches flash.
const DEFAULT_RUNTIME: &str = "/var/etc/xrayop";
/// The router has four cores and the panel is a single user; more workers would
/// only add contention on the state mutex.
const WORKERS: usize = 4;

const USAGE: &str = "\
xrayopd -- Xray manager with a browser panel

USAGE:
    xrayopd [OPTIONS]

OPTIONS:
    --listen <ADDR>    Panel bind address        [default: 0.0.0.0:8088]
    --state <PATH>     Persisted state file      [default: /etc/xrayop/state.json]
    --runtime <DIR>    Generated config and log  [default: /var/etc/xrayop]
    --dump-nft         Print the transparent-proxy ruleset and exit
    --check-nft        Validate that ruleset against the kernel and exit
    -h, --help         Print this help
    -V, --version      Print version

Each option may also be set via XRAYOP_LISTEN, XRAYOP_STATE or XRAYOP_RUNTIME.
The command line wins over the environment.

The panel has no authentication yet. Bind it to a trusted LAN only.
";

struct Args {
    listen: String,
    state: PathBuf,
    runtime: PathBuf,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => return ExitCode::SUCCESS, // --help / --version
        Err(e) => {
            eprintln!("xrayopd: {e}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    let (mut app, warning) = store::App::load(args.state.clone(), &args.runtime);
    if let Some(w) = warning {
        eprintln!("xrayopd: {w}");
    }

    // First run: mint the panel token and tell the user where to find it. It is
    // printed to the log rather than shown in the panel, because anyone who can
    // load the panel is exactly who we are trying to authenticate.
    if app.state.panel_token.is_empty() {
        app.state.panel_token = model::generate_token();
        if app.state.panel_token.is_empty() {
            eprintln!("xrayopd: cannot read /dev/urandom; refusing to run without a token");
            return ExitCode::FAILURE;
        }
        if let Err(e) = app.save() {
            eprintln!("xrayopd: cannot persist the panel token: {e}");
            return ExitCode::FAILURE;
        }
        println!(
            "xrayopd: panel token generated. Open the panel and enter:\n    {}\n\
             (also readable with: sed -n 's/.*\"panel_token\": \"\\([^\"]*\\)\".*/\\1/p' {})",
            app.state.panel_token,
            args.state.display()
        );
    }

    // Restore the previous session. A failure here is reported but not fatal --
    // the panel is how the user would fix a bad node or a missing binary, so it
    // must come up either way.
    if !app.state.active.is_empty() {
        let state = app.state.clone();
        if let Err(e) = app.sup.apply(&state) {
            eprintln!("xrayopd: could not start xray: {e}");
        }
    }

    // Reconcile the kernel with what we believe. nftables rules outlive the
    // process, so both directions matter.
    if app.state.settings.transparent {
        // Rules do not survive a reboot; lay them down again. No watchdog this
        // time -- these were already confirmed by a human, and at boot there is
        // no browser to confirm them again.
        let ips = app
            .active_server_host()
            .map(|h| probe::resolve_all(&h))
            .unwrap_or_default();
        let plan = app.tproxy_plan(ips);
        match tproxy::apply(&plan) {
            Ok(()) => app.tproxy_applied = true,
            Err(e) => {
                // Leave the setting on so the panel shows enabled-but-not-applied
                // rather than silently pretending the tunnel is intercepting.
                eprintln!("xrayopd: could not restore transparent proxy: {e}");
            }
        }
    } else if tproxy::is_applied() {
        // Rules exist that we did not sanction. This is what a crash during the
        // confirmation window leaves behind: the setting was deliberately never
        // saved, but the kernel kept the ruleset, so every LAN packet is being
        // redirected to a port nothing is listening on. Without this branch the
        // LAN stays black-holed across restarts, and a restart makes it worse
        // rather than better -- the watchdog that was supposed to clean up died
        // with the previous process.
        eprintln!("xrayopd: found transparent-proxy rules from a previous run; removing them");
        tproxy::revert(&app.tproxy_plan(Vec::new()));
    }

    println!(
        "xrayopd {} -- panel on http://{}  (state: {}, runtime: {})",
        env!("CARGO_PKG_VERSION"),
        args.listen,
        args.state.display(),
        args.runtime.display()
    );

    let app = Arc::new(Mutex::new(app));
    spawn_log_janitor(Arc::clone(&app));

    if let Err(e) = api::serve(app, &args.listen, WORKERS) {
        eprintln!("xrayopd: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Returns `Ok(None)` when the program should exit successfully without
/// running, which is what `--help` and `--version` want.
fn parse_args() -> Result<Option<Args>, String> {
    let mut listen = std::env::var("XRAYOP_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.into());
    let mut state = std::env::var("XRAYOP_STATE").unwrap_or_else(|_| DEFAULT_STATE.into());
    let mut runtime = std::env::var("XRAYOP_RUNTIME").unwrap_or_else(|_| DEFAULT_RUNTIME.into());

    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("xrayopd {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--listen" => listen = next_value(&mut argv, "--listen")?,
            "--state" => state = next_value(&mut argv, "--state")?,
            "--runtime" => runtime = next_value(&mut argv, "--runtime")?,
            // Both operate on the *saved* settings and neither touches the
            // live firewall, so the ruleset can be inspected and validated on
            // a production router without risking connectivity.
            "--dump-nft" | "--check-nft" => {
                let check = arg == "--check-nft";
                return dump_ruleset(&PathBuf::from(&state), check).map(|()| None);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    Ok(Some(Args {
        listen,
        state: PathBuf::from(state),
        runtime: PathBuf::from(runtime),
    }))
}

/// How often the janitor wakes. Well under the smallest sensible rotation
/// interval, so the size cap is enforced promptly rather than at the next
/// rotation boundary -- a burst of logging can blow past the cap in seconds.
const JANITOR_TICK: Duration = Duration::from_secs(15);

/// Keeps Xray's log from filling tmpfs.
///
/// The log lives in RAM. Left alone at `loglevel: info`, a busy LAN fills it
/// faster than anyone would notice, and the router runs out of memory long
/// before anyone thinks to look at a log file. One thread, asleep almost all
/// the time, is cheap insurance.
fn spawn_log_janitor(app: Arc<Mutex<App>>) {
    thread::spawn(move || loop {
        thread::sleep(JANITOR_TICK);

        // Take the settings and drop the lock before touching the filesystem.
        let Ok(mut guard) = app.lock().or_else(|e| Ok::<_, ()>(e.into_inner())) else {
            return;
        };
        let s = &guard.state.settings;
        if !s.log_enabled {
            continue;
        }
        let max_bytes = s.log_max_kb.saturating_mul(1024);
        let max_age = Duration::from_secs(s.log_rotate_secs.max(10));
        guard.sup.tidy_log(max_bytes, max_age);
        drop(guard);
    });
}

/// Renders the transparent-proxy ruleset from saved settings, optionally
/// validating it against the running kernel.
///
/// `nft --check` parses and verifies every expression without committing
/// anything, so this is safe to run on a live router.
fn dump_ruleset(state_path: &std::path::Path, check: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(state_path).unwrap_or_default();
    let state: model::State = serde_json::from_str(&text).unwrap_or_default();
    let s = &state.settings;

    // Bypassing the active server is what stops the tunnel eating itself, so
    // resolve it here exactly as the daemon would.
    let server_ips = state
        .find(&state.active)
        .map(|n| probe::resolve_all(&n.server))
        .unwrap_or_default();

    let plan = tproxy::Plan {
        port: s.tproxy_port,
        lan_interfaces: s.lan_list(),
        server_ips,
        tunnel_ipv6: s.tunnel_ipv6,
    };

    print!("{}", tproxy::build_ruleset(&plan));
    if check {
        tproxy::check(&plan).map_err(|e| format!("ruleset rejected by kernel:\n{e}"))?;
        eprintln!("\n[ok] the kernel accepts this ruleset (nothing was applied)");
    }
    Ok(())
}

fn next_value(argv: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    argv.next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{flag} needs a value"))
}
