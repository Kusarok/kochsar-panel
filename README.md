# xrayop

A small Xray manager for OpenWrt routers, with a browser panel that behaves like
v2rayNG: paste a subscription, test latency, tap a server, done.

Written in Rust. The daemon is a **~870 KB static binary** using **under 1 MB of
RAM** on the target router; the whole stack measured 38.6 MB against Passwall2's
51.2 MB carrying the same traffic.

> **Status: working, not yet battle-tested.** The SOCKS/HTTP path is in daily
> use. Transparent proxying and tunnelled DNS are written, kernel-validated and
> wired to the panel, but have **never been applied to a live router** — the
> first enable should happen with physical access to the device.

---

## Why this exists

Passwall2 is Lua + shell on top of LuCI's legacy compatibility layer, and it
breaks on OpenWrt upgrades. The modern OpenWrt stack is client-side JavaScript
plus ucode, but ucode is a poor fit for the parts that matter here — fetching
subscriptions over HTTPS, decoding share links, probing dozens of servers
concurrently.

So the panel is its own daemon on its own port, independent of LuCI's release
cycle, and the UI is whatever we want it to be rather than whatever CBI renders.

## What works today

- **Subscriptions** — add a URL, nodes are fetched and parsed. Refreshing drops
  servers that vanished upstream, keeps measured latency for the ones that
  stayed, and never touches manually added nodes.
- **Manual import** — paste one link or a hundred, plain or base64.
- **VLESS** over TCP, WebSocket, gRPC, XHTTP and HTTPUpgrade, with REALITY, TLS
  or no encryption, including XTLS flows and uTLS fingerprints.
- **Latency testing** — a real HTTPS request through each server, measured
  concurrently, plus one-click "connect to fastest".
- **DNS presets** — Cloudflare, Google, Quad9, AdGuard, and the Iranian
  resolvers (Shecan, Electro, Begzar, Radar), or a custom list.
- **Supervision** — Xray is started, restarted and stopped by the daemon. A core
  that dies on startup is reported as a failure with the reason, not silently
  shown as connected.

- **Transparent proxy** — nftables TPROXY for the LAN, with tunnelled DNS, an
  apply-then-confirm handshake and an automatic rollback. Written and validated;
  see the section below before enabling it.

## What it does not do yet

- The router's **own** outbound traffic is not intercepted — only LAN clients.
- IPv6 is left direct.
- VLESS only. VMess, Trojan, Shadowsocks and Hysteria links are counted as
  "unsupported" on import rather than parsed.
- Rules are not re-applied automatically after `fw4 reload`; the panel detects
  the drift and says so, but reinstating them is manual.

---

## Measuring latency

Servers are ranked by making a real HTTPS request *through* each one, to a
destination you choose.

The obvious alternative -- timing a TCP handshake to the server's address --
was implemented first and removed, because on a censored network it measures
the censor. The hostname resolves to a nearby interception box that completes
the handshake instantly, so every server reports about 0 ms and the list looks
perfect while nothing works. It also rates the "update your subscription daily"
notice that providers put in their node list as the fastest server available.

One throwaway Xray instance is started with a SOCKS inbound per node and a
routing rule pinning each inbound to its own outbound, so all nodes are
measured concurrently through a single process rather than one process each.
Unrouted traffic is blackholed: letting it out directly would make a dead
server report the latency of the router's own connection.

The destination is a setting, because it is a real choice -- a server can reach
Google and still fail on Instagram. Presets cover Google, YouTube, GitHub,
Telegram, Instagram, Cloudflare and OpenAI, each pointing at an endpoint that
returns a tiny response so the number reflects latency rather than download
size. A custom URL is accepted if it is http(s) and does not point at the
router.

---

## Access control

The panel is served on the LAN by a daemon running as root that can rewrite the
router's firewall, so it is gated three independent ways. Each closes a
different attack, and none of them is a substitute for the others.

**A token.** Generated from `/dev/urandom` on first run, printed to the system
log, stored in `state.json` (mode `0600`). Every `/api/*` route requires it in
`X-Xrayop-Token` or as a bearer token; comparison is constant-time. Read it with:

```bash
logread | grep -A2 'panel token'
```

**Host must be an IP literal or `localhost`.** DNS rebinding works by making the
victim's browser reach the panel under a *hostname* the attacker controls.
Refusing hostnames outright removes the technique, with nothing to configure.

**Content-Type essence, not substring.** A mutating request must arrive as
`application/json` — compared after stripping parameters. An earlier version
checked whether the header *contained* `application/json`, which
`text/plain;charset=application/json` satisfies while browsers still treat it as
a CORS-safelisted simple request and send it cross-origin with no preflight.
That is the same bug Fastify shipped as GHSA-3fjj-p79j-c9hh. `Origin`, when
present, must also match `Host`.

Beyond the gate: subscription URLs are never returned by the API (they usually
embed a per-user token that would yield the full node list, credentials
included); `xray_bin` is confined to system directories because it is executed
as root; LAN interface names are charset-checked before being interpolated into
an `nft -f` script; and the subscription fetcher refuses loopback and
link-local addresses so it cannot be used to reach the router's own admin pages.

## Resource containment

An OpenWrt router has no swap and no room for a slow leak. These defaults come
from documented failures in Xray's issue tracker and from what the mature
OpenWrt proxy apps actually ship, not from guesswork.

| Setting | Default | Why |
|---|---|---|
| `connIdle` | 120 s | TPROXY UDP carries no close signal, so Xray holds one socket per 4-tuple until this expires. At the stock 300 s a torrent client creates sockets faster than they are reclaimed — the most-reported router failure in Xray's tracker, maintainer-diagnosed. |
| `nofile` | 65536 | The same failure seen from the other side. Passwall2 sets no limit at all, so Xray inherits the kernel's 1024 and users hit `accept4: too many open files`. |
| `GOMEMLIMIT` | 96 MiB | Soft ceiling: Go collects harder as it approaches and never fails an allocation. 70 MiB is the lowest value reported working for a client config on a 512 MB router. |
| `RLIMIT_DATA` | off | Hard backstop for a genuine runaway, so Xray dies instead of the OOM killer picking dnsmasq. Off by default because set too low it kills a healthy core. |
| access log | `none` | Separate from `loglevel`: without this Xray writes a line per connection at *every* level. On a busy LAN it is the largest log producer by far. |
| `routeOnly` | true | Sniffed domains are used for routing but the destination is left alone. Overriding it breaks Tor, Apple push and several IoT devices. |
| log file | none | Off by default; the log lives on tmpfs, which is RAM. When on, a janitor truncates it on a size cap and an age cap. |

Two pieces of widely-repeated advice are deliberately **not** followed:
`V2RAY_CONF_GEOLOADER=memconservative` does nothing on Xray (it is a v2fly
variable), and `bufferSize` is left unset because 32-bit ARM already defaults to
no internal buffer and the value `0` now means *unlimited* rather than
*disabled*.

Before restarting, a candidate config is written to a staging file and validated
with `xray run -test`. A rejected config leaves the running tunnel untouched.
The staging file keeps a `.json` extension — Xray infers the config format from
the file name, and a name like `config.json.next` fails with "Failed to get
format" no matter what is inside it.

---

## Architecture

```
browser  ──HTTP──▶  xrayopd  ──spawns──▶  xray-core
                       │                      │
                       │                  SOCKS :1080
                    state.json            HTTP  :1081
```

| Module | Responsibility |
|---|---|
| `model.rs`  | Persisted types; stable node identity |
| `parse.rs`  | `vless://` and subscription decoding |
| `net.rs`    | Subscription fetching, delegated to `curl` |
| `probe.rs`  | Concurrent TCP latency measurement |
| `dnscfg.rs` | DNS presets and resolver validation |
| `xray.rs`   | Config generation and process supervision |
| `store.rs`  | Application state and its operations |
| `api.rs`    | HTTP panel and JSON API |

Four dependencies: `tiny_http`, `serde_json`, `base64`, `percent-encoding`
(plus `libc` for `PR_SET_PDEATHSIG`). All pure Rust, which is what lets the
project cross-compile with nothing but a rustup target — no C toolchain, no
OpenWrt SDK. HTTPS is delegated to the `curl` already on the router, which keeps
a TLS stack out of the binary entirely.

### Design notes

- **Node identity excludes the remark.** Providers rename servers constantly; a
  name-sensitive id would drop your selection on every refresh.
- **Slow work never holds the state lock.** Fetching and probing snapshot what
  they need, release the mutex, then merge results back.
- **Settings validate on a copy.** An earlier version mutated live state and
  then bailed out on error, leaving rejected values in memory for the next write
  to persist — that shipped a config with two inbounds on one port.
- **`PR_SET_PDEATHSIG` on the child.** If the daemon is SIGKILLed, the kernel
  still takes Xray down, so the ports are never left held by an orphan.
- **A start is not a success.** After spawning, the supervisor watches for
  500 ms; Xray validates config and binds inbounds in that window, so failures
  surface as errors instead of a false "connected".

---

## Build

Requires a Linux host with rustup. No C cross-toolchain needed.

```bash
rustup target add armv7-unknown-linux-musleabihf
cargo build --release --target armv7-unknown-linux-musleabihf
```

From a Windows workstation, `scripts/build.sh` runs the build on a remote Linux
box over SSH:

```bash
BUILDER=rack ./scripts/build.sh --fetch
```

Adjust `TARGET` for other routers — `aarch64-unknown-linux-musl` for ARM64,
`mipsel-unknown-linux-musl` for older MIPS devices.

## Install

Build a release tarball, copy it over, run the installer:

```bash
./scripts/release.sh
```

```bash
scp -O dist/xrayop-*.tar.gz root@ROUTER:/tmp/
ssh root@ROUTER 'cd /tmp && tar xzf xrayop-*.tar.gz && cd xrayop-*/ && sh install.sh'
```

`scp` needs `-O` because OpenWrt's dropbear ships without sftp-server. Piping
through `ssh` works too: `cat file | ssh root@ROUTER 'cat > /tmp/file'`.

The installer checks the router before touching anything and reports every
problem at once rather than failing partway through with the service already
enabled: OpenWrt and CPU match, xray-core present, `nft_tproxy` and
`nft_socket` loadable, dnsmasq running, curl present, flow offloading off (it
short-circuits the hooks global mode uses), and whether another proxy package
is currently intercepting.

It also adds itself to `/etc/sysupgrade.conf`, since the default backup covers
only `/etc/config` and would leave the server list and the service behind.

When it finishes it prints the panel URL and the token. First run comes up in
proxy mode, which changes nothing about how the router routes.

To remove it: `sh uninstall.sh`, or `--purge` to drop the server list too. It
takes the firewall rules and the resolver hand-off down *before* stopping the
service, in that order — the reverse would leave the LAN redirected at a port
with nothing behind it.

### Developing

`./scripts/build.sh --fetch` builds on a remote Linux host and downloads the
binary; `./scripts/deploy.sh` pushes it to a router without rebuilding the
whole package.

### Configuration

`/etc/config/xrayop`:

```
config xrayop 'main'
	option listen '0.0.0.0:8088'
	option enabled '1'
```

Runtime layout:

| Path | Purpose |
|---|---|
| `/etc/xrayop/state.json` | Nodes, subscriptions, settings (persistent) |
| `/var/etc/xrayop/config.json` | Generated Xray config (tmpfs) |
| `/var/etc/xrayop/xray.log` | Xray output, truncated on each start |

Runtime files live on tmpfs so config rewrites never touch flash.

---

## API

All mutating endpoints are `POST` and require `Content-Type: application/json`.
That requirement is deliberate: it forces a CORS preflight, and since no CORS
headers are sent, a hostile web page cannot drive the panel through a form post.

| Endpoint | Body | Purpose |
|---|---|---|
| `GET /api/state` | — | Everything the panel renders |
| `GET /api/log` | — | Tail of the Xray log |
| `POST /api/subs/add` | `{url, name}` | Add a subscription and fetch it |
| `POST /api/subs/refresh` | `{id}` or `{}` | Refresh one, or all |
| `POST /api/subs/remove` | `{id}` | Remove it and its nodes |
| `POST /api/nodes/add` | `{text}` | Import pasted links |
| `POST /api/nodes/remove` | `{id}` | Remove one node |
| `POST /api/select` | `{id}` or `{id:"fastest"}` | Select and connect |
| `POST /api/test` | `{}` | Probe every node |
| `POST /api/dns` | `{preset}` or `{preset:"custom", custom}` | Set resolvers |
| `POST /api/settings` | partial patch | Ports, bind address, binary, log level |
| `POST /api/service` | `{action:"start"\|"stop"\|"restart"}` | Control Xray |
| `POST /api/tproxy/enable` | `{}` | Apply transparent proxy on probation |
| `POST /api/tproxy/confirm` | `{}` | Keep it and persist |
| `POST /api/tproxy/disable` | `{}` | Revert it |

Node listings never include UUIDs or REALITY keys.

## Tests

```bash
cargo test
```

55 tests covering link parsing, subscription merge semantics, config generation,
probe fan-out, settings validation and supervisor lifecycle.

---

## Transparent proxy

LAN traffic is intercepted with nftables TPROXY, so clients need no proxy
settings. Off by default. **Written and kernel-validated, but never yet applied
to a live router** — the first enable should happen with physical access to the
device.

Inspect and validate without touching the firewall:

```bash
xrayopd --dump-nft        # print the ruleset
xrayopd --check-nft       # ask the kernel to validate it, applying nothing
xrayopd --check-config    # ask xray to validate the config it would run
```

### DNS is the part that makes it private

Without DNS handling, transparent proxying delivers a working tunnel to the
wrong address. The client resolves a name *before* the proxy sees anything, so
a poisoned answer sends it to an address the tunnel then faithfully connects
to. By then the name is gone and the proxy has only an IP.

The panel's DNS preset alone does not fix this: it configures Xray's *internal*
resolver, which nothing on the LAN can query.

```
LAN client :53
   │  nat prerouting, dstnat-1 — catches clients with a hardcoded resolver
   ▼
dnsmasq :53                      keeps .lan names, DHCP hostnames, cache
   │  no-resolv + server=127.0.0.1#5353   (drop-in in dnsmasq's conf-dir)
   ▼
xray dns-in :5353 (loopback)
   │  routing: inboundTag dns-in → dns-out
   ▼
dns outbound  →  the panel's chosen resolver, through the tunnel
```

Port 53 is explicitly **excluded** from the tproxy chain. The tproxy hook runs
at `mangle - 1` (-151) and the redirect at `dstnat - 1` (-101), so without that
exclusion tproxy would swallow every query before the redirect ever saw one.
Passwall2 carries the identical `udp dport 53 return` for this reason.

Passwall2 runs a *second* dnsmasq on a high port for this, cloned from the
system config, because it supports per-client DNS policy and needs an instance
it owns. We have one policy for the whole LAN, so a drop-in file plus a restart
does the same job for ~2.6 MB less RAM. The drop-in lives on tmpfs, so a reboot
removes it even if we never get the chance to; the daemon puts it back at
startup when transparent mode is enabled.

### Enabling is a three-step handshake

Because a wrong ruleset can black-hole the router — including the SSH session
you would need to fix it — enabling runs on probation:

1. `POST /api/tproxy/enable` validates against the kernel, restarts Xray with
   the TPROXY inbound, loads the ruleset, and arms a 90-second rollback. The
   setting is deliberately **not** saved yet: if the router drops off the
   network here, a power cycle brings it back clean.
2. The panel shows a countdown. The user checks that the internet still works.
3. `POST /api/tproxy/confirm` disarms the rollback and persists the setting.

Miss the deadline and the watchdog reverts the ruleset and restarts Xray
without it. `POST /api/tproxy/disable` does the same on demand.

Order is load-bearing in both directions: Xray must be listening on the TPROXY
port before nftables redirects to it, and the redirect must stop before Xray is
reconfigured. Otherwise the gap between the two black-holes traffic.

### Scope and limits

- The router's **own** outbound traffic is not intercepted — only LAN clients.
  That needs an `output` chain plus a `nat` REDIRECT path with its own
  loop-avoidance.
- IPv6 is left direct by default.
- Rules do not survive `fw4 reload`; the panel detects this (`enabled` true,
  `applied` false) and says so, but re-applying is still manual.
- Rules are re-laid at daemon start, since nftables does not survive a reboot.

The rule structure follows Passwall2's `nftables.sh` rather than being derived
from scratch. Reading that script corrected four things that were wrong here and
would only have shown up as intermittent breakage on a live router:

| | Wrong | Correct |
|---|---|---|
| Base chain priority | `mangle` | `mangle - 1`, ahead of fw4's own chains |
| Reply packets | relied on `socket transparent` alone | explicit `ct direction reply return` |
| Socket match | `{ tcp, udp }` | TCP only — it does not match UDP reliably |
| tproxy target | `tproxy ip to 127.0.0.1:PORT` | `tproxy ip to :PORT`, preserving the original destination |

Nothing is copied verbatim — this generates its own ruleset — but the technique
is theirs.

Still missing before it can be enabled: panel wiring for the
apply/confirm/revert cycle, a hotplug trigger to reapply after `fw4 reload`, and
interception of the router's own outbound traffic (which needs an `output` chain
and a `nat` REDIRECT path).

## Roadmap

1. **Finish the transparent proxy** — panel wiring, fw4 reload trigger, and the
   router's own traffic.
2. **Panel authentication** — required before this is safe on an untrusted LAN.
3. **More protocols** — VMess, Trojan and Shadowsocks parsing.
4. **Real-delay probing** — measure through the proxy, not just the handshake.
5. An `.apk` package so it installs and upgrades like any other OpenWrt package.

## License

MIT
