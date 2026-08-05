# xrayop

A small Xray manager for OpenWrt routers, with a browser panel that behaves like
v2rayNG: paste a subscription, test latency, tap a server, done.

Written in Rust. The daemon is a **751 KB static binary** using **808 KB of RAM**
on the target router.

> **Status: working prototype.** It runs a SOCKS5 and an HTTP proxy that clients
> point at explicitly. It does **not** yet do transparent proxying, so it is not
> a Passwall2 replacement until that lands. See [Roadmap](#roadmap).

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
- **Latency testing** — concurrent TCP handshake probes across the whole list,
  plus one-click "connect to fastest".
- **DNS presets** — Cloudflare, Google, Quad9, AdGuard, and the Iranian
  resolvers (Shecan, Electro, Begzar, Radar), or a custom list.
- **Supervision** — Xray is started, restarted and stopped by the daemon. A core
  that dies on startup is reported as a failure with the reason, not silently
  shown as connected.

## What it does not do yet

- No transparent proxy. Clients must be pointed at the SOCKS or HTTP port; LAN
  traffic is not intercepted.
- VLESS only. VMess, Trojan, Shadowsocks and Hysteria links are counted as
  "unsupported" on import rather than parsed.
- **No authentication on the panel.** Anyone who can reach the port can drive
  it. Keep it on a trusted LAN.
- Latency is a TCP handshake, not end-to-end proxy delay. A reachable server can
  still fail to authenticate.

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

```bash
ROUTER=router ./scripts/deploy.sh
```

That installs the binary, the procd service and a default `/etc/config/xrayop`,
enables the service and starts it. Then open `http://<router>:8088`.

Manually:

```bash
cat dist/xrayopd | ssh root@router 'cat > /usr/bin/xrayopd && chmod +x /usr/bin/xrayopd'
```

OpenWrt's dropbear has no sftp-server, so `scp` fails — pipe through `ssh`
instead.

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
xrayopd --dump-nft     # print the ruleset
xrayopd --check-nft    # ask the kernel to validate it, applying nothing
```

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
