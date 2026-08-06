# Suggested GitHub repository metadata

Reference for whoever sets up the repository page. Nothing here affects the build.

## Repository description

For the **About** box (GitHub allows 350 characters; this is 289):

```
Lightweight transparent proxy manager for OpenWrt routers. One small Rust daemon drives Xray-core with nftables TPROXY and tunnelled DNS, plus a fast bilingual browser panel for subscriptions, latency testing, server switching and DNS presets. A smaller, sturdier alternative to Passwall2.
```

Website field: leave empty, or point it at the Releases page.

## Topics

GitHub allows up to 20 topics; they must be lowercase, and words are joined with hyphens. These are ordered by
how likely someone is to actually search for them.

| Topic | Why |
|---|---|
| `openwrt` | The single most important one. Anyone browsing router software starts here. |
| `xray` | The core this drives. |
| `xray-core` | The exact project name, searched as often as the short form. |
| `transparent-proxy` | What it does, in the words people use for it. |
| `tproxy` | The kernel mechanism; searched by people who already know what they want. |
| `nftables` | How interception is implemented, and a real differentiator from iptables-era tools. |
| `proxy` | Broad, but it is the category. |
| `router` | Broad, and pairs well with `openwrt` in search. |
| `rust` | Language. Draws people looking for lighter alternatives to shell/Lua router apps. |
| `vless` | The protocol supported today. High-traffic search term. |
| `reality` | REALITY is what most current VLESS configs use. |
| `v2ray` | The wider ecosystem name; many users search this rather than "xray". |
| `v2rayng` | The client whose interaction model the panel copies; a very common search. |
| `passwall` | People explicitly look for Passwall alternatives. |
| `dnsmasq` | The DNS integration is a large part of what this project actually solves. |
| `socks5` | Proxy mode exposes one; a common entry point for search. |
| `anti-censorship` | Honest description of the use case. |
| `web-panel` | The panel is the reason to pick this over a config file. |
| `firewall` | Adjacent category on OpenWrt. |
| `openwrt-package` | Catches people browsing installable OpenWrt software. |

### If you would rather use fewer

The ten that carry the most weight:

`openwrt`, `xray`, `transparent-proxy`, `tproxy`, `nftables`, `rust`, `vless`, `v2ray`, `passwall`, `router`

## Notes

- Do not add a CI topic or badge until there is a workflow — there is none yet.
- If VMess, Trojan or Shadowsocks parsing is added later, `vmess`, `trojan` and `shadowsocks` are worth swapping
  in; drop `firewall` and `openwrt-package` first, they pull the least traffic.
