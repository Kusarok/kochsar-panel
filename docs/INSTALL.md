# Installing kochsar panel, step by step

This guide assumes you have never used SSH and have never installed anything on a router by hand. It is longer
than it needs to be on purpose. If you already know your way around a terminal, the short version in the
[README](../README.md#installation) is four commands.

Set aside about twenty minutes for the first time.

**Throughout this guide, `ROUTER_IP` means your router's address.** Step 1 tells you how to find it. Wherever you
see `ROUTER_IP`, type your own number instead.

---

## Before you start

You need three things:

1. **An OpenWrt router.** Version 22.03 or newer. If you are not sure, step 1 shows you how to check. This will
   not work on stock manufacturer firmware.
2. **`xray-core` installed on that router.** kochsar drives Xray; it does not include it. If it is missing, the
   installer will tell you and stop without changing anything. Installing it is one command, shown below.
3. **A computer on the same network as the router**, connected by cable or Wi-Fi.

You also need at least one working proxy server or subscription link — kochsar manages servers, it does not
provide them.

---

## Step 1 — Find your router's address, and check it runs OpenWrt

Your router's address is almost always `192.168.1.1`. Some are `192.168.0.1` or `10.0.0.1`.

**On Windows:** press `Win + R`, type `cmd`, press Enter, then type:

```
ipconfig
```

Look for **Default Gateway** under your active connection. That number is your router.

**On macOS or Linux:**

```
ip route | grep default
```

or on macOS:

```
netstat -nr | grep default
```

The address after `via` (or `default`) is your router.

Now open `http://ROUTER_IP` in a browser. If you see the OpenWrt / LuCI login page, you are in the right place.
Write the address down; you will type it several times.

> **If you see a manufacturer's page instead** (TP-Link, Asus, Netgear…), the router is not running OpenWrt and
> this software will not install. Installing OpenWrt is a separate project — start at
> [openwrt.org](https://openwrt.org/toh/start) and make sure your model is supported.

---

## Step 2 — Get an SSH connection to the router

SSH is a text window that runs commands *on the router* instead of on your computer. Everything after this step
happens there.

### Windows 10 / 11

SSH is built in. Open **Command Prompt** or **PowerShell** and type:

```
ssh root@ROUTER_IP
```

### macOS

Open **Terminal** (Applications → Utilities → Terminal) and type the same thing:

```
ssh root@ROUTER_IP
```

### Linux

Open your terminal and type the same thing.

### What you will see

The first time, it asks something like:

```
The authenticity of host '192.168.1.1' can't be established.
ED25519 key fingerprint is SHA256:...
Are you sure you want to continue connecting (yes/no)?
```

Type `yes` and press Enter. This is normal — it is your own router, being introduced for the first time.

Then it asks for a password. **This is your router's admin password**, the one you use to log into LuCI in a
browser. Nothing appears as you type — no dots, no stars. That is normal too. Type it and press Enter.

When you are in, you will see a banner and a prompt ending in `#`. You are now typing commands on the router.

### If step 2 fails

| What you see | What it means | What to do |
|---|---|---|
| `Connection refused` | The SSH server is not running or is not listening on your network. | Log into LuCI in a browser → System → Administration → SSH Access, and make sure an instance is listening on `lan`. |
| `Permission denied` | Wrong password, or root login over password is disabled. | Use your LuCI admin password. If you have never set one, set it in LuCI → System → Administration. |
| `Connection timed out` | You are not on the same network, or the address is wrong. | Redo step 1. Try a cable connection. |
| `ssh: command not found` (Windows) | Very old Windows. | Install [PuTTY](https://www.putty.org/), enter the router IP, port 22, click Open, log in as `root`. |

---

## Step 3 — Check the prerequisites (optional but pleasant)

Still in the SSH window, check whether Xray is already installed:

```sh
which xray
```

If it prints a path such as `/usr/bin/xray`, you are set. If it prints nothing, install it:

```sh
apk update && apk add xray-core
```

If `apk` is not found, your OpenWrt release uses the older package manager, `opkg`:

```sh
opkg update && opkg install xray-core
```

While you are here, install the two kernel modules that whole-LAN mode needs:

```sh
apk add kmod-nft-tproxy kmod-nft-socket
```

(Again, use `opkg install` if your release does not have `apk`. If the packages are missing from your feed, do
not worry — the installer will tell you, and everything except global mode still works.)

You can leave this SSH window open; you will come back to it in step 5.

---

## Step 4 — Copy the release file to the router

Go to the project's **Releases** page and download the file matching your router's CPU. If you do not know what
CPU your router has, run this in the SSH window:

```sh
uname -m
```

| It prints | Download the file containing |
|---|---|
| `armv7l` | `armv7-unknown-linux-musleabihf` |
| `aarch64` | `aarch64-unknown-linux-musl` |
| `mips` or `mipsel` | `mipsel-unknown-linux-musl` |
| `x86_64` | `x86_64-unknown-linux-musl` |

Now, **on your own computer** — a new Command Prompt / Terminal window, not the SSH one — go to your Downloads
folder and copy the file over:

```
cd Downloads
scp -O xrayop-0.2.1-armv7-unknown-linux-musleabihf.tar.gz root@ROUTER_IP:/tmp/
```

Adjust the filename to whatever you actually downloaded.

> ### Why `-O`?
>
> This is the single most common thing to trip over, and it is not your fault. OpenWrt's SSH server (dropbear)
> does not include the `sftp-server` component, and modern versions of `scp` use SFTP behind the scenes. Without
> `-O`, `scp` fails with `subsystem request failed on channel 0`, which explains nothing.
>
> `-O` tells `scp` to use the old, simpler protocol. It works.

It asks for the router password again, then shows a progress bar. The file is about half a megabyte.

### If step 4 fails

**`subsystem request failed on channel 0`** — you left out `-O`. Add it.

**`scp: command not found`, or `-O` is rejected as an unknown option** — your `scp` is too old or too new. Use
this instead, which works everywhere:

```
cat xrayop-0.2.1-armv7-unknown-linux-musleabihf.tar.gz | ssh root@ROUTER_IP "cat > /tmp/xrayop.tar.gz"
```

(If you use that form, the file on the router is called `/tmp/xrayop.tar.gz` — remember that in step 5.)

**`No space left on device`** — `/tmp` on the router is small. Check with `df -h /tmp` in the SSH window and
clear something out, or copy to `/root` instead and adjust the paths in step 5.

**Windows users:** if `cd Downloads` does not find the file, run `dir` to see what is in the folder you are in,
or drag the file into the terminal window to paste its full path.

---

## Step 5 — Run the installer

Back in the SSH window (or open a new one with `ssh root@ROUTER_IP`):

```sh
cd /tmp
tar xzf xrayop-0.2.1-*.tar.gz
cd xrayop-0.2.1-*/
sh install.sh
```

If you used the `cat | ssh` method in step 4, the first two lines are `cd /tmp` and `tar xzf xrayop.tar.gz`
instead.

The installer prints a checklist before it changes anything:

```
xrayop installer
================

Checking this router:
  ✓ OpenWrt 25.12.2 on ipq40xx/generic
  ✓ binary matches this CPU (armv7l)
  ✓ xray found at /usr/bin/xray (Xray 26.7.28)
  ✓ TPROXY kernel modules present
  ✓ dnsmasq is running
  ✓ curl present
  ✓ flow offloading is off

Installing:
  ✓ /usr/bin/xrayopd
  ✓ /etc/init.d/xrayop
  ✓ /etc/hotplug.d/iface/99-xrayop
  ✓ /etc/config/xrayop
  ✓ added to /etc/sysupgrade.conf so backups include it

Installed and running.

  Panel:  http://192.168.1.1:8088
  Token:  3f7a1c9e5b2d4086a1c7e93b5f0d2a48

Running in proxy mode: a SOCKS5 proxy on port 1080 and an HTTP
proxy on 1081, for clients you point at them. Add a subscription,
pick a server, then switch to global mode for the whole LAN.
```

**Copy that token somewhere.** You need it in the next step. (You can always read it again later — see
troubleshooting at the end.)

### If step 5 fails

The installer refuses rather than half-installing, and it lists every problem at once. Common ones:

**`✗ xray-core is not installed`** — go back to step 3.

**`✗ binary is not built for armv7l -- get the right release`** — you downloaded the wrong file. Check
`uname -m` again and redownload.

**`✗ curl is missing`** — `apk add curl` (or `opkg install curl`), then rerun the installer.

**`! missing: nft_tproxy nft_socket`** — a warning, not an error. Proxy mode will work; whole-LAN mode will not
until you install `kmod-nft-tproxy` and `kmod-nft-socket`.

**`! flow offloading is enabled`** — also a warning. Turn it off in LuCI → Network → Firewall before using
global mode. It makes packets skip the hooks that interception relies on.

**`! passwall2 is currently intercepting traffic`** — you have another proxy manager running. The two cannot
intercept at the same time. Stop it with `/etc/init.d/passwall2 stop` before switching kochsar to global mode.

**`Installed, but the service did not start`** — the installer prints the last few log lines. Get more with
`logread | grep xrayop | tail -30`.

**`-ash: install.sh: not found` or strange syntax errors** — you are in the wrong directory. `ls` should show
`install.sh`, `xrayopd` and an `etc` folder.

---

## Step 6 — Open the panel

On any device on the same network, open:

```
http://ROUTER_IP:8088
```

Use the **IP address**, not a name like `router.lan`. The panel deliberately refuses hostnames — it is a
protection against a browser attack called DNS rebinding, and there is nothing to configure around it.

You will see a small unlock box. Paste the token from step 5 and press **Unlock**. Your browser remembers it, so
this is a one-time thing per device.

### If step 6 fails

**The page does not load at all.** Check the service is running, in the SSH window:

```sh
ps | grep xrayopd
logread | grep xrayop | tail -20
```

If nothing is running, start it with `/etc/init.d/xrayop start` and look at the log again.

**"Reach the panel by IP address, not by hostname".** You used a name. Use the number.

**"Wrong token".** Read the real one on the router:

```sh
logread | grep 'panel token' -A2
```

or straight from the settings file:

```sh
sed -n 's/.*"panel_token": "\([^"]*\)".*/\1/p' /etc/xrayop/state.json
```

---

## Step 7 — Add servers and connect

Now you are in the panel; nothing else needs SSH.

1. Tap **Settings** (bottom right) → **Subscriptions**. Paste your subscription URL, give it a name if you like,
   and press **Add and fetch**. The servers appear.
   *No subscription?* Tap **Servers** → **Add** and paste `vless://` links instead — one per line, or a base64
   blob. Both work.
2. Tap **Servers** → **Test all**. Each server is tested by making a real request through it, so the milliseconds
   shown mean something. It takes a few seconds.
3. Tap **Fastest**, or tap any server in the list to select it.
4. Go back to **Home**. You should see the server name and a status of *Connected*.

At this point you are in **proxy mode**: the tunnel exists, but only devices you explicitly point at it use it.
To try it, set a browser or a phone to use the router as a SOCKS5 proxy at `ROUTER_IP` port `1080` (or an HTTP
proxy on port `1081`) and load a page.

---

## Step 8 — Turn on the whole LAN

Only do this once step 7 works, and ideally while you can physically reach the router.

On the **Home** tab, tap **Global**. A warning appears explaining that this changes the router's firewall; accept
it. Then:

1. The rules are validated against your kernel and loaded, and DNS is pointed at the tunnel.
2. **A 90-second countdown starts.**
3. **Right now, before doing anything else, open a website.** Another browser tab, your phone, anything on the
   network. Check it loads.
4. If it works, press **"It works — keep"**.

**If it does not work, do nothing.** After 90 seconds the router undoes everything by itself: the firewall rules
come out, DNS goes back to normal, and Xray restarts without interception. You do not have to be able to reach
the panel for that to happen.

And if the router falls off the network completely: **unplug it and plug it back in.** The change is
deliberately not written to disk until you confirm, so a power cycle brings the router back exactly as it was.
Nothing to repair, nothing to reset.

Once you confirm, global mode survives reboots. Every device on the network now goes through the tunnel with no
configuration of its own.

---

## Common questions

**Do I have to configure my phone, TV, console?**
In global mode, no. That is the entire point of it. In proxy mode, yes — each device you want tunnelled points
at the router's SOCKS5 or HTTP port.

**Does this survive a reboot?**
Yes, once you have confirmed global mode. The service starts at boot and re-applies everything.

**Does this survive a firmware upgrade?**
The installer adds its files to `/etc/sysupgrade.conf`, so a sysupgrade that keeps settings keeps kochsar,
including your server list.

**Where are my servers stored?**
`/etc/xrayop/state.json`, readable only by root. It contains credentials, so treat it like a password file. The
panel keeps one generation of backup — Settings → About → *Restore server list* — in case you delete something
by accident.

**How much RAM does it use?**
The whole stack — daemon plus Xray — measured 38.6 MB on the router it was developed on, against 51.2 MB for
Passwall2 carrying the same traffic.

**Can I change the panel port?**
Yes. Edit `/etc/config/xrayop`, change the `listen` line, then `/etc/init.d/xrayop restart`.

**How do I remove it?**

```sh
cd /tmp/xrayop-0.2.1-*/
sh uninstall.sh            # keeps your server list
sh uninstall.sh --purge    # removes everything
```

It takes the firewall rules and the DNS hand-off down before stopping the service, then prints a DNS lookup and
an internet check so you can see the router is back to normal.

---

## Getting help

If something is wrong, this is the information worth collecting first, from an SSH window:

```sh
logread | grep xrayop | tail -40      # what the daemon has been saying
nft list table inet xrayop            # the firewall rules, if any
ps | grep xrayopd                     # is the daemon running
xrayopd --check-config                # would xray accept the config it would run
```

`xrayopd --check-config`, `xrayopd --dump-nft` and `xrayopd --check-nft` are all read-only: they show you what
*would* happen without touching the running router.

When reporting a problem, please include your OpenWrt version (`cat /etc/openwrt_release`), your architecture
(`uname -m`), and the relevant log lines — with any subscription URLs, server addresses and UUIDs removed.
