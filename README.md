<div align="center">

<img src="assets/logo/banner.png" alt="Tailscale Subnet Router for ESP32-S3" width="100%">

# ESP32 Tailscale Gateway

### Subnet router · Exit node · LAN → Tailnet port forwarder · IoT WiFi gateway · MQTT/Home Assistant · Wake-on-LAN

**Turn a single ESP32-S3 into a pocket-sized, privacy-first gateway between your
LAN, isolated WiFi devices and an entire Tailscale or Headscale network — no
Raspberry Pi, public port or client software on the connected devices.**

Based on the original
[Csontikka/esp32-tailscale-subnet-router](https://github.com/Csontikka/esp32-tailscale-subnet-router)
and its [microlink](https://github.com/Csontikka/microlink) Tailscale stack.
This Mattboxx edition expands the project with automation, selective service
forwarding, privacy hardening and a ready-to-flash release.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: ESP32-S3](https://img.shields.io/badge/platform-ESP32--S3-7c3aed.svg)](#hardware)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-5.3.1-e7352c.svg)](https://docs.espressif.com/projects/esp-idf/)
[![CodeQL](https://github.com/Mattboxx/esp32-tailscale-gateway/actions/workflows/codeql.yml/badge.svg)](https://github.com/Mattboxx/esp32-tailscale-gateway/actions/workflows/codeql.yml)
[![Latest release](https://img.shields.io/github/v/release/Mattboxx/esp32-tailscale-gateway?label=ready-to-flash)](../../releases/latest)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ea4aaa.svg?style=plastic&logo=githubsponsors)](https://github.com/sponsors/Csontikka)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-donate-yellow.svg?style=plastic)](https://buymeacoffee.com/csontikka)

</div>

---

## One board, three network gateways

| Traffic path | What it unlocks |
|---|---|
| **Tailnet → LAN/AP subnet** | Reach sensors, switches and legacy devices remotely through the ESP32 subnet router. |
| **AP-side device → Tailnet/Internet** | Give devices with no VPN client their own simple WiFi gateway, optionally through a Tailscale exit node. |
| **Uplink LAN → Tailnet service** | Let an ordinary LAN device reach a selected TCP/UDP service on a Tailnet peer through the ESP32 — no Tailscale client and no ESP access-point connection required. |

Example: forward `ESP-LAN-IP:2222` to `tailnet-server:22`, then SSH from any
permitted local client. Each rule has its own source CIDR, protocol, ports,
enable switch, counters and live status. This is completely independent from
the existing AP-side port forwarding.

**[Download the ready-to-flash release](../../releases/latest)** ·
**[See every change from upstream](CUSTOM_BRANCH.md)** ·
**[Read the security model](SECURITY.md)**

## Why the Mattboxx edition is different

Version `0.1.19-Mattboxx-1.4` is based on upstream `v0.1.19`. This firmware line
is developed, flashed and end-to-end tested on a real ESP32-S3 N16R8; every
release is also compiled and statically checked before publication.

| Area | Added or improved in this edition |
|---|---|
| **LAN → Tailnet forwarding** | Multiple TCP/UDP rules to a Tailscale IPv4 or MagicDNS destination, mandatory allowed-source subnet, live resolution/install state and conflict protection. Works even with the ESP client WiFi/AP disabled. |
| **WiFi gateway policy** | Keep the client AP always available, or automatically place it in standby while the uplink works and restore it after an outage. The dashboard makes disabled state unmistakable. |
| **Wake-on-LAN** | Save up to 12 named devices and wake them from the web UI, MQTT, Home Assistant or replay-protected ntfy commands. |
| **MQTT + Home Assistant** | Retained availability and device state, Last Will, broker watchdog, inbound commands and automatic discovery for AP, routes, SNAT, LAN bypass, Tailscale, 4via6, reconnect, restart, WOL and every LAN → Tailnet rule. |
| **ntfy remote operations** | Optional outage alerts, bounded diagnostic context, `info` replies and WOL commands with durable polling and replay protection. Private details stay hidden unless explicitly enabled. |
| **Tailscale 4via6** | Optional bidirectional TCP/UDP/ICMP translation for overlapping IPv4 LANs, with calculated advertised prefix, flow counters and Home Assistant controls. |
| **Exit-node server** | Advertise the ESP32 itself as a Tailscale exit node, with automatic IPv4 egress masquerading, admin-approval guidance, fail-closed IPv6 behavior and Home Assistant/ntfy visibility. Server mode cannot conflict with selecting another exit node. |
| **Web administration** | Responsive dark UI, graphical feature switches, clear disabled cards, configurable web port, optional password gate and session timeout, local OTA and encrypted backup/restore. |
| **Fast, safer login** | Salted 60,000-round PBKDF2-HMAC-SHA256 verifier plus a one-time browser challenge; no plaintext password for modern records and no multi-second ESP-side unlock delay. |
| **Reliability fixes** | Repairs WiFi scan/save and HTTP 431 failures, ntfy reboot loops and missed commands, false post-login offline state, forwarding-table startup counts and web/Tailscale socket starvation. |
| **Privacy cleanup** | Removes anonymous telemetry, external crash/log uploads, automatic GitHub polling/downloads, Cloudflare speed tests and the hard-coded public DNS fallback. |
| **Easy installation** | Releases include one factory image, one update image and a Windows ZIP with Espressif `esptool` plus guided clean-install/update batch files. No toolchain required. |

The complete technical comparison is in [`CUSTOM_BRANCH.md`](CUSTOM_BRANCH.md).
This remains community firmware rather than a formally audited network
appliance; read [Known limitations](#known-limitations) before deployment.

## What it is

This firmware turns one ESP32-S3 board into three things at once:

1. **A WiFi NAT router.** It joins your existing 2.4 GHz network as a
   client (STA) and re-broadcasts its own access point (AP). The IoT
   devices on that AP reach the internet through the upstream WiFi, with
   NAPT, DHCP, and an on-board DNS forwarder.
2. **A Tailscale subnet router.** It runs a userspace WireGuard +
   Tailscale (`ts2021`) stack, so any peer on your tailnet can reach the
   devices behind its AP — and the AP-side devices can use the ESP as a
   Tailscale **exit node** gateway. No client software on the IoT
   devices, no cloud account on the LAN.
3. **A selective Tailnet service gateway.** Ordinary devices on the ESP32's
   uplink LAN can connect to its LAN address and reach individual services on
   Tailnet peers. Per-rule source CIDRs expose only the ports you choose,
   without installing Tailscale on the local client.

Everything — WiFi credentials, the tailnet auth key, advertised routes,
firewall rules, diagnostics — is configured from a phone or laptop
browser. There is no app and no serial console required after the first
flash.

<div align="center">
<img src="docs/images/status_v3.png" alt="Web UI — Status dashboard" width="88%">
<br><em>The Status dashboard: uplink, access point, Tailscale node and peers at a glance.</em>
</div>

## Why

Most "put a sensor on Tailscale" setups need either a Raspberry Pi
acting as a subnet router or per-device Tailscale clients. This project
collapses that into a ~$10 board you can leave plugged into a USB
charger: it bridges a whole IoT subnet onto your tailnet *and* gives
those devices internet through an exit node, while staying small enough
to ignore.

## Where it fits

Typical setups people use it for:

- **Weekend house / cabin.** A Tasmota/Shelly AC, water heater or
  freeze-guard on the cabin's existing WiFi — your home Home Assistant
  sees and controls it, with no public IP, port-forward or VPN server on
  the cabin's router.
- **Parents' / grandparents' place.** A couple of sensors (temperature,
  door/window, water-leak) pulled into your own HA so you can watch them
  and get alerted, without ever touching their router.
- **CGNAT / mobile-broadband locations.** Sites with no public IP (4G
  routers, shared building internet) that you could never reach before —
  the tailnet bridges the CGNAT, so HA sees everything anyway.
- **Garage / workshop / shed.** There's WiFi, but you don't want to set up
  a VLAN or VPN; the garage door, irrigation or a frost guard just show
  up in HA.
- **Rentals / networks you don't own.** Not your router, no right to
  port-forward — the ESP puts your gadgets on the tailnet as a node, done.

The common thread: there's WiFi on site, but you can't (or don't want to)
touch the router. That's exactly where this fits.

## What it's for — and what it isn't

This is a **micro-controller** doing userspace encryption and NAT on a
single shared 2.4 GHz radio. Its job is **reach, not throughput** — size
your expectations accordingly.

**✅ What it's for**

- IoT / home-automation gear: **sensors, smart switches, plugs,
  thermostats**, energy/environmental monitors, ESPHome / Zigbee / MQTT
  bridges — anything small and low-bandwidth.
- Low-rate control and status traffic: bursty, tiny payloads that are perfectly
  happy with around a megabit.
- Reaching a device stuck behind NAT/CGNAT so you (or Home Assistant) can
  poll it, flip a relay, or SSH in from anywhere on your tailnet.

**🚫 What it's not for**

- Being the everyday internet uplink for your **phone or laptop**.
- **Streaming, video calls, or watching a camera feed in high resolution.**
- Large downloads, backups, OTA images for other devices — anything
  bandwidth-heavy.
- A general-purpose VPN gateway for fast clients.

Real-world throughput through the tunnel runs **roughly 0.3–1.4 Mbit/s**,
depending on the path — plain STA routing is at the top of that range, a
**direct** exit node in the middle, and a **DERP-relayed** exit node at
the bottom. Plenty for switches and sensors, not for media. If you need
real bandwidth, put a Raspberry Pi (or similar) on that job instead. *(Configuring the device from a
phone or laptop browser is of course fine — that's just the admin UI, not
traffic you route through it.)*

## Features

- **Dual role** — simultaneous WiFi STA (uplink) + AP (NAT router) +
  Tailscale subnet router.
- **Expose the upstream LAN too** — beyond its own AP subnet, an optional
  Source-NAT (à la Tailscale `--snat-subnet-routes`) lets tailnet peers reach
  the network the device is *connected to*, with no static route needed on the
  upstream router.
- **Web UI for everything** — optional password gate and session timeout, WiFi join,
  tailnet enrolment, routes, firewall, diagnostics. Dark, responsive,
  single-page; served straight off the device.
- **Tailscale, the real protocol** — DISCO peer discovery, direct paths
  *and* DERP relay fallback, NAT traversal, MagicDNS-aware, exit-node
  client, exit-node server and gateway. Powered by [microlink](https://github.com/Csontikka/microlink).
- **Exit-node advertising** — optionally offer the ESP32 uplink as an IPv4
  Internet exit for authorized tailnet peers. The firmware announces the
  standard default routes, automatically applies egress NAT, and prevents
  simultaneous exit-node client/server modes. Approval in the Tailscale admin
  console is still required. IPv6 is fail-closed on the current IPv4 data plane.
- **Exit-node aware routing** — AP clients' internet traffic can be
  forced through a chosen Tailscale exit node; when the exit node is
  unreachable the firmware **fails closed** (traffic stops) rather than
  silently leaking to the local uplink.
- **Stateful-ish ACL firewall** — four hook points (Internet↔ESP,
  Clients↔ESP) with first-match-wins rules by protocol / CIDR / port /
  action, plus per-rule hit counters.
- **DNS forwarder with cache** — on-board resolver for AP clients with a
  PSRAM-backed response cache and configurable upstream.
- **Operations toolbox** — on-device ping / traceroute / route-explain,
  live WiFi scan, and a microSD "flight recorder" for catching
  control-plane stalls.
- **DHCP niceties** — reservations, live lease table, per-client signal,
  and a MAC denylist.
- **Selectable client WiFi** — use the ESP access point as a simple gateway for
  devices that need Internet and tailnet access; keep it always available or
  place it in standby while the uplink is connected. It returns automatically
  after an uplink failure so administration remains possible.
- **Wake-on-LAN address book** — save up to 12 devices and send their UDP
  magic packets from the web UI, MQTT, or Home Assistant.
- **MQTT + Home Assistant** — retained health/network/Tailscale state,
  inbound AP/routing/Tailscale/reconnect/restart/WOL commands, Last Will
  availability, and automatic Home Assistant discovery (including one Wake
  button per saved device).
- **Optional Tailscale 4via6** — maps a configurable IPv4 LAN and site ID
  into Tailscale's 4via6 prefix, advertises it alongside normal IPv4 routes,
  and translates TCP, UDP and ICMP traffic in both directions.
- **Optional ntfy integration** — alerts when the internet uplink works but
  Tailscale remains down, includes a bounded local log tail, and accepts
  replay-protected `info` and WOL commands. It is disabled by default.
- **Robust by design** — encrypted config backup/restore, local-only manual
  OTA upload, per-sink (console + SD) log levels, auto AP-channel realign on
  STA roam, and pre-crash log capture.
- **Private by design** — no usage reports, crash uploads, release polling,
  or automatic firmware downloads. Outbound application traffic is limited
  to Tailscale and the MQTT/ntfy endpoints explicitly configured by the operator.

## Hardware

| | |
|---|---|
| **Target** | ESP32-S3 with PSRAM (8 MB octal, 80 MHz) |
| **Reference board** | ESP32-S3-DevKitC-1 **N16R8** (16 MB flash / 8 MB PSRAM) |
| **Radio** | Single 2.4 GHz — STA and AP share one radio (see [limitations](#known-limitations)) |
| **Storage (optional)** | microSD for the log flight-recorder |
| **Power** | USB-C; ~real-world draw of a small dev board |

**Only the ESP32-S3 is supported.** It's the board this firmware is
written for and tested on, and it's the only one I have. The PlatformIO
config still lists a few other targets (`esp32`, `esp32-c3`,
`wt32-eth01`) left over from earlier scaffolding, but I don't build or
test against them and have no idea whether they work — so I can't support
them. This is a free hobby project and I'm not planning to buy extra
boards just to validate other hardware. If you get it running elsewhere,
great — but you're on your own there, and PRs are welcome.

### Board compatibility notes (community-tested)

Real-world results from the field (see [#9](../../issues/9) and
[#10](../../pull/10) — thanks @bobcroft and @markvovo):

| Board | Result |
|---|---|
| **ESP32-S3-DevKitC-1 N16R8** (genuine) | ✅ Reference — developed and tested on this |
| **Freenove ESP32-S3-WROOM N8R8** | ✅ Community-confirmed: AP, web UI, full setup |
| **Seeed XIAO ESP32-S3 N8R8** | ✅ Community-confirmed: AP join, plus the WireGuard/DERP data plane (both a direct peer-to-peer session and a relayed one). Web UI wasn't separately re-verified. See the first-flash note below |
| **YD-ESP32-S3 ("YD32") clones** | ❌ SoftAP never visible on air — fails even with a minimal ESP-IDF AP example, i.e. a board-level RF problem, not this firmware |

> **First flash on a XIAO:** one tester's board wouldn't accept the default AP
> password until they ran a full `esptool erase_flash` followed by a
> `factory_reset --confirm`, allowing a little extra time before retrying the
> join. No log survives from the failed first boot, so this is a known rough
> edge rather than a diagnosed bug. If you hit it, erase the flash and retry.
> The `firmware-factory.bin` asset on the
> [latest release](../../releases/latest) is a full-flash
> image and rewrites the NVS region too, so it sidesteps this as well.

## Quick start

### 1. Flash it — no build tools required

Download the latest
[`ESP32-S3-router-0.1.19-Mattboxx-1.4-windows.zip`](../../releases/latest),
connect the ESP32-S3 over USB and run one of the included guided batch files:

- `UPDATE_KEEP_SETTINGS.bat` updates an existing installation without erasing its configuration;
- `CLEAN_INSTALL_ERASE_ALL.bat` performs a fresh installation and removes every old setting.

The release also provides `firmware-factory.bin` for other flashing tools and
`firmware.bin` for the local web updater.

### Build from source instead

```bash
git clone --recurse-submodules https://github.com/Mattboxx/esp32-tailscale-gateway
cd esp32-tailscale-gateway

# PlatformIO (recommended)
pio run -e esp32-s3 -t upload

# …or ESP-IDF (>= 5.5.3)
idf.py set-target esp32s3
idf.py build flash monitor
```

> The web assets are embedded into the firmware at build time from
> `main/index.html`, so a single flash carries the whole UI.

### 2. First-time setup

On first boot the device brings up its own access point:

- SSID: **`ESP32-TSR-Setup`** (builds before v0.1.18: `myssid`),
  password: **`mypassword`**
- Connect to it and open **http://192.168.4.1** — set an admin password
  there, then rename the AP to your liking.

<div align="center">
<img src="docs/images/login.png" alt="First-run admin password" width="46%">
</div>

### 3. Join your WiFi

On **Network → Access Point / Uplink networks**, point the device at your
existing 2.4 GHz network and (optionally) rename the AP it broadcasts.

<div align="center">
<img src="docs/images/network-ap_v2.png" alt="Access Point configuration" width="80%">
</div>

### 4. Enrol on your tailnet

This is the one step with a couple of non-obvious Tailscale details — do
them once and the device stays on your tailnet for good.

#### 4a · Create a Tailscale auth key

Log in to the [Tailscale admin console](https://login.tailscale.com/admin/settings/keys)
→ **Settings → Keys** and click **Generate auth key…**.

<div align="center">
<img src="docs/images/tailscale-keys-page.png" alt="Tailscale admin — Keys page" width="80%">
</div>

Fill in the dialog:

<div align="center">
<img src="docs/images/tailscale-auth-key-create.png" alt="Generate auth key dialog" width="70%">
</div>

| Option | Value | Why |
|---|---|---|
| **Description** | `esp32-router` | so you can find it later |
| **Reusable** | ✅ On | re-flash without regenerating a key |
| **Ephemeral** | ❌ **Off** | ephemeral nodes get garbage-collected when offline — bad for a device that reboots |
| **Pre-approved** | ✅ On *(if your tailnet uses device approval)* | lets the device join without a manual click |
| **Tags** | `tag:esp32` *(optional)* | handy for ACL targeting |
| **Expiration** | 90 days *(max)* | Tailscale caps this — you make the node **permanent** in 4c below |

Copy the key (it starts with `tskey-auth-…`).

#### 4b · Paste it into the device

On the device's **Tailscale** tab, paste the auth key, set a **hostname**,
and list the **subnet(s) to advertise** (your AP subnet is offered
automatically). Pick an **exit node** here too if you want AP clients to
egress through it. Save — the device registers with your tailnet on its
next connect.

<div align="center">
<img src="docs/images/tailscale_v2.png" alt="Tailscale configuration and peers" width="88%">
</div>

> **Approve the route.** A newly advertised subnet shows up in the Tailscale
> admin (Machines → your device → **Edit route settings**) and must be
> **approved** before peers can use it. And if you later change the AP subnet,
> re-approve the new route there — the old approval stays but no longer matches,
> so the subnet silently becomes unreachable until you do.

> **Reaching the *uplink* LAN (not just the AP subnet).** To expose the network
> the device is connected to (its STA/uplink side), advertise that subnet too and
> turn on **Source-NAT advertised routes**. That masquerades tunnel→LAN traffic to
> the device's own uplink IP (Tailscale's `--snat-subnet-routes` default), so
> upstream hosts can reply without a route back to the tailnet. Without it, the
> upstream router would need a static route (`100.64.0.0/10 → this device`).

> **🔑 Auth key vs. node key — read this once**
>
> - The **auth key** (`tskey-auth-…`) is a *one-time ticket*: the device uses
>   it only on first registration. After that it has its own private **node
>   key** (stored in NVS) and no longer needs the auth key — so it's fine if
>   the auth key later expires.
> - The **node key** is the device's long-term identity, and Tailscale expires
>   it after ~180 days by default. When it expires the device drops off the
>   tailnet — exactly what you *don't* want on an unattended sensor.
>
> So once the device shows up in your tailnet, **disable its node-key expiry**
> (next step). Skip it and everything looks fine for months, then the device
> silently falls off and you won't know why. Do it for every device you flash.

#### 4c · Disable node-key expiry (do this — always)

1. Open the [Tailscale **Machines** page](https://login.tailscale.com/admin/machines).
2. Find the new `esp32-router` entry.
3. Click the `⋯` menu → **Disable key expiry**.

<div align="center">
<img src="docs/images/tailscale-disable-key-expiry.png" alt="Tailscale admin — Disable key expiry" width="80%">
</div>

4. **Reboot the device** (Reboot on the **System** tab, or power-cycle). The
   expiry status is only re-fetched on a fresh control-plane login, so a plain
   reconnect isn't enough.

That's it — remote tailnet peers can now reach the IoT devices on the AP
subnet, and those devices can use the tailnet (and any exit node you picked).

## Web UI tour

The single-page UI has seven sections:

| Section | What's there |
|---|---|
| **Status** | Uplink, AP, Tailscale node + peer list, memory, uptime |
| **Network** | Uplink networks, AP (SSID/IP/DNS), DHCP, MAC denylist, AP-side forwarding, and separate LAN → Tailnet service forwarding |
| **Tailscale** | Auth key, hostname, advertised routes, exit node, MTU, peer table |
| **Firewall** | The four ACL chains, rule editor, hit counters |
| **Diagnostics** | Route-explain, ping, traceroute, WiFi scan, live + SD logs |
| **Automation** | Wake-on-LAN address book, MQTT status/commands, broker watchdog, Home Assistant discovery, optional ntfy alerts and commands |
| **System** | Device name, web password gate + idle timeout, manual firmware upload, SD-card logging, backup, danger zone, privacy status |

### Firewall / ACL

Four chains, evaluated first-match-wins; an empty chain allows by
default. Rules match on protocol, source/destination CIDR, ports, and
action, with live hit counters.

<div align="center">
<img src="docs/images/firewall_v2.png" alt="Firewall — four ACL chains with example rules" width="88%">
</div>

| Chain | Direction |
|---|---|
| `TO_ESP` | Internet → ESP |
| `FROM_ESP` | ESP → Internet |
| `TO_AP` | Clients → ESP |
| `FROM_AP` | ESP → Clients |

### Diagnostics

Route-explain answers "where would a packet to *X* actually go —
uplink, WireGuard, or DERP?", which is the fastest way to reason about
exit-node and subnet routing.

<div align="center">
<img src="docs/images/tools-route.png" alt="Route explain" width="80%">
<br>
<img src="docs/images/tools-ping.png" alt="On-device ping" width="80%">
</div>

## How it works

```
             Internet                   Tailnet peers/services
                │                               │
      ordinary uplink-LAN client ──┐            │ WireGuard / DERP
                                   ▼            ▼
                            ┌────────────────────────┐
                            │       ESP32-S3         │
                            │ NAPT · DHCP · DNS · ACL│
                            │ LAN→Tailnet forwarding │
                            └───────────┬────────────┘
                                  AP   │  optional IoT gateway
                              ┌────────┼──────────┐
                            sensor   switch   thermostat
```

> The AP is for **IoT gear** — sensors, switches, low-bandwidth control —
> not for routing your phone's or laptop's everyday internet. See
> [What it's for](#what-its-for--and-what-it-isnt).

- **Data plane vs control plane.** WireGuard moves packets; Tailscale's
  DISCO/`ts2021` control plane decides *how* (direct UDP vs DERP relay).
  The firmware watches the WireGuard data plane and re-handshakes over
  DERP when a direct path dies, so an exit-node session survives a
  direct↔DERP transition without dropping.
- **Exit-node routing.** A route hook forces AP-client public traffic
  into the WireGuard tunnel when an exit node is set; CGNAT (`100.64/10`)
  always goes to the tunnel. If the exit node is down, traffic stops —
  it is **not** silently rerouted to the local uplink.
- **microlink.** The Tailscale-compatible stack lives in its own repo,
  [Csontikka/microlink](https://github.com/Csontikka/microlink) — itself
  based on the original [CamM2325/microlink](https://github.com/CamM2325/microlink) —
  attached here as a git submodule and pinned to the integration commit.
  Its `docs/ARCHITECTURE.md` and `docs/TAILSCALE_REFERENCE.md` go deeper.

See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for a field-by-field
configuration reference.

## Tailscale & Headscale

The device authenticates with a standard **Tailscale** auth key and has
been validated against the hosted Tailscale control plane.

**Headscale is supported** (validated against Headscale v0.28.0; requires
Headscale ≥ 0.26): set **Login server** to your server and authenticate
with a Headscale pre-auth key. Accepted forms:

- `host` or `host:port` — plain TCP, port defaults to 80
- `http://host[:port]` — e.g. `http://192.168.1.42:8080`
- `https://host[:port]` — TLS, port defaults to 443. The certificate is
  validated against the ESP-IDF public-CA bundle (Let's Encrypt works);
  **self-signed / private-CA certificates are not supported**.

The device fetches the server's Noise public key from `/key?v=88` and
reads the initial netmap from the streaming long-poll, matching what
current Headscale versions require.

`tailnet lock` is not supported (the device cannot sign its own node
key); disable it for the tailnet or pre-authorize the node.

## Known limitations

- **Single radio.** STA and AP share one 2.4 GHz radio and channel. If
  the upstream AP is on a different channel after a roam, throughput
  collapses until the device realigns (it auto-reboots to do so).
- **Throughput.** This is an MCU doing userspace crypto + NAT; expect
  roughly **0.3–1.4 Mbit/s** through the tunnel (plain STA highest, direct
  exit node mid, DERP-relayed exit node lowest), not gigabit. Plenty for
  IoT and remote-admin traffic.
- **Exit node fails closed.** By design — when a selected exit node is
  unreachable, AP-client internet traffic stops rather than leaking to
  the local uplink. Clear the exit node to restore direct internet.
- **Exit-node server egress is IPv4-only.** The device advertises both
  standard default routes so a client cannot leak IPv6 around the chosen exit,
  but the current microlink data plane only forwards IPv4 Internet traffic.
  IPv6 through this ESP32 therefore fails closed instead of bypassing it.
- **Tailnet lock unsupported.** Headscale over HTTPS needs a public-CA
  certificate (self-signed is rejected).
- **Local web UI uses HTTP.** Tailscale still encrypts tailnet transport, but
  administer the device only from a trusted LAN/AP or through Tailscale. A
  hostile client on the same local network can otherwise observe HTTP traffic.
  Browser hardening headers reduce injection/clickjacking exposure but cannot
  provide transport encryption.
- **Physical extraction is not prevented.** The portable factory image leaves
  ESP32-S3 Secure Boot, flash encryption and NVS encryption disabled. Someone
  with physical access can read stored credentials or replace the firmware.
- **Remote automation is as trusted as its transport.** Use MQTT/ntfy TLS,
  private topics and broker/server ACLs, especially when commands are enabled.
  The dashboard warns on plaintext transports, and ntfy `info` hides private
  network details unless they are explicitly enabled.
- **ESP-IDF 5.3.1.** The pinned PlatformIO framework must be compatibility-tested
  before a patch-line upgrade; security-relevant upstream fixes are reviewed
  against the enabled feature set in this fork.
- **2.4 GHz only**, single AP subnet.

## Privacy and outbound traffic

This build contains no usage reporting, crash upload, release polling, or
automatic firmware download. Crash summaries and logs stay on the device.
The only application-level outbound connections are Tailscale/Headscale and,
when enabled by the operator, the configured MQTT broker and ntfy server. DNS, DHCP and NTP
remain available as infrastructure needed to resolve and establish those
connections. Diagnostic ping and traceroute run only when explicitly started.

For the complete, explicit comparison with upstream `main`, see
[`CUSTOM_BRANCH.md`](CUSTOM_BRANCH.md). A ready-to-use Windows flash package is
available as [`ESP32-S3-router-0.1.19-Mattboxx-1.4-windows.zip`](flash-package/ESP32-S3-router-0.1.19-Mattboxx-1.4-windows.zip);
instructions are in [`flash-package/README.txt`](flash-package/README.txt).

## Security

Please report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).
The repo runs CodeQL, Dependabot, secret scanning, and a custom
[Sensitive Data Check](.github/workflows/sensitive-check.yml) on every
push.

## Development

```
main/                 firmware entry, web server + embedded SPA (index.html)
components/
  acl/                the ACL firewall engine
  sdlog/              microSD flight-recorder
  …                   DNS relay, DHCP server, etc.
external/microlink/   Tailscale/WireGuard stack (git submodule, MIT)
docs/                 configuration reference, images
tools/                helper scripts
```

The entire web UI is the single file `main/index.html`, embedded into
the firmware by `main/CMakeLists.txt` at build time.

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for build/flash setup and pull-request
guidelines, and **[docs/TESTING.md](docs/TESTING.md)** for the test harness.

## Support

Found a bug or have an idea? Open an
[issue](https://github.com/Mattboxx/esp32-tailscale-gateway/issues).
If this firmware saved you a router purchase or an afternoon of
debugging, you can chip in:
[buy me a coffee](https://buymeacoffee.com/csontikka) ☕ or [sponsor me on GitHub](https://github.com/sponsors/Csontikka)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/bunny.png">
    <img alt="Csontikka" src="assets/logo/bunny_dark.png" width="52">
  </picture>
</p>

## Credits & license

This firmware is [MIT](LICENSE) licensed. It builds on:

- **[microlink](https://github.com/Csontikka/microlink)** — Tailscale
  `ts2021` client (MIT), based on the original
  [CamM2325/microlink](https://github.com/CamM2325/microlink)
- **wireguard_lwip** — userspace WireGuard for lwIP (BSD-3-Clause),
  vendored inside microlink
- **[ESP-IDF](https://github.com/espressif/esp-idf)** — Espressif RTOS &
  networking (Apache-2.0)

See [`NOTICE.md`](NOTICE.md) for the full third-party attribution list.

> *Tailscale* and *Headscale* are trademarks of their respective owners.
> This is an independent, unaffiliated community project.
