# Security Policy

## LAN → Tailnet forwarding boundary

Each enabled LAN → Tailnet rule deliberately exposes one Tailnet TCP/UDP
service on the ESP32 uplink address. The firmware requires an allowed-source
CIDR, rejects non-CGNAT resolved targets, isolates these mappings from the AP
and WireGuard input interfaces, and rejects listener collisions. Operators
should still choose the narrowest CIDR, authenticate the destination service,
and enforce Tailnet ACLs; this is a gateway, not an application firewall.

## Reporting a Vulnerability

If you think you've found a security issue in this firmware — for example a
memory-corruption bug in the C code, a way to leak the web-UI password or the
Tailscale auth key / WireGuard keys out of NVS, an ACL/firewall bypass, a
web-UI authentication bypass, or any other concern that affects the safety of a
device running this code — please report it privately rather than opening a
public issue.

**Preferred channel:** use GitHub's [private vulnerability reporting](https://github.com/Mattboxx/esp32-tailscale-subnet-router/security/advisories/new)
on this repository. This creates a private security advisory that only the
maintainer and invited collaborators can see.

If that isn't available, contact the fork owner through the GitHub profile at
[@Mattboxx](https://github.com/Mattboxx).

Please include:

- A description of the issue and why you think it's a security problem.
- The exact commit / version of the firmware you observed it on.
- Steps to reproduce, if possible — ideally the relevant web-UI / `/api/*`
  configuration or serial-console input and a description of the runtime
  behavior.
- Any logs, crash dumps (coredump), or serial output that illustrates the
  problem.

Reports will be reviewed privately and coordinated before disclosure.

## Scope

This repository is the **ESP-IDF firmware** for the router (AP/STA NAT, web UI,
ACL firewall, DHCP/DNS, etc.). The Tailscale-compatible WireGuard userspace
stack lives in the [microlink](https://github.com/Csontikka/microlink)
submodule — if the vulnerability is in the DISCO/DERP/magicsock/WireGuard
protocol handling itself, please consider reporting it there as well, since the
fix will likely need to land in that project first.

## Supported Versions

This project is under **heavy development**. Only the current `mattboxx` branch is
supported for security fixes. Older commits and unreleased snapshots are not
maintained.

## Deployment hardening

- Keep the web password gate enabled. Short passwords are accepted for device
  recovery and compatibility, but a long unique password is strongly advised.
  Password verifiers use salted PBKDF2-HMAC-SHA256; older SHA-256 records are
  upgraded automatically after the next successful login.
- The embedded UI is HTTP-only. Do not forward port 80 to the Internet or an
  untrusted VLAN. Prefer access through a trusted LAN or the encrypted
  Tailscale path, and disable the access point when it is not needed.
- Prefer `mqtts://`, `wss://`, and `https://` transports. If a plaintext local
  MQTT or ntfy server is unavoidable, isolate it on a trusted network and use
  broker/topic ACLs. Anyone allowed to publish commands can operate WOL and
  the exposed router controls.
- Use an access-controlled, unguessable ntfy topic. The optional `info`
  response never contains passwords or tokens; network topology, peer names/
  IPs, AP-client MACs and saved WOL targets are omitted unless the separate
  private-details option is explicitly enabled.

## Hardware-security boundary

The general-purpose release does not enable ESP32 Secure Boot, flash
encryption, or encrypted NVS. Those features require owner-specific keys and
an irreversible provisioning procedure; enabling them in a universal binary
would either embed a shared secret or risk making boards unflashable. Treat
physical access as trusted. A device-specific hardened build should provision
unique keys, enable Secure Boot and flash/NVS encryption, then retain an
offline recovery copy of those keys.

## History rewrite — 2026-06-01

The git history of this repository was rewritten on 2026-06-01 to remove
development-environment data that had been committed in earlier code comments,
a deleted helper script, and test utilities:

- the maintainer's real Tailscale **tailnet name** and a development **WiFi
  SSID** (replaced with generic placeholders);
- development-network **IP ranges** (replaced with generic RFC1918 examples);
- a development **admin password** that appeared in a since-deleted helper
  script (`tools/verify_routes.py`) — replaced with `REDACTED`.

That password protected only a local development board, but since it was once
public it must be considered **burned** and should be **rotated** on any
affected device. No Tailscale auth keys, WireGuard keys, API tokens, or private
keys were ever committed (those have always been git-ignored).

Because history was rewritten, commit hashes prior to this date differ from any
older clone or fork. Re-clone rather than pull if you have an old copy. The
rewrite is marked by the annotated tag `history-scrub-2026-06-01`.

## Non-affiliation notice

This project is **not** affiliated with, sponsored by, or endorsed by Tailscale
Inc., Jason A. Donenfeld, or the WireGuard project. Please do not report
Tailscale-service or WireGuard-protocol vulnerabilities here — report those to
the respective upstream projects.
