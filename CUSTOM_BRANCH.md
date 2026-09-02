# Custom ESP32-S3 router branch

This branch starts from upstream `main` at `v0.1.19` and targets the ESP32-S3
N16R8 used during development. It has been built, flashed and tested on the
connected board.

## Added

- Stable ESP32-S3 setup UI and WiFi scanning/saving, including the HTTP 431 fix.
- Selectable client WiFi / tailnet gateway: always available, or placed in
  standby while the uplink is connected and restored after a disconnect.
  Dashboard and Network explicitly show Disabled when it is not running.
- A separate Automation page for Wake-on-LAN and MQTT/Home Assistant.
- A WOL address book with saved name, MAC, broadcast and port, plus web, MQTT
  and Home Assistant triggers.
- MQTT retained state, Last Will, commands and watchdog.
- Home Assistant discovery for network/Tailscale/AP/system/MQTT diagnostics and
  AP, routes, SNAT, LAN bypass, Tailscale, reconnect, restart, publish and WOL.
- Optional Tailscale 4via6 routing for overlapping IPv4 LANs: configurable
  LAN CIDR and site ID, calculated/advertised prefix, bidirectional TCP/UDP/
  ICMP translation, flow counters and Home Assistant status/control.
- Optional ntfy alerts for a Tailscale outage while the uplink is working,
  plus replay-protected `info` and saved/direct-MAC WOL commands.
- Fixed the ntfy command-poll reboot loop: the HTTP response buffer is now
  heap-backed instead of exhausting the ntfy task stack on its first poll.
- Fixed ntfy commands being permanently missed because the old 10-second
  history window was shorter than the default 15-second poll interval. The
  first eligible poll is immediate and subsequent polls use a durable cursor.
- Graphical on/off switches and visibly dimmed disabled cards/settings for AP,
  Tailscale, 4via6, MQTT, Home Assistant, watchdog, ntfy and web authentication.
- Optional web password gate and session timeout. Passwords of at least four
  characters are accepted, with a visible warning for weak choices.
- Manual local OTA upload and explicit privacy/outbound-traffic reporting.

## Removed from upstream main

- Built-in anonymous telemetry and its hard-coded Cloudflare Worker. No boot,
  usage, reconnect, reset or crash event is uploaded.
- Automatic GitHub release polling and firmware downloads.
- Cloudflare speed test and its hard-coded public DNS fallback.
- Browser-side automatic GitHub release requests.

Historical telemetry entries remain in `CHANGELOG.md` only because it records
older upstream releases. The source is deleted and not linked into the firmware.

## Security and privacy hardening

- Persistent warning logs omit peer names, key prefixes, private endpoint IPs
  and endpoint ports.
- The remote TCP console refuses to start without a configured admin password.
- Login attempts are rate-limited per client; initial password setup is only
  accepted through the ESP's own access point.
- Dynamic toast text is inserted as text rather than HTML, preventing stored or
  reflected script injection through device names and server error messages.
- HTTP request bodies are read completely before JSON parsing instead of
  assuming one TCP read contains the entire save request.
- Retained or duplicate MQTT commands are ignored so an old restart/WOL command
  cannot execute again every time the broker reconnects.
- DHCP packet address fields are defensively initialized and lease eviction is
  safe even when its list-size invariant is violated in a release build.
- Secrets, OTA, factory reset, crash trigger and Tailscale identity reset always
  require a password-authenticated session, even when the UI gate is disabled.
- The compiled image contains no fixed telemetry, update or speed-test target.

## Expected outbound traffic

The remaining functional traffic is limited to:

- the selected Tailscale/Headscale control plane, DERP and STUN endpoints;
- NTP (`pool.ntp.org`) for time required by authenticated/TLS connections;
- the operator-configured MQTT broker, only when MQTT is enabled;
- the operator-configured ntfy server, only when ntfy is enabled;
- targets explicitly requested by ping, traceroute, WOL or routed clients.

No hidden path that adds tailnet devices or uploads local logs was found in the
reviewed source or compiled image. Peers come from the configured control plane.
This source audit is not a formal proof; tailnet and broker ACLs remain important.

## Remaining security boundaries

- The web UI is HTTP, so use it only on a trusted AP/LAN or over encrypted
  Tailscale transport.
- Secure Boot, flash encryption and NVS encryption remain disabled so one
  generic factory image can be flashed on ordinary boards. Physical access can
  therefore expose saved credentials and replace the firmware.
- Four-character passwords are accepted by operator choice. Online guesses are
  throttled, but a strong unique password is still recommended.
- MQTT/ntfy commands trust the configured broker/server, token and topic. Prefer
  TLS transports, private random topics and restrictive ACLs.

## Flashing

`flash-package` contains tested binaries, Espressif's official standalone
`esptool.exe`, and guided Windows batch files. See `flash-package/README.txt`.
