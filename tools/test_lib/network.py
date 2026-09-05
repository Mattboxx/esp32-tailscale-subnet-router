"""Network endpoints: status/configuration sanity and reversible roundtrips."""
from __future__ import annotations
import time
from .common import Context, Result, SpaClient, check

MODULE_ID = "network"
MODULE_DESC = "AP/STA/DHCP/AP-forward/Tailnet-forward/denylist smoke + roundtrip"


def run(ctx: Context) -> list[Result]:
    results: list[Result] = []
    spa = SpaClient(ctx)
    try:
        # /api/status sanity
        s = spa.fetch_json("/api/status")
        check(results, MODULE_ID, "status: ap fields", isinstance(s, dict) and "ap" in s and "ip" in s["ap"],
              f"got keys={list(s.keys()) if isinstance(s, dict) else type(s).__name__}")
        check(results, MODULE_ID, "status: sta fields", isinstance(s, dict) and "sta" in s and "ip" in s["sta"])
        check(results, MODULE_ID, "status: tailscale fields",
              isinstance(s, dict) and isinstance(s.get("tailscale"), dict) and "advertise_routes" in s["tailscale"])

        # uptime grows between two reads
        u0 = s.get("uptime_s", 0)
        time.sleep(2)
        s2 = spa.fetch_json("/api/status")
        u1 = s2.get("uptime_s", 0)
        check(results, MODULE_ID, "status: uptime monotonic", u1 > u0,
              f"u0={u0} u1={u1}")

        # /api/network
        n = spa.fetch_json("/api/network")
        check(results, MODULE_ID, "network: ap+hostname+networks",
              isinstance(n, dict) and "ap" in n and "hostname" in n and "networks" in n)

        # /api/dhcp/leases shape
        d = spa.fetch_json("/api/dhcp/leases")
        check(results, MODULE_ID, "dhcp/leases: shape",
              isinstance(d, dict) and isinstance(d.get("clients"), list) and isinstance(d.get("leases"), list))

        # /api/dhcp/reservations shape
        r = spa.fetch_json("/api/dhcp/reservations")
        check(results, MODULE_ID, "dhcp/reservations: shape",
              isinstance(r, dict) and isinstance(r.get("reservations"), list))

        # ----- portmap roundtrip -----
        before_pm = spa.fetch_json("/api/portmap")
        check(results, MODULE_ID, "portmap: GET shape",
              isinstance(before_pm, dict) and isinstance(before_pm.get("mappings"), list))

        probe = {"proto": "tcp", "ext_port": 47222, "int_ip": "192.168.31.99", "int_port": 8080, "name": "test-runner"}
        new_list = list(before_pm.get("mappings", [])) + [probe]
        resp = spa.post_json("/api/portmap", {"mappings": new_list})
        ok_post = isinstance(resp, dict) and resp.get("__http_status") == 200
        check(results, MODULE_ID, "portmap: POST add", ok_post, f"resp={resp}")

        after_pm = spa.fetch_json("/api/portmap")
        present = any(e.get("ext_port") == 47222 and e.get("name") == "test-runner"
                      for e in after_pm.get("mappings", []))
        check(results, MODULE_ID, "portmap: probe readback", present,
              f"saved list = {after_pm.get('mappings')}")

        # Restore original
        resp2 = spa.post_json("/api/portmap", {"mappings": before_pm.get("mappings", [])})
        check(results, MODULE_ID, "portmap: restore",
              isinstance(resp2, dict) and resp2.get("__http_status") == 200,
              f"resp={resp2}")
        restored = spa.fetch_json("/api/portmap")
        restore_gone = not any(e.get("ext_port") == 47222 for e in restored.get("mappings", []))
        check(results, MODULE_ID, "portmap: probe removed after restore", restore_gone)
        # ----- independent LAN -> Tailnet forwarding roundtrip -----
        before_tf = spa.fetch_json("/api/tailnet-forward")
        check(results, MODULE_ID, "tailnet-forward: GET shape",
              isinstance(before_tf, dict) and isinstance(before_tf.get("rules"), list))

        tf_probe = {
            "name": "test-runner", "enabled": False, "protocol": "tcp",
            "listen_port": 47223, "tailnet_destination": "100.127.255.254",
            "destination_port": 9, "allowed_source_subnet": "192.168.1.0/24",
        }
        tf_list = list(before_tf.get("rules", [])) + [tf_probe]
        tf_resp = spa.post_json("/api/tailnet-forward", {"rules": tf_list})
        check(results, MODULE_ID, "tailnet-forward: POST add",
              isinstance(tf_resp, dict) and tf_resp.get("__http_status") == 200,
              f"resp={tf_resp}")

        after_tf = spa.fetch_json("/api/tailnet-forward")
        tf_present = any(e.get("listen_port") == 47223 and e.get("name") == "test-runner"
                         for e in after_tf.get("rules", []))
        check(results, MODULE_ID, "tailnet-forward: probe readback", tf_present,
              f"saved list = {after_tf.get('rules')}")

        tf_restore = spa.post_json("/api/tailnet-forward", {"rules": before_tf.get("rules", [])})
        check(results, MODULE_ID, "tailnet-forward: restore",
              isinstance(tf_restore, dict) and tf_restore.get("__http_status") == 200,
              f"resp={tf_restore}")
        restored_tf = spa.fetch_json("/api/tailnet-forward")
        tf_gone = not any(e.get("listen_port") == 47223 for e in restored_tf.get("rules", []))
        check(results, MODULE_ID, "tailnet-forward: probe removed after restore", tf_gone)


        # ----- mac denylist roundtrip -----
        before_md = spa.fetch_json("/api/mac/denylist")
        check(results, MODULE_ID, "mac/denylist: GET shape",
              isinstance(before_md, dict) and isinstance(before_md.get("denylist"), list))

        new_md = list(before_md.get("denylist", [])) + [{"mac": "02:00:00:de:ad:01", "name": "test-runner"}]
        resp3 = spa.post_json("/api/mac/denylist", {"denylist": new_md})
        check(results, MODULE_ID, "mac/denylist: POST add",
              isinstance(resp3, dict) and resp3.get("__http_status") == 200, f"resp={resp3}")

        after_md = spa.fetch_json("/api/mac/denylist")
        md_present = any(e.get("mac") == "02:00:00:de:ad:01" for e in after_md.get("denylist", []))
        check(results, MODULE_ID, "mac/denylist: probe readback", md_present,
              f"saved list = {after_md.get('denylist')}")

        spa.post_json("/api/mac/denylist", {"denylist": before_md.get("denylist", [])})
        restored_md = spa.fetch_json("/api/mac/denylist")
        md_gone = not any(e.get("mac") == "02:00:00:de:ad:01" for e in restored_md.get("denylist", []))
        check(results, MODULE_ID, "mac/denylist: probe removed after restore", md_gone)

    finally:
        spa.close()
    return results
