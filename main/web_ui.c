/* Single-page web UI server.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "sdkconfig.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_app_desc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cJSON.h"
#include "lwip/ip4_addr.h"
#include "lwip/sockets.h"
#include "web_ui.h"
#include "tailscale_config.h"
#include "tailscale_mtu.h"
#include "nvs_params.h"
#include "microlink.h"
#include "dns_relay.h"
#include "lwip_route_hook.h"
#include "acl.h"
#include "sdlog.h"
#include "net_diag.h"
#include "wifi_networks.h"
#include "wol.h"
#include "mqtt_integration.h"
#include "ntfy_integration.h"
#include "fourvia6.h"
#include "dhcp_reservations.h"
#include "dhcps_ext.h"
#include "portmap.h"
#include "tailnet_forward.h"
#include "mac_deny.h"
#include "reset_history.h"
#include "ota.h"
#include <stdlib.h>
#include <time.h>

/* Cap on log payloads we surface over /api endpoints — both the live
 * log tail and the pre-crash snapshot share this ceiling so the JSON
 * stays bounded. */
#define WEB_UI_LOG_SNAPSHOT_BYTES 4096
#include "log_capture.h"
#include "netif_hooks.h"
#include "web_password.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_mac.h"
#include "esp_psram.h"
#include "esp_core_dump.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/temperature_sensor.h"

/* Globals owned by main.c — link status flags rendered in /api/status. */
extern int ap_connect;
extern int connect_count;
extern void wifi_sta_pause_for_scan(void);
extern void wifi_sta_resume_after_scan(void);
extern bool wifi_ap_policy_auto_off(void);
extern bool wifi_ap_runtime_enabled(void);
extern void wifi_ap_policy_set_auto_off(bool auto_off);

static const char *TAG = "web_ui";

/* index.html is generated as a gzipped C source by main/CMakeLists.txt
 * via the gen_index_html_gz.py helper. Stored compressed (≈5× smaller
 * than raw) and served with Content-Encoding: gzip — every modern
 * browser transparently inflates. See the build script for why the
 * Python-helper route was chosen over ESP-IDF EMBED_TXTFILES. */
extern const char   index_html_gz_start[];
extern const size_t index_html_gz_len;

/* Browser-facing hardening.  The UI is intentionally a single embedded page,
 * so it needs no third-party frames, objects, forms, scripts or network
 * destinations. Inline script/style remain necessary until the SPA is split
 * into separate embedded assets. */
static void set_browser_security_headers(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Content-Security-Policy",
                       "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                       "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                       "frame-ancestors 'none'; form-action 'self'");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "Permissions-Policy",
                       "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
    httpd_resp_set_hdr(req, "Cross-Origin-Resource-Policy", "same-origin");
}

static esp_err_t index_handler(httpd_req_t *req)
{
    set_browser_security_headers(req);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    /* Without this the browser happily reuses last session's SPA HTML
     * out of HTTP cache, so any client-side fix we ship requires the
     * operator to force-refresh before it takes effect. The SPA is
     * tiny and served from RAM — no reason to cache. */
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    return httpd_resp_send(req, index_html_gz_start, index_html_gz_len);
}

static const httpd_uri_t uri_index = {
    .uri      = "/",
    .method   = HTTP_GET,
    .handler  = index_handler,
    .user_ctx = NULL,
};

static void ip4_to_str(uint32_t ip_nbo, char *out, size_t out_size)
{
    const ip4_addr_t a = { .addr = ip_nbo };
    snprintf(out, out_size, IPSTR, IP2STR(&a));
}

/* Forward decls — definitions live further down. */
static bool  request_authenticated(httpd_req_t *req);
static int   session_find_for_req(httpd_req_t *req);
static void  ip4_hbo_to_str(uint32_t hbo, char *out, size_t out_size);
static char *device_name_dup(void);
static int   subnet_mask_prefix_len(uint32_t mask_nbo);
static bool  s_web_auth_enabled;

static esp_err_t require_auth(httpd_req_t *req)
{
    if (request_authenticated(req)) return ESP_OK;
    httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth required");
    return ESP_FAIL;
}

/* Translate esp_reset_reason() into the short string the SPA renders.
 * IDF 5.5 added USB / JTAG / EFUSE / PWR_GLITCH / CPU_LOCKUP — without
 * those cases the switch fell through to UNKNOWN every time the S3
 * came back from a clean esp_restart(), since IDF reports it as one
 * of the new codes rather than the legacy ESP_RST_SW. */
static const char *reset_reason_str(void)
{
    /* ESP_RST_* are enum values (not #defines), so the previous #ifdef
     * guards never compiled the new IDF 5.x cases in — that's why the
     * S3 always reported UNKNOWN after a clean esp_restart(). With the
     * guards gone, the chip's actual cause shows through. */
    esp_reset_reason_t r = esp_reset_reason();
    static char unk[16];
    const char *base;
    switch (r) {
        case ESP_RST_POWERON:    base = "POWERON";    break;
        case ESP_RST_EXT:        base = "EXT";        break;
        case ESP_RST_SW:         base = "SW";         break;
        case ESP_RST_PANIC:      base = "PANIC";      break;
        case ESP_RST_INT_WDT:    base = "INT_WDT";    break;
        case ESP_RST_TASK_WDT:   base = "TASK_WDT";   break;
        case ESP_RST_WDT:        base = "WDT";        break;
        case ESP_RST_DEEPSLEEP:  base = "DEEPSLEEP";  break;
        case ESP_RST_BROWNOUT:   base = "BROWNOUT";   break;
        case ESP_RST_SDIO:       base = "SDIO";       break;
        case ESP_RST_USB:        base = "USB";        break;
        case ESP_RST_JTAG:       base = "JTAG";       break;
        case ESP_RST_EFUSE:      base = "EFUSE";      break;
        case ESP_RST_PWR_GLITCH: base = "PWR_GLITCH"; break;
        case ESP_RST_CPU_LOCKUP: base = "CPU_LOCKUP"; break;
        default:
            /* Surface the raw enum code so future IDF additions show up. */
            snprintf(unk, sizeof unk, "RAW_%d", (int)r);
            base = unk;
            break;
    }
    /* Append the software cause we tagged just before a deliberate
     * esp_restart() (e.g. "ch-realign 11->1") so the coarse hardware reason
     * (usually "SW") becomes actionable. g_reboot_why is read+cached once at
     * boot in main.c and is empty for resets we didn't tag. */
    extern char g_reboot_why[];
    if (g_reboot_why[0]) {
        static char combined[80];
        snprintf(combined, sizeof combined, "%s (%s)", base, g_reboot_why);
        return combined;
    }
    return base;
}

/* Live CPU-load percentage from the FreeRTOS runtime-stats counters.
 * Compares the IDLE0+IDLE1 task tick deltas against total task ticks
 * since the previous sample, so the first call returns 0 and every
 * call after that gives the load over the elapsed interval. Throttled
 * to 1-per-second so the same /api/status poll burst doesn't churn
 * the sampler. Requires CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS=y. */
static uint8_t sample_cpu_load_pct(void)
{
    static uint64_t s_last_sample_us = 0;
    static uint32_t s_last_total     = 0;
    static uint32_t s_last_idle      = 0;
    static uint8_t  s_last_load_pct  = 0;

    uint64_t now = (uint64_t)esp_timer_get_time();
    if (s_last_sample_us != 0 && now - s_last_sample_us < 1000000) {
        return s_last_load_pct;
    }

    UBaseType_t n = uxTaskGetNumberOfTasks();
    TaskStatus_t *arr = malloc(sizeof(TaskStatus_t) * n);
    if (!arr) return s_last_load_pct;
    uint32_t total = 0;
    UBaseType_t got = uxTaskGetSystemState(arr, n, &total);

    uint32_t idle = 0;
    for (UBaseType_t i = 0; i < got; i++) {
        if (arr[i].pcTaskName && strncmp(arr[i].pcTaskName, "IDLE", 4) == 0) {
            idle += arr[i].ulRunTimeCounter;
        }
    }
    free(arr);

    if (s_last_sample_us != 0 && total > s_last_total) {
        uint32_t total_delta = total - s_last_total;
        uint32_t idle_delta  = idle  - s_last_idle;
        if (idle_delta >= total_delta) {
            s_last_load_pct = 0;
        } else {
            s_last_load_pct = (uint8_t)(100 - ((uint64_t)idle_delta * 100 / total_delta));
        }
    }
    s_last_total     = total;
    s_last_idle      = idle;
    s_last_sample_us = now;
    return s_last_load_pct;
}

/* Internal CPU temperature in °C, or -999 if the sensor isn't available.
 * Lazy-installs on first call; the sensor draws ~1 mA continuously while
 * enabled, so we keep it running once installed rather than turn it on
 * and off per sample. Diag-tab also calls into this via its own copy
 * (kept until the diag handler migrates to this shared helper). */
static float sample_cpu_temp_c(void)
{
    static temperature_sensor_handle_t s_sensor = NULL;
    if (!s_sensor) {
        temperature_sensor_config_t cfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
        if (temperature_sensor_install(&cfg, &s_sensor) != ESP_OK) return -999.0f;
        temperature_sensor_enable(s_sensor);
    }
    float tc = 0;
    if (temperature_sensor_get_celsius(s_sensor, &tc) != ESP_OK) return -999.0f;
    return tc;
}

static esp_err_t status_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    const esp_app_desc_t *desc = esp_app_get_description();
    cJSON_AddStringToObject(root, "version",      desc ? desc->version : "?");
    cJSON_AddNumberToObject(root, "uptime_s",     esp_timer_get_time() / 1000000);
    cJSON_AddNumberToObject(root, "free_heap",    esp_get_free_heap_size());
    /* Heap total tracks the largest-known-free moment since boot; the
     * SPA only uses it to draw the % bar, so the exact denominator
     * isn't important — what matters is that it stays >= free_heap. */
    cJSON_AddNumberToObject(root, "heap_total",   heap_caps_get_total_size(MALLOC_CAP_8BIT));
    cJSON_AddNumberToObject(root, "free_psram",   heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    /* Per-heap split for the Status System tile — separate progress bars
     * for internal DRAM vs SPIRAM let the operator see which heap is
     * actually under pressure (internal is the constrained one). */
    cJSON_AddNumberToObject(root, "mem_internal_free",  heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "mem_internal_total", heap_caps_get_total_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "mem_spiram_free",    heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(root, "mem_spiram_total",   heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(root, "cpu_load_pct",       sample_cpu_load_pct());
    {
        float tc = sample_cpu_temp_c();
        if (tc > -100.0f) cJSON_AddNumberToObject(root, "cpu_temp_c", tc);
    }
    cJSON_AddStringToObject(root, "reset_reason", reset_reason_str());

    /* STA (uplink) — SSID, IP, RSSI, MAC. */
    cJSON *sta = cJSON_CreateObject();
    cJSON_AddBoolToObject(sta, "connected", ap_connect != 0);
    wifi_ap_record_t apr;
    if (ap_connect && esp_wifi_sta_get_ap_info(&apr) == ESP_OK) {
        cJSON_AddStringToObject(sta, "ssid", (const char *)apr.ssid);
        cJSON_AddNumberToObject(sta, "rssi", apr.rssi);
        cJSON_AddNumberToObject(sta, "channel", apr.primary);
    }
    uint8_t mac[6];
    char mac_str[18];
    if (esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK) {
        snprintf(mac_str, sizeof mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        cJSON_AddStringToObject(sta, "mac", mac_str);
    }
    esp_netif_t *sta_if = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip;
    if (sta_if && esp_netif_get_ip_info(sta_if, &ip) == ESP_OK) {
        char buf[16];
        ip4_to_str(ip.ip.addr, buf, sizeof buf);
        cJSON_AddStringToObject(sta, "ip", buf);
        ip4_to_str(ip.gw.addr, buf, sizeof buf);
        cJSON_AddStringToObject(sta, "gateway", buf);
        /* Prefix length + network CIDR — the UI shows the address as
         * "<ip>/<prefix>" and the SNAT toggle offers this subnet for advertising. */
        int sta_pfx = subnet_mask_prefix_len(ip.netmask.addr);
        if (sta_pfx >= 0) {
            cJSON_AddNumberToObject(sta, "prefix", sta_pfx);
            char netbuf[16], cidrbuf[32];
            ip4_to_str(ip.ip.addr & ip.netmask.addr, netbuf, sizeof netbuf);
            snprintf(cidrbuf, sizeof cidrbuf, "%s/%u", netbuf, (unsigned)sta_pfx);
            cJSON_AddStringToObject(sta, "cidr", cidrbuf);
        }
    }
    /* DNS — main resolver only; secondary is rarely set on this device.
     * Reading via esp_netif_get_dns_info so we don't have to track
     * whether DHCP or our static override last touched the slot. */
    if (sta_if) {
        esp_netif_dns_info_t dns_info = {0};
        if (esp_netif_get_dns_info(sta_if, ESP_NETIF_DNS_MAIN, &dns_info) == ESP_OK
            && dns_info.ip.u_addr.ip4.addr) {
            char buf[16];
            ip4_to_str(dns_info.ip.u_addr.ip4.addr, buf, sizeof buf);
            cJSON_AddStringToObject(sta, "dns", buf);
        }
    }
    cJSON_AddNumberToObject(sta, "bytes_in",  (double)netif_hooks_get_sta_bytes_in());
    cJSON_AddNumberToObject(sta, "bytes_out", (double)netif_hooks_get_sta_bytes_out());
    cJSON_AddItemToObject(root, "sta", sta);

    /* AP (downlink) — SSID + channel from live wifi_config, MAC, clients, IP. */
    cJSON *ap = cJSON_CreateObject();
    cJSON_AddBoolToObject(ap, "enabled", wifi_ap_runtime_enabled());
    cJSON_AddBoolToObject(ap, "auto_off_when_connected", wifi_ap_policy_auto_off());
    cJSON_AddNumberToObject(ap, "clients", connect_count);
    wifi_config_t ap_cfg;
    if (esp_wifi_get_config(WIFI_IF_AP, &ap_cfg) == ESP_OK) {
        cJSON_AddStringToObject(ap, "ssid",    (const char *)ap_cfg.ap.ssid);
        cJSON_AddNumberToObject(ap, "channel", ap_cfg.ap.channel);
    }
    if (esp_wifi_get_mac(WIFI_IF_AP, mac) == ESP_OK) {
        snprintf(mac_str, sizeof mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        cJSON_AddStringToObject(ap, "mac", mac_str);
    }
    esp_netif_t *ap_if = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_if && esp_netif_get_ip_info(ap_if, &ip) == ESP_OK) {
        char buf[16];
        ip4_to_str(ip.ip.addr, buf, sizeof buf);
        cJSON_AddStringToObject(ap, "ip", buf);
        int ap_pfx = subnet_mask_prefix_len(ip.netmask.addr);
        if (ap_pfx >= 0) cJSON_AddNumberToObject(ap, "prefix", ap_pfx);
    }
    cJSON_AddNumberToObject(ap, "bytes_in",  (double)netif_hooks_get_ap_bytes_in());
    cJSON_AddNumberToObject(ap, "bytes_out", (double)netif_hooks_get_ap_bytes_out());
    cJSON_AddItemToObject(root, "ap", ap);

    /* Radio-wide TX power (live, post-override). Same value for both
     * STA + AP — kept at the root rather than duplicated under each
     * interface object since it's a single radio setting. */
    {
        int8_t live_pwr = 0;
        if (esp_wifi_get_max_tx_power(&live_pwr) == ESP_OK) {
            cJSON_AddNumberToObject(root, "tx_power", live_pwr);
        }
    }

    /* Tailscale (microlink) — runtime state from tailscale_config.h.
     * tailscale_is_connected() polls microlink + refreshes the cached
     * tunnel_ip; we use its return value over the stale bool global. */
    bool ts_connected = tailscale_is_connected();
    cJSON *ts = cJSON_CreateObject();
    cJSON_AddBoolToObject  (ts, "enabled",   tailscale_enabled != 0);
    cJSON_AddBoolToObject  (ts, "connected", ts_connected);
    if (tailscale_hostname)         cJSON_AddStringToObject(ts, "hostname",         tailscale_hostname);
    if (tailscale_advertise_routes) cJSON_AddStringToObject(ts, "advertise_routes", tailscale_advertise_routes);
    if (tailscale_tunnel_ip) {
        char buf[16];
        ip4_to_str(tailscale_tunnel_ip, buf, sizeof buf);
        cJSON_AddStringToObject(ts, "tunnel_ip", buf);
    }
    if (tailscale_exit_node_ip) {
        char buf[16];
        ip4_hbo_to_str(tailscale_exit_node_ip, buf, sizeof buf);
        cJSON_AddStringToObject(ts, "exit_node_ip", buf);
    }
    /* Peer count summary — full peer table lives at /api/tailscale.
     * While we are still in Registering state, microlink_peer_info_t.online
     * reflects "control-plane echoed this peer" rather than "we have a
     * verified session" — so it briefly reports everyone online + DERP
     * before DISCO settles. Suppress that to avoid lying to the SPA. */
    int online = 0, total = 0;
    struct microlink_s *ml = tailscale_get_microlink();
    if (ml) {
        total = microlink_get_peer_count(ml);
        if (ts_connected) {
            for (int i = 0; i < total; i++) {
                microlink_peer_info_t pi;
                if (microlink_get_peer_info(ml, i, &pi) == ESP_OK && pi.online) online++;
            }
        }
    }
    cJSON_AddNumberToObject(ts, "peers_online", online);
    cJSON_AddNumberToObject(ts, "peers_total",  total);
    /* Auth-failure surface — same field the Tailscale tab reads; the
     * Status page consumes it for the small TS badge in the AP card. */
    if (ml) {
        microlink_diag_t diag;
        if (microlink_get_diag(ml, &diag) == ESP_OK) {
            cJSON_AddNumberToObject(ts, "register_user_id", diag.register_user_id);
            if (diag.register_user_name[0]) {
                cJSON_AddStringToObject(ts, "register_user_name", diag.register_user_name);
            }
            cJSON_AddBoolToObject  (ts, "identity_persistent", diag.identity_persistent);
            cJSON_AddStringToObject(ts, "identity_pubkey_prefix", diag.identity_pubkey_prefix);
        }
    }
    cJSON_AddItemToObject(root, "tailscale", ts);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static const httpd_uri_t uri_status = {
    .uri      = "/api/status",
    .method   = HTTP_GET,
    .handler  = status_handler,
    .user_ctx = NULL,
};

/* Helper: read NVS string and attach to obj if non-empty. Frees the buffer. */
static void add_nvs_string(cJSON *obj, const char *json_key, const char *nvs_key)
{
    char *s = nvs_param_get_str(nvs_key);
    if (s) {
        if (s[0]) cJSON_AddStringToObject(obj, json_key, s);
        free(s);
    }
}

static esp_err_t network_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    /* networks[] — priority-ordered uplink list. Passwords are NEVER
     * serialised. Static IP block is included as a sub-object per
     * network; empty fields mean DHCP for that entry. */
    cJSON *nets = cJSON_CreateArray();
    int count = wifi_networks_count();
    for (int i = 0; i < count; i++) {
        wifi_network_t n;
        if (!wifi_networks_get(i, &n)) continue;
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "ssid", n.ssid);
        cJSON *sip = cJSON_CreateObject();
        if (n.static_ip[0]) cJSON_AddStringToObject(sip, "ip",   n.static_ip);
        if (n.subnet[0])    cJSON_AddStringToObject(sip, "mask", n.subnet);
        if (n.gateway[0])   cJSON_AddStringToObject(sip, "gw",   n.gateway);
        if (n.dns[0])       cJSON_AddStringToObject(sip, "dns",  n.dns);
        cJSON_AddItemToObject(e, "static_ip", sip);
        /* EAP / WPA2-Enterprise block — password is NEVER emitted; identity
         * and username are because the SPA needs them to render the row
         * and the operator should be able to see them at a glance. */
        cJSON *eap = cJSON_CreateObject();
        cJSON_AddNumberToObject(eap, "method", n.eap_method);
        cJSON_AddNumberToObject(eap, "phase2", n.eap_phase2);
        cJSON_AddBoolToObject  (eap, "cert_bundle", n.eap_use_cert_bundle != 0);
        cJSON_AddStringToObject(eap, "identity", n.eap_identity);
        cJSON_AddStringToObject(eap, "username", n.eap_username);
        cJSON_AddBoolToObject  (eap, "has_password", n.eap_password[0] != '\0');
        cJSON_AddItemToObject(e, "eap", eap);
        cJSON_AddItemToArray(nets, e);
    }
    cJSON_AddItemToObject(root, "networks", nets);

    /* Hostname is a device-wide setting (not per-network). */
    add_nvs_string(root, "hostname", "hostname");

    /* STA TTL hop-limit override — 0 means passthrough (no rewrite),
     * non-zero is the value the netif hook stamps on every outgoing
     * IPv4 frame. Device-wide; lives next to hostname in the JSON. */
    {
        uint8_t ttl = netif_hooks_get_sta_ttl();
        cJSON_AddNumberToObject(root, "sta_ttl_override", ttl);
    }

    /* AP — same omit-rule on the password. */
    cJSON *ap = cJSON_CreateObject();
    cJSON_AddBoolToObject(ap, "enabled", wifi_ap_runtime_enabled());
    cJSON_AddBoolToObject(ap, "auto_off_when_connected", wifi_ap_policy_auto_off());
    add_nvs_string(ap, "ssid", "ap_ssid");
    /* Report the LIVE AP channel (read-only in the UI). On the single-radio
     * ESP32-S3 the AP follows the uplink channel automatically, so there is
     * no operator-settable channel — the old `ap_channel` NVS knob is dead
     * and the boot path deliberately ignores it (see wifi_init_softap). */
    {
        wifi_config_t ap_cfg;
        if (esp_wifi_get_config(WIFI_IF_AP, &ap_cfg) == ESP_OK && ap_cfg.ap.channel > 0) {
            cJSON_AddNumberToObject(ap, "channel", ap_cfg.ap.channel);
        }
    }
    /* AP-side IP override — empty / unset means the default 192.168.4.1/24. */
    add_nvs_string(ap, "ip",   "ap_ip");
    add_nvs_string(ap, "mask", "ap_mask");
    add_nvs_string(ap, "dns",  "ap_dns");
    uint8_t ap_hidden = 0;
    nvs_param_get_u8("ap_hidden", &ap_hidden);
    cJSON_AddBoolToObject(ap, "hidden", ap_hidden != 0);

    /* DNS relay state — the "AP clients see ESP as resolver" mode. */
    {
        cJSON *dr = cJSON_CreateObject();
        cJSON_AddBoolToObject(dr, "enabled",  dns_relay_is_enabled());
        cJSON_AddBoolToObject(dr, "healthy",  dns_relay_is_healthy());
        uint32_t up_nbo = dns_relay_get_upstream();
        if (up_nbo) {
            char buf[16];
            snprintf(buf, sizeof buf, "%u.%u.%u.%u",
                     (unsigned)( up_nbo        & 0xff),
                     (unsigned)((up_nbo >>  8) & 0xff),
                     (unsigned)((up_nbo >> 16) & 0xff),
                     (unsigned)((up_nbo >> 24) & 0xff));
            cJSON_AddStringToObject(dr, "upstream", buf);
        } else {
            cJSON_AddStringToObject(dr, "upstream", "");
        }
        cJSON_AddItemToObject(ap, "dns_relay", dr);
    }
    cJSON_AddItemToObject(root, "ap", ap);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static const httpd_uri_t uri_network = {
    .uri      = "/api/network",
    .method   = HTTP_GET,
    .handler  = network_handler,
    .user_ctx = NULL,
};

/* Read up to (buf_size - 1) bytes of the POST body into buf and NUL-
 * terminate. Returns ESP_OK on success or after sending the appropriate
 * error response on failure. */
/* SPIRAM-first body-buffer allocator for the save-handlers' 2-4 KB
 * scratch space. The IDF default CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=
 * 16384 would otherwise route every sub-16K malloc() to the much
 * smaller internal DRAM heap (~346 KB total, ~41 KB free under load).
 * Explicit MALLOC_CAP_SPIRAM keeps the buffers on the 8 MB SPIRAM
 * heap where there's effectively unlimited room. Returns NULL when
 * SPIRAM is exhausted — caller already has the NULL-check path. */
static inline char *malloc_body_buf(size_t n) {
    return heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
}

static esp_err_t recv_body(httpd_req_t *req, char *buf, size_t buf_size, int *out_len)
{
    if (req->content_len <= 0 || (size_t)req->content_len >= buf_size) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body too large or empty");
        return ESP_FAIL;
    }
    int received = 0;
    while (received < req->content_len) {
        int n = httpd_req_recv(req, buf + received, req->content_len - received);
        if (n <= 0) {
            if (n == HTTPD_SOCK_ERR_TIMEOUT) httpd_resp_send_408(req);
            return ESP_FAIL;
        }
        received += n;
    }
    buf[received] = '\0';
    if (out_len) *out_len = received;
    return ESP_OK;
}

/* Write an NVS string key only when the JSON object carries a string
 * value for the given json_key. Empty string is accepted as "clear". */
/* Per-request NVS-error capture. Each save_*_if_present helper sets
 * this when nvs_param_set_* returns non-OK; the surrounding handler
 * checks it before claiming success. Reset at handler entry via
 * nvs_save_errors_reset(). Single-threaded — httpd runs save handlers
 * one at a time on its worker task so a static is fine. */
static struct {
    int       count;
    esp_err_t first_err;
    char      first_key[24];
} s_save_err = { 0 };

static void nvs_save_errors_reset(void) {
    s_save_err.count = 0;
    s_save_err.first_err = ESP_OK;
    s_save_err.first_key[0] = '\0';
}

static void nvs_save_record_err(const char *nvs_key, esp_err_t err) {
    if (err == ESP_OK) return;
    s_save_err.count++;
    if (s_save_err.first_err == ESP_OK) {
        s_save_err.first_err = err;
        strlcpy(s_save_err.first_key, nvs_key, sizeof s_save_err.first_key);
    }
}

/* Shorthand for the handlers that don't carry extra fields in the
 * response: build {ok, [nvs_save_error]} from the accumulated error
 * state and send it. Returns the httpd send-result so the handler
 * can pass it straight through. */
static esp_err_t send_save_response(httpd_req_t *req);

/* Attach `ok` + optional `nvs_save_error` block to a response body
 * cJSON object based on the accumulated per-request error state. The
 * SPA renders nvs_save_error as a red toast — operator sees the
 * silent NVS-out-of-space failure instead of a green "Saved" lie. */
static void nvs_save_errors_attach(cJSON *root) {
    bool ok = (s_save_err.count == 0);
    cJSON_AddBoolToObject(root, "ok", ok);
    if (!ok) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddNumberToObject(e, "count",     s_save_err.count);
        cJSON_AddStringToObject(e, "first_key", s_save_err.first_key);
        cJSON_AddStringToObject(e, "first_err", esp_err_to_name(s_save_err.first_err));
        cJSON_AddItemToObject(root, "nvs_save_error", e);
    }
}

static esp_err_t send_save_response(httpd_req_t *req)
{
    cJSON *resp = cJSON_CreateObject();
    nvs_save_errors_attach(resp);
    char *body = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    httpd_resp_set_type(req, "application/json");
    esp_err_t e = httpd_resp_sendstr(req, body ? body : "{\"ok\":true}");
    free(body);
    return e;
}

/* Thin wrappers that route every NVS write through the per-request
 * error tracker. Replaces direct nvs_param_set_*() calls inside save
 * handlers — operator gets a real toast instead of a green "Saved"
 * lie when an out-of-space write silently fails. */
static void nvs_save_str(const char *key, const char *value) {
    esp_err_t err = nvs_param_set_str(key, value ? value : "");
    if (err != ESP_OK) {
        ESP_LOGE("web_ui", "NVS write FAILED for key=%s (str len=%u): %s",
                 key, (unsigned)(value ? strlen(value) : 0), esp_err_to_name(err));
        nvs_save_record_err(key, err);
    }
}
static void nvs_save_int(const char *key, int32_t value) {
    esp_err_t err = nvs_param_set_int(key, value);
    if (err != ESP_OK) {
        ESP_LOGE("web_ui", "NVS write FAILED for key=%s (int=%ld): %s",
                 key, (long)value, esp_err_to_name(err));
        nvs_save_record_err(key, err);
    }
}
static void nvs_save_u8(const char *key, uint8_t value) {
    esp_err_t err = nvs_param_set_u8(key, value);
    if (err != ESP_OK) {
        ESP_LOGE("web_ui", "NVS write FAILED for key=%s (u8=%u): %s",
                 key, (unsigned)value, esp_err_to_name(err));
        nvs_save_record_err(key, err);
    }
}
static void nvs_save_u32(const char *key, uint32_t value) {
    esp_err_t err = nvs_param_set_u32(key, value);
    if (err != ESP_OK) {
        ESP_LOGE("web_ui", "NVS write FAILED for key=%s (u32=%lu): %s",
                 key, (unsigned long)value, esp_err_to_name(err));
        nvs_save_record_err(key, err);
    }
}

static void save_str_if_present(const cJSON *obj, const char *json_key, const char *nvs_key)
{
    const cJSON *v = cJSON_GetObjectItem(obj, json_key);
    if (cJSON_IsString(v)) nvs_save_str(nvs_key, v->valuestring);
}

static void save_int_if_present(const cJSON *obj, const char *json_key, const char *nvs_key)
{
    const cJSON *v = cJSON_GetObjectItem(obj, json_key);
    if (cJSON_IsNumber(v)) nvs_save_int(nvs_key, (int32_t)v->valuedouble);
}

/* Look up the saved password for an SSID we already know about. Used
 * to honour omit-to-keep when the SPA sends an entry without a
 * password field (or with an empty one). Returns true if found. */
static bool lookup_existing_password(const char *ssid, char *out, size_t out_size)
{
    int count = wifi_networks_count();
    for (int j = 0; j < count; j++) {
        wifi_network_t n;
        if (wifi_networks_get(j, &n) && strcmp(n.ssid, ssid) == 0) {
            strlcpy(out, n.passwd, out_size);
            return true;
        }
    }
    return false;
}

/* Same omit-to-keep pattern for the EAP inner password — we never echo
 * it in the GET response (security), so the SPA can't round-trip it on
 * save. When the POST body omits eap_password (or sends an empty one)
 * AND the SSID already exists with a non-empty stored credential, copy
 * it across; otherwise the operator is providing a fresh credential. */
static bool lookup_existing_eap_password(const char *ssid, char *out, size_t out_size)
{
    int count = wifi_networks_count();
    for (int j = 0; j < count; j++) {
        wifi_network_t n;
        if (wifi_networks_get(j, &n) && strcmp(n.ssid, ssid) == 0) {
            strlcpy(out, n.eap_password, out_size);
            return true;
        }
    }
    return false;
}

/* Count leading 1-bits in a host-byte-order subnet mask. Returns -1
 * if the mask is non-contiguous (which lwIP rejects anyway). */
static int subnet_mask_prefix_len(uint32_t mask_nbo)
{
    uint32_t bits = ntohl(mask_nbo);
    int prefix = 0;
    while (bits & 0x80000000u) { prefix++; bits <<= 1; }
    return bits ? -1 : prefix;
}

/* Read NVS ap_ip / ap_mask (falling back to the firmware default
 * 192.168.4.0/24 when either is empty) and write the resulting CIDR
 * string "a.b.c.d/N" into `out`. Used as a stable identifier of the
 * AP-side subnet for the advertised-routes auto-maintenance. */
static void compute_ap_cidr_from_nvs(char *out, size_t out_size)
{
    const char *def = "192.168.4.0/24";
    char *ip_str   = nvs_param_get_str("ap_ip");
    char *mask_str = nvs_param_get_str("ap_mask");
    ip4_addr_t ip = {0}, mask = {0};
    int prefix = -1;
    if (ip_str && ip_str[0] && mask_str && mask_str[0]
        && ip4addr_aton(ip_str,   &ip)
        && ip4addr_aton(mask_str, &mask)
        && (prefix = subnet_mask_prefix_len(mask.addr)) >= 0) {
        ip4_addr_t net = { .addr = ip.addr & mask.addr };
        char buf[16];
        snprintf(buf, sizeof buf, IPSTR, IP2STR(&net));
        /* Cast to unsigned + %u so GCC's snprintf size analysis sees
         * a 0-32 range instead of the full int(11+sign) worst-case. */
        snprintf(out, out_size, "%s/%u", buf, (unsigned)prefix);
    } else {
        strlcpy(out, def, out_size);
    }
    free(ip_str);
    free(mask_str);
}

/* Inspect ts_advertise_routes against the AP CIDR change and propose
 * what the new value should be, WITHOUT touching NVS. The UI prompts
 * the operator and POSTs the proposed string back via /api/tailscale.
 *
 * Cases:
 *   * Routes empty → propose "new_cidr" (first-time fill).
 *   * Old CIDR in routes → propose old replaced by new.
 *   * Old CIDR absent → propose appending new_cidr.
 *   * new_cidr already there + no old to drop → nothing to propose.
 *
 * Operator-added custom routes are preserved in the proposal.
 * Returns true when a proposal exists; out_proposed_routes is filled
 * only in that case. */
static bool maintain_ap_cidr_in_routes(const char *old_cidr,
                                       const char *new_cidr,
                                       bool *out_offer_add,
                                       char *out_proposed_routes,
                                       size_t proposed_size)
{
    if (out_offer_add) *out_offer_add = false;
    if (!new_cidr || !*new_cidr) return false;

    /* NVS keys are limited to 15 chars — the rest of the code base
     * stores this value under "ts_routes" (matches tailscale_init and
     * tailscale_save_handler), so the auto-maintain has to use the
     * same key or the write lands on a different (and silently
     * rejected) slot. */
    char *routes = nvs_param_get_str("ts_routes");
    const bool routes_empty = !routes || !routes[0];
    const bool unchanged = old_cidr && strcmp(old_cidr, new_cidr) == 0;

    /* First pass: track presence of old / new in the existing routes. */
    bool old_present = false, new_present = false;
    if (!routes_empty) {
        const char *p = routes;
        while (*p) {
            const char *eol = p;
            while (*eol && *eol != '\n' && *eol != '\r') eol++;
            size_t llen = (size_t)(eol - p);
            while (llen > 0 && (p[llen - 1] == ' ' || p[llen - 1] == '\t')) llen--;
            if (llen > 0) {
                if (old_cidr && strlen(old_cidr) == llen
                    && strncmp(p, old_cidr, llen) == 0) old_present = true;
                if (strlen(new_cidr) == llen
                    && strncmp(p, new_cidr, llen) == 0) new_present = true;
            }
            p = eol;
            while (*p == '\n' || *p == '\r') p++;
        }
    }

    /* Build the *proposed* updated routes: drop old_cidr lines when
     * different from new, then ensure new_cidr is present once. */
    char out[512];
    out[0] = '\0';
    bool out_has_new = false;
    if (!routes_empty) {
        const char *p = routes;
        while (*p) {
            const char *eol = p;
            while (*eol && *eol != '\n' && *eol != '\r') eol++;
            size_t llen = (size_t)(eol - p);
            while (llen > 0 && (p[llen - 1] == ' ' || p[llen - 1] == '\t')) llen--;
            if (llen > 0) {
                bool is_old = !unchanged && old_cidr
                              && strlen(old_cidr) == llen
                              && strncmp(p, old_cidr, llen) == 0;
                bool is_new = strlen(new_cidr) == llen
                              && strncmp(p, new_cidr, llen) == 0;
                if (is_new && out_has_new) {
                    /* Duplicate of new_cidr — drop. */
                } else if (!is_old) {
                    if (out[0]) strlcat(out, "\n", sizeof out);
                    strncat(out, p, llen);
                    if (is_new) out_has_new = true;
                }
            }
            p = eol;
            while (*p == '\n' || *p == '\r') p++;
        }
    }
    if (!out_has_new) {
        if (out[0]) strlcat(out, "\n", sizeof out);
        strlcat(out, new_cidr, sizeof out);
    }

    /* If the proposed string matches what's already in NVS, there's
     * nothing to ask — just bail. Otherwise hand the proposed string
     * back to the caller; we never touch NVS ourselves now, the SPA
     * confirms with the operator and POSTs the change via
     * /api/tailscale. */
    bool would_change = !routes || strcmp(routes, out) != 0;
    free(routes);
    if (!would_change) return false;

    if (out_offer_add) *out_offer_add = true;
    if (out_proposed_routes && proposed_size > 0) {
        strlcpy(out_proposed_routes, out, proposed_size);
    }
    ESP_LOGI(TAG, "ts_routes: AP CIDR %s%s%s — offering UI update",
             old_cidr ? old_cidr : "(none)",
             old_cidr ? " → " : "",
             new_cidr);
    (void)old_present; (void)new_present; (void)unchanged;
    return true;
}

static esp_err_t network_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    nvs_save_errors_reset();

    /* Heap-allocate the body buffer — a 4 KB stack-local on the httpd
     * worker overflows the task stack once cJSON parsing piles on. */
    size_t buf_size = 4096;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, buf_size, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }

    /* networks[] — preferred shape. Replaces the WHOLE list. Each entry
     * may omit `password` (or leave it empty) to keep the stored
     * credential — matched by SSID against the existing table. */
    cJSON *nets_j = cJSON_GetObjectItem(root, "networks");
    if (cJSON_IsArray(nets_j)) {
        wifi_network_t arr[WIFI_NETWORKS_MAX];
        memset(arr, 0, sizeof arr);
        int n_in    = cJSON_GetArraySize(nets_j);
        int n_out   = 0;
        for (int i = 0; i < n_in && n_out < WIFI_NETWORKS_MAX; i++) {
            cJSON *e = cJSON_GetArrayItem(nets_j, i);
            if (!cJSON_IsObject(e)) continue;
            cJSON *ssid_j = cJSON_GetObjectItem(e, "ssid");
            if (!cJSON_IsString(ssid_j) || !ssid_j->valuestring[0]) continue;

            wifi_network_t *n = &arr[n_out];
            strlcpy(n->ssid, ssid_j->valuestring, sizeof n->ssid);

            cJSON *pw_j = cJSON_GetObjectItem(e, "password");
            if (cJSON_IsString(pw_j) && pw_j->valuestring[0]) {
                strlcpy(n->passwd, pw_j->valuestring, sizeof n->passwd);
            } else {
                lookup_existing_password(n->ssid, n->passwd, sizeof n->passwd);
            }

            cJSON *sip = cJSON_GetObjectItem(e, "static_ip");
            if (cJSON_IsObject(sip)) {
                const cJSON *ip   = cJSON_GetObjectItem(sip, "ip");
                const cJSON *mask = cJSON_GetObjectItem(sip, "mask");
                const cJSON *gw   = cJSON_GetObjectItem(sip, "gw");
                const cJSON *dns  = cJSON_GetObjectItem(sip, "dns");
                if (cJSON_IsString(ip))   strlcpy(n->static_ip, ip->valuestring,   sizeof n->static_ip);
                if (cJSON_IsString(mask)) strlcpy(n->subnet,    mask->valuestring, sizeof n->subnet);
                if (cJSON_IsString(gw))   strlcpy(n->gateway,   gw->valuestring,   sizeof n->gateway);
                if (cJSON_IsString(dns))  strlcpy(n->dns,       dns->valuestring,  sizeof n->dns);
            }

            /* EAP block — every field is optional. method=0 (DISABLED)
             * keeps the plain-PSK behaviour. eap_password follows the
             * same omit-to-keep pattern as the regular PSK password. */
            cJSON *eap = cJSON_GetObjectItem(e, "eap");
            if (cJSON_IsObject(eap)) {
                const cJSON *m  = cJSON_GetObjectItem(eap, "method");
                const cJSON *p2 = cJSON_GetObjectItem(eap, "phase2");
                const cJSON *cb = cJSON_GetObjectItem(eap, "cert_bundle");
                const cJSON *id = cJSON_GetObjectItem(eap, "identity");
                const cJSON *un = cJSON_GetObjectItem(eap, "username");
                const cJSON *pw = cJSON_GetObjectItem(eap, "password");
                if (cJSON_IsNumber(m))  n->eap_method = (uint8_t)m->valueint;
                if (cJSON_IsNumber(p2)) n->eap_phase2 = (uint8_t)p2->valueint;
                if (cJSON_IsBool(cb))   n->eap_use_cert_bundle = cJSON_IsTrue(cb) ? 1 : 0;
                if (cJSON_IsString(id)) strlcpy(n->eap_identity, id->valuestring, sizeof n->eap_identity);
                if (cJSON_IsString(un)) strlcpy(n->eap_username, un->valuestring, sizeof n->eap_username);
                if (cJSON_IsString(pw) && pw->valuestring[0]) {
                    strlcpy(n->eap_password, pw->valuestring, sizeof n->eap_password);
                } else {
                    lookup_existing_eap_password(n->ssid, n->eap_password, sizeof n->eap_password);
                }
            }

            n->valid = 1;
            n_out++;
        }
        esp_err_t save_err = wifi_networks_set_all(arr, n_out);
        nvs_save_record_err("wifi_nets", save_err);
    }

    /* Backward-compat path: pre-multi-network SPA clients still POST
     * { sta:{ ssid, password, hostname }, static_ip:{...} } — when
     * they do, treat it as a single-entry write to slot 0. */
    cJSON *sta = cJSON_GetObjectItem(root, "sta");
    if (cJSON_IsObject(sta) && !cJSON_IsArray(nets_j)) {
        wifi_network_t one = {0};
        const cJSON *ssid_j = cJSON_GetObjectItem(sta, "ssid");
        if (cJSON_IsString(ssid_j) && ssid_j->valuestring[0]) {
            strlcpy(one.ssid, ssid_j->valuestring, sizeof one.ssid);
            const cJSON *pw_j = cJSON_GetObjectItem(sta, "password");
            if (cJSON_IsString(pw_j) && pw_j->valuestring[0]) {
                strlcpy(one.passwd, pw_j->valuestring, sizeof one.passwd);
            } else {
                lookup_existing_password(one.ssid, one.passwd, sizeof one.passwd);
            }
            cJSON *sip = cJSON_GetObjectItem(root, "static_ip");
            if (cJSON_IsObject(sip)) {
                const cJSON *ip   = cJSON_GetObjectItem(sip, "ip");
                const cJSON *mask = cJSON_GetObjectItem(sip, "mask");
                const cJSON *gw   = cJSON_GetObjectItem(sip, "gw");
                const cJSON *dns  = cJSON_GetObjectItem(sip, "dns");
                if (cJSON_IsString(ip))   strlcpy(one.static_ip, ip->valuestring,   sizeof one.static_ip);
                if (cJSON_IsString(mask)) strlcpy(one.subnet,    mask->valuestring, sizeof one.subnet);
                if (cJSON_IsString(gw))   strlcpy(one.gateway,   gw->valuestring,   sizeof one.gateway);
                if (cJSON_IsString(dns))  strlcpy(one.dns,       dns->valuestring,  sizeof one.dns);
            }
            one.valid = 1;
            esp_err_t save_err = wifi_networks_set_all(&one, 1);
            nvs_save_record_err("wifi_nets", save_err);
        }
        save_str_if_present(sta, "hostname", "hostname");
    }

    /* Hostname (device-wide) and AP block are still saved via the same
     * legacy NVS keys regardless of which write shape the client used. */
    save_str_if_present(root, "hostname", "hostname");

    /* STA TTL override — clamp to 0..255 (u8) and apply LIVE so the
     * change takes effect on the next outgoing IPv4 frame without
     * waiting for a reboot. */
    const cJSON *ttl_j = cJSON_GetObjectItem(root, "sta_ttl_override");
    if (cJSON_IsNumber(ttl_j)) {
        int v = (int)ttl_j->valuedouble;
        if (v < 0)   v = 0;
        if (v > 255) v = 255;
        nvs_save_u8("sta_ttl", (uint8_t)v);
        netif_hooks_set_sta_ttl((uint8_t)v);
    }

    cJSON *ap = cJSON_GetObjectItem(root, "ap");
    if (cJSON_IsObject(ap)) {
        /* Snapshot the AP CIDR BEFORE the save so we can swap it out of
         * ts_advertise_routes after — keeps operator-added manual
         * routes intact and just maintains the auto-AP entry. */
        char old_cidr[32];
        compute_ap_cidr_from_nvs(old_cidr, sizeof old_cidr);

        save_str_if_present(ap, "ssid",     "ap_ssid");
        save_str_if_present(ap, "password", "ap_passwd");
        /* AP channel is auto-managed (follows the uplink on the single radio);
         * the UI exposes it read-only, so there is nothing to persist here. */
        save_str_if_present(ap, "ip",       "ap_ip");
        save_str_if_present(ap, "mask",     "ap_mask");
        save_str_if_present(ap, "dns",      "ap_dns");
        const cJSON *hidden_j = cJSON_GetObjectItem(ap, "hidden");
        if (cJSON_IsBool(hidden_j)) {
            nvs_save_u8("ap_hidden", cJSON_IsTrue(hidden_j) ? 1 : 0);
        }
        const cJSON *auto_off_j = cJSON_GetObjectItem(ap, "auto_off_when_connected");
        if (cJSON_IsBool(auto_off_j)) {
            bool auto_off = cJSON_IsTrue(auto_off_j);
            esp_err_t policy_err = nvs_param_set_u8("ap_auto_off", auto_off ? 1 : 0);
            nvs_save_record_err("ap_auto_off", policy_err);
            if (policy_err == ESP_OK) wifi_ap_policy_set_auto_off(auto_off);
        }

        /* DNS relay — live apply (no restart needed; the forwarder
         * picks up enable/upstream right away, and we re-run
         * softap_set_dns_addr so the DHCP-advertised resolver flips
         * for new lease requests). */
        const cJSON *dr = cJSON_GetObjectItem(ap, "dns_relay");
        bool dns_relay_touched = false;
        if (cJSON_IsObject(dr)) {
            const cJSON *en = cJSON_GetObjectItem(dr, "enabled");
            if (cJSON_IsBool(en)) {
                dns_relay_set_enabled(cJSON_IsTrue(en));
                dns_relay_touched = true;
            }
            const cJSON *up = cJSON_GetObjectItem(dr, "upstream");
            if (cJSON_IsString(up)) {
                uint32_t nbo = 0;
                if (up->valuestring[0]) {
                    ip4_addr_t a;
                    if (ip4addr_aton(up->valuestring, &a)) nbo = a.addr;
                }
                dns_relay_set_upstream(nbo);
                dns_relay_touched = true;
            }
        }
        /* No direct softap_set_dns_addr() here — the dns_relay task
         * fires dns_relay_on_healthy / dns_relay_on_unhealthy on every
         * health transition, and main.c's overrides re-run softap from
         * there. Calling it both places would cause a second DHCP-server
         * restart 12 s after the first and knock newly-leased clients
         * off their fresh DNS-server entry. */
        (void)dns_relay_touched;

        char new_cidr[32];
        char proposed[512];
        proposed[0] = '\0';
        compute_ap_cidr_from_nvs(new_cidr, sizeof new_cidr);
        bool offer = false;
        maintain_ap_cidr_in_routes(old_cidr, new_cidr, &offer,
                                   proposed, sizeof proposed);
        if (offer) {
            /* Stash proposal for the response — the SPA confirms with
             * the operator and POSTs proposed_routes back to
             * /api/tailscale. */
            cJSON_AddStringToObject(root, "_ap_cidr_offer", new_cidr);
            cJSON_AddStringToObject(root, "_proposed_routes", proposed);
        }
    }

    cJSON *resp_json = cJSON_CreateObject();
    /* nvs_save_errors_attach decides ok=true/false based on whether
     * any nvs_save_* call recorded a write failure for this request. */
    nvs_save_errors_attach(resp_json);
    cJSON_AddBoolToObject(resp_json, "restart_required", true);
    cJSON *offer = cJSON_GetObjectItem(root, "_ap_cidr_offer");
    cJSON *proposed = cJSON_GetObjectItem(root, "_proposed_routes");
    if (offer && cJSON_IsString(offer)) {
        cJSON_AddStringToObject(resp_json, "ap_cidr_offer", offer->valuestring);
        if (proposed && cJSON_IsString(proposed)) {
            cJSON_AddStringToObject(resp_json, "proposed_routes", proposed->valuestring);
        }
    }
    char *resp_str = cJSON_PrintUnformatted(resp_json);
    cJSON_Delete(resp_json);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, resp_str ? resp_str : "{\"ok\":true}");
    free(resp_str);
    return err;
}

static const httpd_uri_t uri_network_save = {
    .uri      = "/api/network",
    .method   = HTTP_POST,
    .handler  = network_save_handler,
    .user_ctx = NULL,
};

static const char *wifi_authmode_str(wifi_auth_mode_t m)
{
    switch (m) {
        case WIFI_AUTH_OPEN:            return "open";
        case WIFI_AUTH_WEP:             return "wep";
        case WIFI_AUTH_WPA_PSK:         return "wpa";
        case WIFI_AUTH_WPA2_PSK:        return "wpa2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "wpa/wpa2";
        case WIFI_AUTH_ENTERPRISE:      return "wpa2-ent";
        case WIFI_AUTH_WPA3_PSK:        return "wpa3";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "wpa2/wpa3";
        case WIFI_AUTH_WAPI_PSK:        return "wapi";
        default:                        return "unknown";
    }
}

/* === Async WiFi scan ====================================================
 *
 * The old handler called esp_wifi_scan_start(blocking=true), which held
 * the single httpd-server task in a wait state for ~2 s per call. Any
 * other HTTP request landing in that window queued up and frequently
 * timed out client-side. The SPA-load alone fires 5–7 parallel fetches.
 *
 * Now: the GET /api/network/scan handler just KICKS a scan
 * (non-blocking) and returns immediately. The actual scan result lands
 * in s_scan_cache via the WIFI_EVENT_SCAN_DONE event handler. SPA
 * polls /api/network/scan/result every 500 ms until status == "ready".
 *
 * Handler latency goes from ~2 s to <10 ms; concurrent requests are
 * no longer serialised behind it. */

typedef enum {
    SCAN_IDLE = 0,
    SCAN_RUNNING,
    SCAN_READY,
    SCAN_ERROR,
} scan_state_t;

#define SCAN_CACHE_MAX 32
static volatile scan_state_t s_scan_state    = SCAN_IDLE;
static uint16_t              s_scan_count    = 0;
static wifi_ap_record_t      s_scan_cache[SCAN_CACHE_MAX];
static uint32_t              s_scan_done_ms  = 0;
static SemaphoreHandle_t     s_scan_mutex    = NULL;

static void scan_done_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)data;
    if (base != WIFI_EVENT || id != WIFI_EVENT_SCAN_DONE) return;
    uint16_t n = 0;
    esp_wifi_scan_get_ap_num(&n);
    if (n > SCAN_CACHE_MAX) n = SCAN_CACHE_MAX;
    xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
    if (n) esp_wifi_scan_get_ap_records(&n, s_scan_cache);
    s_scan_count   = n;
    s_scan_done_ms = (uint32_t)(esp_timer_get_time() / 1000);
    s_scan_state   = SCAN_READY;
    xSemaphoreGive(s_scan_mutex);
    wifi_sta_resume_after_scan();
    ESP_LOGI("web_ui", "async scan done: %u networks", (unsigned)n);
}

/* Lazy init — first scan request creates the mutex + subscribes to the
 * SCAN_DONE event. Keeps the init footprint zero until somebody actually
 * uses the scan endpoint. */
static void scan_init_once(void)
{
    if (s_scan_mutex) return;
    s_scan_mutex = xSemaphoreCreateMutex();
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE,
                                scan_done_event, NULL);
}

static esp_err_t network_scan_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    scan_init_once();

    xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
    bool kick = (s_scan_state != SCAN_RUNNING);
    if (kick) s_scan_state = SCAN_RUNNING;
    xSemaphoreGive(s_scan_mutex);

    if (kick) {
        /* Passive scan — listens for beacons, never disassociates the
         * STA (which used to kill the very TCP socket carrying this
         * request back in the synchronous era). */
        wifi_scan_config_t cfg = {
            .ssid = NULL, .bssid = NULL, .channel = 0, .show_hidden = false,
            .scan_type = WIFI_SCAN_TYPE_PASSIVE,
            .scan_time = { .passive = 120 },
        };
        esp_err_t scan_err = esp_wifi_scan_start(&cfg, false);
        if (scan_err == ESP_ERR_WIFI_STATE) {
            /* IDF refuses scans while an association is in progress. Pause
             * the reconnect loop, let DISCONNECTED settle, then retry once.
             * Connected stations normally scan without entering this path. */
            ESP_LOGI("web_ui", "STA is connecting; pausing it for manual scan");
            wifi_sta_pause_for_scan();
            vTaskDelay(pdMS_TO_TICKS(150));
            scan_err = esp_wifi_scan_start(&cfg, false);
        }
        if (scan_err != ESP_OK) {
            wifi_sta_resume_after_scan();
            xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
            s_scan_state = SCAN_ERROR;
            xSemaphoreGive(s_scan_mutex);
            ESP_LOGE("web_ui", "esp_wifi_scan_start failed: %s",
                     esp_err_to_name(scan_err));
            httpd_resp_set_type(req, "application/json");
            char body[112];
            snprintf(body, sizeof body,
                     "{\"status\":\"error\",\"reason\":\"esp_wifi_scan_start: %s\"}",
                     esp_err_to_name(scan_err));
            return httpd_resp_sendstr(req, body);
        }
    }

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"status\":\"scanning\"}");
}

static esp_err_t network_scan_result_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    scan_init_once();

    cJSON *root = cJSON_CreateObject();
    cJSON *arr  = cJSON_CreateArray();

    xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
    scan_state_t st = s_scan_state;
    uint16_t n = (st == SCAN_READY) ? s_scan_count : 0;
    uint32_t age = (st == SCAN_READY)
        ? ((uint32_t)(esp_timer_get_time() / 1000) - s_scan_done_ms)
        : 0;
    for (uint16_t i = 0; i < n; i++) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "ssid",    (const char *)s_scan_cache[i].ssid);
        cJSON_AddNumberToObject(e, "rssi",    s_scan_cache[i].rssi);
        cJSON_AddNumberToObject(e, "channel", s_scan_cache[i].primary);
        cJSON_AddStringToObject(e, "auth",    wifi_authmode_str(s_scan_cache[i].authmode));
        cJSON_AddItemToArray(arr, e);
    }
    xSemaphoreGive(s_scan_mutex);

    const char *status_str = "idle";
    if (st == SCAN_RUNNING) status_str = "scanning";
    else if (st == SCAN_READY) status_str = "ready";
    else if (st == SCAN_ERROR) status_str = "error";
    cJSON_AddStringToObject(root, "status", status_str);
    cJSON_AddNumberToObject(root, "age_ms", age);
    cJSON_AddItemToObject(root, "networks", arr);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static const httpd_uri_t uri_network_scan = {
    .uri      = "/api/network/scan",
    .method   = HTTP_GET,
    .handler  = network_scan_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t uri_network_scan_result = {
    .uri      = "/api/network/scan/result",
    .method   = HTTP_GET,
    .handler  = network_scan_result_handler,
    .user_ctx = NULL,
};

static esp_err_t tools_route_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    /* Parse ?dst=<ipv4>[&src=<ipv4>]. */
    char query[128];
    char dst_str[32];
    char src_str[32] = "";
    if (httpd_req_get_url_query_str(req, query, sizeof query) != ESP_OK
        || httpd_query_key_value(query, "dst", dst_str, sizeof dst_str) != ESP_OK)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing dst");
        return ESP_FAIL;
    }
    /* src is optional — empty means "self-origin" (matches default behaviour). */
    (void)httpd_query_key_value(query, "src", src_str, sizeof src_str);

    ip4_addr_t a;
    if (!ip4addr_aton(dst_str, &a)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid IPv4");
        return ESP_FAIL;
    }
    /* route_explain takes host byte order. */
    uint32_t dst_hbo = lwip_ntohl(a.addr);
    uint32_t src_hbo = 0;
    if (src_str[0]) {
        ip4_addr_t sa;
        if (!ip4addr_aton(src_str, &sa)) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid src IPv4");
            return ESP_FAIL;
        }
        src_hbo = lwip_ntohl(sa.addr);
    }

    char netif_name[16] = {0};
    char reason[160]    = {0};
    route_explain(src_hbo, dst_hbo, netif_name, sizeof netif_name, reason, sizeof reason);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "dst",    dst_str);
    if (src_str[0]) cJSON_AddStringToObject(root, "src", src_str);
    cJSON_AddStringToObject(root, "netif",  netif_name);
    cJSON_AddStringToObject(root, "reason", reason);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static const httpd_uri_t uri_tools_route = {
    .uri      = "/api/tools/route",
    .method   = HTTP_GET,
    .handler  = tools_route_handler,
    .user_ctx = NULL,
};

/* Helper: read a single query param into a stack buffer. Returns ESP_OK
 * on success or NOT_FOUND if the key is missing. */
static esp_err_t tools_query_get(httpd_req_t *req, const char *key,
                                 char *out, size_t out_size)
{
    char qs[160];
    if (httpd_req_get_url_query_str(req, qs, sizeof qs) != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }
    return httpd_query_key_value(qs, key, out, out_size);
}

static esp_err_t tools_ping_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char target[80];
    if (tools_query_get(req, "target", target, sizeof target) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing target");
        return ESP_FAIL;
    }
    char count_str[8];
    int count = 4;
    if (tools_query_get(req, "count", count_str, sizeof count_str) == ESP_OK) {
        count = atoi(count_str);
        if (count < 1)  count = 1;
        if (count > 10) count = 10;
    }

    /* net_diag writes plain text into the buffer; we expose it as text/plain
     * so the SPA can render it in a <pre>. */
    size_t buf_size = 2048;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    buf[0] = '\0';

    net_diag_ping(target, count, 1000, buf, buf_size);

    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    esp_err_t err = httpd_resp_sendstr(req, buf);
    free(buf);
    return err;
}

static esp_err_t tools_trace_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char target[80];
    if (tools_query_get(req, "target", target, sizeof target) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing target");
        return ESP_FAIL;
    }
    char hops_str[8];
    int max_hops = 16;
    if (tools_query_get(req, "max_hops", hops_str, sizeof hops_str) == ESP_OK) {
        max_hops = atoi(hops_str);
        if (max_hops < 1)  max_hops = 1;
        if (max_hops > 30) max_hops = 30;
    }

    size_t buf_size = 2048;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    buf[0] = '\0';

    net_diag_trace(target, max_hops, 1500, buf, buf_size);

    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    esp_err_t err = httpd_resp_sendstr(req, buf);
    free(buf);
    return err;
}

static const httpd_uri_t uri_tools_ping = {
    .uri = "/api/tools/ping",  .method = HTTP_GET, .handler = tools_ping_handler,
};
static const httpd_uri_t uri_tools_trace = {
    .uri = "/api/tools/trace", .method = HTTP_GET, .handler = tools_trace_handler,
};

static esp_err_t firewall_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root  = cJSON_CreateObject();
    cJSON *lists = cJSON_CreateArray();

    acl_lock();
    for (int i = 0; i < MAX_ACL_LISTS; i++) {
        cJSON *list = cJSON_CreateObject();
        cJSON_AddNumberToObject(list, "index", i);
        cJSON_AddStringToObject(list, "name",  acl_get_name(i));
        cJSON_AddStringToObject(list, "desc",  acl_get_desc(i));

        acl_stats_t *st = acl_get_stats(i);
        cJSON *stats = cJSON_CreateObject();
        cJSON_AddNumberToObject(stats, "allowed", st ? st->packets_allowed : 0);
        cJSON_AddNumberToObject(stats, "denied",  st ? st->packets_denied  : 0);
        cJSON_AddNumberToObject(stats, "nomatch", st ? st->packets_nomatch : 0);
        cJSON_AddItemToObject(list, "stats", stats);

        cJSON *rules = cJSON_CreateArray();
        acl_entry_t *entries = acl_get_rules(i);
        if (entries) {
            for (int j = 0; j < MAX_ACL_ENTRIES; j++) {
                if (!entries[j].valid) break;   /* list is compacted */

                cJSON *r = cJSON_CreateObject();
                cJSON_AddNumberToObject(r, "index", j);
                char buf[28];
                acl_format_ip(entries[j].src,  entries[j].s_mask, buf, sizeof buf);
                cJSON_AddStringToObject(r, "src",  buf);
                acl_format_ip(entries[j].dest, entries[j].d_mask, buf, sizeof buf);
                cJSON_AddStringToObject(r, "dest", buf);
                cJSON_AddNumberToObject(r, "proto",  entries[j].proto);
                cJSON_AddNumberToObject(r, "s_port", entries[j].s_port);
                cJSON_AddNumberToObject(r, "d_port", entries[j].d_port);
                cJSON_AddNumberToObject(r, "action", entries[j].allow & 0x01);
                cJSON_AddNumberToObject(r, "hits",   entries[j].hit_count);
                cJSON_AddItemToArray(rules, r);
            }
        }
        cJSON_AddItemToObject(list, "rules", rules);
        cJSON_AddItemToArray(lists, list);
    }
    acl_unlock();

    cJSON_AddItemToObject(root, "lists", lists);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static const httpd_uri_t uri_firewall = {
    .uri      = "/api/firewall",
    .method   = HTTP_GET,
    .handler  = firewall_handler,
    .user_ctx = NULL,
};

/* Helper: pull a uint8 ACL list index out of the JSON body. */
static int parse_acl_index(const cJSON *body)
{
    const cJSON *idx = body ? cJSON_GetObjectItem(body, "acl") : NULL;
    if (!cJSON_IsNumber(idx)) return -1;
    int n = (int)idx->valuedouble;
    if (n < 0 || n >= MAX_ACL_LISTS) return -1;
    return n;
}

static esp_err_t firewall_add_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char body_buf[512];
    if (recv_body(req, body_buf, sizeof body_buf, NULL) != ESP_OK) return ESP_FAIL;

    cJSON *body = cJSON_Parse(body_buf);
    int acl_no = parse_acl_index(body);
    const cJSON *src_j   = body ? cJSON_GetObjectItem(body, "src")   : NULL;
    const cJSON *dest_j  = body ? cJSON_GetObjectItem(body, "dest")  : NULL;
    if (acl_no < 0 || !cJSON_IsString(src_j) || !cJSON_IsString(dest_j)) {
        cJSON_Delete(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing acl/src/dest");
        return ESP_FAIL;
    }

    uint32_t src, s_mask, dest, d_mask;
    if (!acl_parse_ip(src_j->valuestring,  &src,  &s_mask) ||
        !acl_parse_ip(dest_j->valuestring, &dest, &d_mask)) {
        cJSON_Delete(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad src/dest CIDR");
        return ESP_FAIL;
    }

    /* Optional fields default to "any". */
    const cJSON *pr = cJSON_GetObjectItem(body, "proto");
    const cJSON *sp = cJSON_GetObjectItem(body, "s_port");
    const cJSON *dp = cJSON_GetObjectItem(body, "d_port");
    const cJSON *ac = cJSON_GetObjectItem(body, "action");

    uint8_t  proto  = cJSON_IsNumber(pr) ? (uint8_t) pr->valuedouble : 0;
    uint16_t s_port = cJSON_IsNumber(sp) ? (uint16_t)sp->valuedouble : 0;
    uint16_t d_port = cJSON_IsNumber(dp) ? (uint16_t)dp->valuedouble : 0;
    uint8_t  allow  = cJSON_IsNumber(ac) ? (uint8_t) ac->valuedouble : ACL_ALLOW;

    bool ok = acl_add((uint8_t)acl_no, src, s_mask, dest, d_mask,
                      proto, s_port, d_port, allow);
    cJSON_Delete(body);
    if (!ok) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "list full");
        return ESP_FAIL;
    }
    nvs_save_errors_reset();
    esp_err_t serr = save_acl_rules();
    if (serr != ESP_OK) nvs_save_record_err("acl", serr);
    return send_save_response(req);
}

static esp_err_t firewall_delete_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char body_buf[128];
    if (recv_body(req, body_buf, sizeof body_buf, NULL) != ESP_OK) return ESP_FAIL;

    cJSON *body = cJSON_Parse(body_buf);
    int acl_no = parse_acl_index(body);
    const cJSON *rule_j = body ? cJSON_GetObjectItem(body, "index") : NULL;
    if (acl_no < 0 || !cJSON_IsNumber(rule_j)) {
        cJSON_Delete(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing acl/index");
        return ESP_FAIL;
    }
    int rule_idx = (int)rule_j->valuedouble;
    cJSON_Delete(body);

    if (rule_idx < 0 || rule_idx >= MAX_ACL_ENTRIES
        || !acl_delete((uint8_t)acl_no, (uint8_t)rule_idx)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid index");
        return ESP_FAIL;
    }
    nvs_save_errors_reset();
    esp_err_t serr = save_acl_rules();
    if (serr != ESP_OK) nvs_save_record_err("acl", serr);
    return send_save_response(req);
}

static esp_err_t firewall_clear_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char body_buf[128];
    if (recv_body(req, body_buf, sizeof body_buf, NULL) != ESP_OK) return ESP_FAIL;

    cJSON *body = cJSON_Parse(body_buf);
    int acl_no = parse_acl_index(body);
    cJSON_Delete(body);
    if (acl_no < 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing acl");
        return ESP_FAIL;
    }

    acl_clear((uint8_t)acl_no);
    nvs_save_errors_reset();
    esp_err_t serr = save_acl_rules();
    if (serr != ESP_OK) nvs_save_record_err("acl", serr);
    return send_save_response(req);
}

static const httpd_uri_t uri_firewall_add = {
    .uri = "/api/firewall/add",    .method = HTTP_POST, .handler = firewall_add_handler,
};
static const httpd_uri_t uri_firewall_delete = {
    .uri = "/api/firewall/delete", .method = HTTP_POST, .handler = firewall_delete_handler,
};
static const httpd_uri_t uri_firewall_clear = {
    .uri = "/api/firewall/clear",  .method = HTTP_POST, .handler = firewall_clear_handler,
};

/* ───────────────────────── DHCP reservations ────────────────────────
 * GET  /api/dhcp/reservations  → { reservations: [{mac,ip,name}...], max }
 * POST /api/dhcp/reservations  → body { reservations: [...] } replaces the
 *                                whole table. Empty/invalid entries are
 *                                silently dropped. */

static bool parse_mac_str(const char *s, uint8_t out[6])
{
    if (!s) return false;
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6
        && sscanf(s, "%x-%x-%x-%x-%x-%x",
                  &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff) return false;
        out[i] = (uint8_t)v[i];
    }
    return true;
}

/* GET /api/wol — saved Wake-on-LAN address book. */
static esp_err_t wol_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    if (!root || !arr) {
        cJSON_Delete(root);
        cJSON_Delete(arr);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    int count = wol_count();
    for (int i = 0; i < count; i++) {
        wol_device_t device;
        if (!wol_get(i, &device)) continue;
        char mac[18];
        wol_format_mac(device.mac, mac);
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "name", device.name);
        cJSON_AddStringToObject(entry, "mac", mac);
        cJSON_AddStringToObject(entry, "broadcast", device.broadcast);
        cJSON_AddNumberToObject(entry, "port", device.port ? device.port : 9);
        cJSON_AddItemToArray(arr, entry);
    }
    cJSON_AddNumberToObject(root, "max", WOL_MAX_DEVICES);
    cJSON_AddItemToObject(root, "devices", arr);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

/* Secret export/import is deliberately stricter than the rest of the UI.
 * When the operator disables the web password, ordinary configuration is
 * public by choice, but saved WiFi/EAP/MQTT credentials and the Tailscale
 * auth key must never become anonymously downloadable. */
static esp_err_t require_password_session(httpd_req_t *req)
{
    if (is_web_password_set() && session_find_for_req(req) >= 0) return ESP_OK;
    httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                        "enable web authentication and sign in to access secrets");
    return ESP_FAIL;
}

/* POST /api/wol — atomically replace the address book. */
static esp_err_t wol_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    const size_t buf_size = 4096;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, buf_size, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }
    cJSON *arr = cJSON_GetObjectItem(root, "devices");
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing devices[]");
        return ESP_FAIL;
    }

    wol_device_t devices[WOL_MAX_DEVICES];
    memset(devices, 0, sizeof devices);
    int input_count = cJSON_GetArraySize(arr);
    if (input_count > WOL_MAX_DEVICES) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "too many WOL devices");
        return ESP_FAIL;
    }
    int count = 0;
    for (int i = 0; i < input_count; i++) {
        cJSON *entry = cJSON_GetArrayItem(arr, i);
        cJSON *mac_j = cJSON_GetObjectItem(entry, "mac");
        if (!cJSON_IsObject(entry) || !cJSON_IsString(mac_j)
            || !wol_parse_mac(mac_j->valuestring, devices[count].mac)) {
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid WOL MAC address");
            return ESP_FAIL;
        }
        cJSON *name_j = cJSON_GetObjectItem(entry, "name");
        cJSON *broadcast_j = cJSON_GetObjectItem(entry, "broadcast");
        cJSON *port_j = cJSON_GetObjectItem(entry, "port");
        if (cJSON_IsString(name_j)) strlcpy(devices[count].name, name_j->valuestring,
                                           sizeof devices[count].name);
        if (cJSON_IsString(broadcast_j) && broadcast_j->valuestring[0]) {
            ip4_addr_t parsed;
            if (!ip4addr_aton(broadcast_j->valuestring, &parsed)) {
                cJSON_Delete(root);
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid broadcast address");
                return ESP_FAIL;
            }
            strlcpy(devices[count].broadcast, broadcast_j->valuestring,
                    sizeof devices[count].broadcast);
        }
        int port = cJSON_IsNumber(port_j) ? port_j->valueint : 9;
        if (port < 1 || port > 65535) {
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid WOL UDP port");
            return ESP_FAIL;
        }
        devices[count].port = (uint16_t)port;
        devices[count].valid = 1;
        count++;
    }
    cJSON_Delete(root);

    esp_err_t err = wol_set_all(devices, count);
    if (err == ESP_OK) mqtt_integration_wol_changed();
    httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"NVS write failed\"}");
    }
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

/* POST /api/wol/send — send to a saved index or saved MAC. */
static esp_err_t wol_send_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    char buf[160];
    if (recv_body(req, buf, sizeof buf, NULL) != ESP_OK) return ESP_FAIL;
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }
    cJSON *index_j = cJSON_GetObjectItem(root, "index");
    cJSON *mac_j = cJSON_GetObjectItem(root, "mac");
    esp_err_t err = ESP_ERR_INVALID_ARG;
    if (cJSON_IsNumber(index_j)) err = wol_send_index(index_j->valueint);
    else if (cJSON_IsString(mac_j)) err = wol_send_saved_mac_text(mac_j->valuestring);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) {
        httpd_resp_set_status(req, err == ESP_ERR_NOT_FOUND
                                  ? "404 Not Found" : "503 Service Unavailable");
        char response[96];
        snprintf(response, sizeof response,
                 "{\"ok\":false,\"error\":\"%s\"}", esp_err_to_name(err));
        return httpd_resp_sendstr(req, response);
    }
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_wol = {
    .uri = "/api/wol", .method = HTTP_GET, .handler = wol_handler,
};
static const httpd_uri_t uri_wol_save = {
    .uri = "/api/wol", .method = HTTP_POST, .handler = wol_save_handler,
};
static const httpd_uri_t uri_wol_send = {
    .uri = "/api/wol/send", .method = HTTP_POST, .handler = wol_send_handler,
};

/* GET/POST /api/mqtt — broker settings and live connection state. */
static esp_err_t mqtt_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    mqtt_integration_config_t config;
    mqtt_integration_get_config(&config);
    cJSON *root = cJSON_CreateObject();
    if (!root) { httpd_resp_send_500(req); return ESP_FAIL; }
    cJSON_AddBoolToObject(root, "enabled", config.enabled);
    cJSON_AddBoolToObject(root, "connected", mqtt_integration_connected());
    cJSON_AddStringToObject(root, "uri", config.uri);
    cJSON_AddStringToObject(root, "username", config.username);
    cJSON_AddBoolToObject(root, "has_password", config.password[0] != '\0');
    cJSON_AddStringToObject(root, "base_topic", config.base_topic);
    cJSON_AddBoolToObject(root, "home_assistant_discovery",
                          config.home_assistant_discovery);
    cJSON_AddStringToObject(root, "discovery_prefix", config.discovery_prefix);
    cJSON_AddNumberToObject(root, "interval_seconds", config.interval_seconds);
    cJSON_AddBoolToObject(root, "broker_watchdog_enabled",
                          config.broker_watchdog_enabled);
    cJSON_AddNumberToObject(root, "broker_watchdog_timeout_seconds",
                            config.broker_watchdog_timeout_seconds);
    cJSON_AddStringToObject(root, "broker_watchdog_wol_mac",
                            config.broker_watchdog_wol_mac);
    cJSON_AddBoolToObject(root, "broker_watchdog_triggered",
                          mqtt_integration_watchdog_triggered());
    cJSON_AddNumberToObject(root, "broker_watchdog_wake_count",
                            mqtt_integration_watchdog_wake_count());
    cJSON_AddNumberToObject(root, "broker_silence_seconds",
                            mqtt_integration_broker_silence_seconds());
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static esp_err_t mqtt_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    char *buf = malloc_body_buf(3072);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, 3072, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }
    mqtt_integration_config_t config;
    mqtt_integration_get_config(&config);
    cJSON *item;
#define COPY_MQTT_STRING(json_key, field) do { \
        item = cJSON_GetObjectItem(root, (json_key)); \
        if (cJSON_IsString(item)) strlcpy((field), item->valuestring, sizeof(field)); \
    } while (0)
    COPY_MQTT_STRING("uri", config.uri);
    COPY_MQTT_STRING("username", config.username);
    COPY_MQTT_STRING("base_topic", config.base_topic);
    COPY_MQTT_STRING("discovery_prefix", config.discovery_prefix);
    COPY_MQTT_STRING("broker_watchdog_wol_mac", config.broker_watchdog_wol_mac);
    item = cJSON_GetObjectItem(root, "password");
    if (cJSON_IsString(item) && item->valuestring[0])
        strlcpy(config.password, item->valuestring, sizeof config.password);
    item = cJSON_GetObjectItem(root, "clear_password");
    if (cJSON_IsTrue(item)) config.password[0] = '\0';
#undef COPY_MQTT_STRING
    item = cJSON_GetObjectItem(root, "enabled");
    if (cJSON_IsBool(item)) config.enabled = cJSON_IsTrue(item);
    item = cJSON_GetObjectItem(root, "home_assistant_discovery");
    if (cJSON_IsBool(item)) config.home_assistant_discovery = cJSON_IsTrue(item);
    item = cJSON_GetObjectItem(root, "interval_seconds");
    if (cJSON_IsNumber(item)) config.interval_seconds = (uint16_t)item->valueint;
    item = cJSON_GetObjectItem(root, "broker_watchdog_enabled");
    if (cJSON_IsBool(item)) config.broker_watchdog_enabled = cJSON_IsTrue(item);
    item = cJSON_GetObjectItem(root, "broker_watchdog_timeout_seconds");
    if (cJSON_IsNumber(item)) config.broker_watchdog_timeout_seconds = (uint32_t)item->valuedouble;
    cJSON_Delete(root);

    bool valid_uri = !config.enabled
        || ((strncmp(config.uri, "mqtt://", 7) == 0
             || strncmp(config.uri, "mqtts://", 8) == 0
             || strncmp(config.uri, "ws://", 5) == 0
             || strncmp(config.uri, "wss://", 6) == 0)
            /* Credentials belong in the separate write-only fields. Apart
             * from confusing the URI parser, user-info here would be echoed
             * by diagnostics and logs as part of the broker URI. */
            && strpbrk(config.uri, "@\r\n\t ") == NULL);
    if (!valid_uri || !config.base_topic[0] || strchr(config.base_topic, '#')
        || strchr(config.base_topic, '+') || config.interval_seconds < 5
        || config.interval_seconds > 3600
        || config.broker_watchdog_timeout_seconds < 30
        || config.broker_watchdog_timeout_seconds > 86400
        || (config.broker_watchdog_enabled
            && (!config.enabled || !config.broker_watchdog_wol_mac[0]))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid MQTT settings");
        return ESP_FAIL;
    }
    if (config.broker_watchdog_wol_mac[0]) {
        uint8_t mac[6];
        if (!wol_parse_mac(config.broker_watchdog_wol_mac, mac)) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid watchdog WOL MAC");
            return ESP_FAIL;
        }
        wol_format_mac(mac, config.broker_watchdog_wol_mac);
    }
    esp_err_t err = mqtt_integration_set_config(&config);
    httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"save failed\"}");
    }
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_mqtt = {
    .uri = "/api/mqtt", .method = HTTP_GET, .handler = mqtt_handler,
};
static const httpd_uri_t uri_mqtt_save = {
    .uri = "/api/mqtt", .method = HTTP_POST, .handler = mqtt_save_handler,
};
static esp_err_t mqtt_publish_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    mqtt_integration_publish_now();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, mqtt_integration_connected()
                                   ? "{\"ok\":true}" : "{\"ok\":false,\"connected\":false}");
}
static const httpd_uri_t uri_mqtt_publish = {
    .uri = "/api/mqtt/publish", .method = HTTP_POST, .handler = mqtt_publish_handler,
};

/* GET/POST /api/ntfy — token is write-only and never leaves the device. */
static esp_err_t ntfy_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    ntfy_integration_config_t c;
    ntfy_integration_status_t st;
    ntfy_integration_get_config(&c);
    ntfy_integration_get_status(&st);
    cJSON *root = cJSON_CreateObject();
    if (!root) { httpd_resp_send_500(req); return ESP_FAIL; }
    cJSON_AddBoolToObject(root, "enabled", c.enabled);
    cJSON_AddStringToObject(root, "server", c.server);
    cJSON_AddStringToObject(root, "topic", c.topic);
    cJSON_AddBoolToObject(root, "has_token", c.token[0] != '\0');
    cJSON_AddBoolToObject(root, "tailscale_alerts", c.tailscale_alerts);
    cJSON_AddBoolToObject(root, "commands_enabled", c.commands_enabled);
    cJSON_AddBoolToObject(root, "commands_only_when_tailscale_down",
                          c.commands_only_when_tailscale_down);
    cJSON_AddBoolToObject(root, "allow_direct_mac", c.allow_direct_mac);
    cJSON_AddBoolToObject(root, "info_enabled", c.info_enabled);
    cJSON_AddBoolToObject(root, "info_include_details", c.info_include_details);
    cJSON_AddNumberToObject(root, "failure_delay_seconds", c.failure_delay_seconds);
    cJSON_AddNumberToObject(root, "poll_interval_seconds", c.poll_interval_seconds);
    cJSON_AddBoolToObject(root, "last_publish_ok", st.last_publish_ok);
    cJSON_AddNumberToObject(root, "alerts_sent", st.alerts_sent);
    cJSON_AddNumberToObject(root, "commands_received", st.commands_received);
    cJSON_AddNumberToObject(root, "command_errors", st.command_errors);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static esp_err_t ntfy_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    char *buf = malloc_body_buf(3072);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, 3072, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON"); return ESP_FAIL; }
    ntfy_integration_config_t c;
    ntfy_integration_get_config(&c);
    cJSON *item;
#define NTFY_STRING(key, field) do { item=cJSON_GetObjectItem(root,(key)); \
    if (cJSON_IsString(item)) strlcpy((field),item->valuestring,sizeof(field)); } while(0)
#define NTFY_BOOL(key, field) do { item=cJSON_GetObjectItem(root,(key)); \
    if (cJSON_IsBool(item)) (field)=cJSON_IsTrue(item); } while(0)
    NTFY_STRING("server", c.server); NTFY_STRING("topic", c.topic);
    item = cJSON_GetObjectItem(root, "token");
    if (cJSON_IsString(item) && item->valuestring[0]) strlcpy(c.token, item->valuestring, sizeof c.token);
    if (cJSON_IsTrue(cJSON_GetObjectItem(root, "clear_token"))) c.token[0] = '\0';
    NTFY_BOOL("enabled", c.enabled); NTFY_BOOL("tailscale_alerts", c.tailscale_alerts);
    NTFY_BOOL("commands_enabled", c.commands_enabled);
    NTFY_BOOL("commands_only_when_tailscale_down", c.commands_only_when_tailscale_down);
    NTFY_BOOL("allow_direct_mac", c.allow_direct_mac); NTFY_BOOL("info_enabled", c.info_enabled);
    NTFY_BOOL("info_include_details", c.info_include_details);
#undef NTFY_STRING
#undef NTFY_BOOL
    item=cJSON_GetObjectItem(root,"failure_delay_seconds");
    if(cJSON_IsNumber(item)) c.failure_delay_seconds=(uint16_t)item->valueint;
    item=cJSON_GetObjectItem(root,"poll_interval_seconds");
    if(cJSON_IsNumber(item)) c.poll_interval_seconds=(uint16_t)item->valueint;
    cJSON_Delete(root);
    esp_err_t err = ntfy_integration_set_config(&c);
    if (err != ESP_OK) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid ntfy settings"); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t ntfy_test_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    esp_err_t err = ntfy_integration_send_test();
    httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) httpd_resp_set_status(req, "503 Service Unavailable");
    return httpd_resp_sendstr(req, err == ESP_OK ? "{\"ok\":true}" : "{\"ok\":false}");
}

static const httpd_uri_t uri_ntfy = {
    .uri="/api/ntfy",.method=HTTP_GET,.handler=ntfy_handler };
static const httpd_uri_t uri_ntfy_save = {
    .uri="/api/ntfy",.method=HTTP_POST,.handler=ntfy_save_handler };
static const httpd_uri_t uri_ntfy_test = {
    .uri="/api/ntfy/test",.method=HTTP_POST,.handler=ntfy_test_handler };

static esp_err_t dhcp_reservations_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    cJSON *arr  = cJSON_CreateArray();
    if (!root || !arr) {
        cJSON_Delete(root);
        cJSON_Delete(arr);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    for (int i = 0; i < DHCP_RESERVATIONS_MAX; i++) {
        dhcp_reservation_t r;
        if (!dhcp_reservations_get(i, &r)) continue;

        char mac_str[18];
        snprintf(mac_str, sizeof mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                 r.mac[0], r.mac[1], r.mac[2], r.mac[3], r.mac[4], r.mac[5]);

        ip4_addr_t a = { .addr = r.ip };
        char ip_str[16];
        snprintf(ip_str, sizeof ip_str, IPSTR, IP2STR(&a));

        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "mac",  mac_str);
        cJSON_AddStringToObject(e, "ip",   ip_str);
        cJSON_AddStringToObject(e, "name", r.name);
        cJSON_AddItemToArray(arr, e);
    }
    cJSON_AddItemToObject(root, "reservations", arr);
    cJSON_AddNumberToObject(root, "max", DHCP_RESERVATIONS_MAX);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static esp_err_t dhcp_reservations_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    /* Heap buffer — the table can grow up to 16 entries and cJSON
     * parsing piles on top of the httpd worker stack. */
    size_t buf_size = 4096;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, buf_size, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }

    cJSON *arr = cJSON_GetObjectItem(root, "reservations");
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing reservations[]");
        return ESP_FAIL;
    }

    dhcp_reservation_t out[DHCP_RESERVATIONS_MAX];
    memset(out, 0, sizeof out);
    int n_in  = cJSON_GetArraySize(arr);
    int n_out = 0;

    for (int i = 0; i < n_in && n_out < DHCP_RESERVATIONS_MAX; i++) {
        cJSON *e = cJSON_GetArrayItem(arr, i);
        if (!cJSON_IsObject(e)) continue;

        cJSON *mac_j = cJSON_GetObjectItem(e, "mac");
        cJSON *ip_j  = cJSON_GetObjectItem(e, "ip");
        if (!cJSON_IsString(mac_j) || !cJSON_IsString(ip_j)) continue;

        dhcp_reservation_t *r = &out[n_out];
        if (!parse_mac_str(mac_j->valuestring, r->mac)) continue;

        ip4_addr_t a;
        if (!ip4addr_aton(ip_j->valuestring, &a) || a.addr == 0) continue;
        r->ip = a.addr;

        cJSON *name_j = cJSON_GetObjectItem(e, "name");
        if (cJSON_IsString(name_j)) {
            strlcpy(r->name, name_j->valuestring, sizeof r->name);
        }
        r->valid = 1;
        n_out++;
    }
    cJSON_Delete(root);

    esp_err_t err = dhcp_reservations_set_all(out, n_out);

    /* Reservations apply on the next DHCP REQUEST — the table is hot-
     * reloaded into the lookup cache, so no reboot is required. Clients
     * already holding a non-matching lease keep it until expiry. */
    nvs_save_errors_reset();
    if (err != ESP_OK) nvs_save_record_err("dhcp_res", err);
    return send_save_response(req);
}

static const httpd_uri_t uri_dhcp_reservations = {
    .uri      = "/api/dhcp/reservations",
    .method   = HTTP_GET,
    .handler  = dhcp_reservations_handler,
    .user_ctx = NULL,
};
static const httpd_uri_t uri_dhcp_reservations_save = {
    .uri      = "/api/dhcp/reservations",
    .method   = HTTP_POST,
    .handler  = dhcp_reservations_save_handler,
    .user_ctx = NULL,
};

/* GET /api/dhcp/leases — { clients:[{mac,ip,hostname,name,rssi,reserved}...],
 *                          leases :[{mac,ip,hostname,lease_remaining}...] }
 *
 * `clients` is the current AP station list, joined with the active-lease
 * table for IP + hostname, then overlaid with the reservation name when
 * one exists for that MAC.
 *
 * `leases` is the raw active-lease snapshot — a station that has fallen
 * off the air still appears here until its lease expires. */

#define DHCP_LEASES_MAX_REPORT 16

static esp_err_t dhcp_leases_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    /* Pull both views first so we can cross-reference them in one pass. */
    dhcp_lease_info_t leases[DHCP_LEASES_MAX_REPORT];
    int lease_count = dhcps_get_active_leases(leases, DHCP_LEASES_MAX_REPORT);

    wifi_sta_list_t sta_list;
    memset(&sta_list, 0, sizeof sta_list);
    esp_wifi_ap_get_sta_list(&sta_list);

    cJSON *root         = cJSON_CreateObject();
    cJSON *clients_arr  = cJSON_CreateArray();
    cJSON *leases_arr   = cJSON_CreateArray();
    if (!root || !clients_arr || !leases_arr) {
        cJSON_Delete(root); cJSON_Delete(clients_arr); cJSON_Delete(leases_arr);
        httpd_resp_send_500(req); return ESP_FAIL;
    }

    /* Connected stations — for each, find its lease and reservation. */
    for (int i = 0; i < sta_list.num; i++) {
        wifi_sta_info_t *sta = &sta_list.sta[i];

        char mac_str[18];
        snprintf(mac_str, sizeof mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                 sta->mac[0], sta->mac[1], sta->mac[2],
                 sta->mac[3], sta->mac[4], sta->mac[5]);

        const char *hostname = "";
        uint32_t    ip_nbo   = 0;
        for (int j = 0; j < lease_count; j++) {
            if (memcmp(leases[j].mac, sta->mac, 6) == 0) {
                hostname = leases[j].hostname;
                ip_nbo   = leases[j].ip;
                break;
            }
        }

        const char *res_name = dhcp_reservations_lookup_name_by_mac(sta->mac);
        bool reserved        = dhcp_reservations_lookup(sta->mac) != 0;

        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "mac", mac_str);
        if (ip_nbo) {
            ip4_addr_t a = { .addr = ip_nbo };
            char ip_str[16];
            snprintf(ip_str, sizeof ip_str, IPSTR, IP2STR(&a));
            cJSON_AddStringToObject(e, "ip", ip_str);
        } else {
            cJSON_AddStringToObject(e, "ip", "");
        }
        cJSON_AddStringToObject(e, "hostname", hostname);
        cJSON_AddStringToObject(e, "name",     res_name ? res_name : "");
        cJSON_AddNumberToObject(e, "rssi",     sta->rssi);
        cJSON_AddBoolToObject  (e, "reserved", reserved);
        cJSON_AddItemToArray(clients_arr, e);
    }

    /* Raw lease snapshot. */
    for (int j = 0; j < lease_count; j++) {
        char mac_str[18];
        snprintf(mac_str, sizeof mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                 leases[j].mac[0], leases[j].mac[1], leases[j].mac[2],
                 leases[j].mac[3], leases[j].mac[4], leases[j].mac[5]);

        ip4_addr_t a = { .addr = leases[j].ip };
        char ip_str[16];
        snprintf(ip_str, sizeof ip_str, IPSTR, IP2STR(&a));

        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "mac",      mac_str);
        cJSON_AddStringToObject(e, "ip",       ip_str);
        cJSON_AddStringToObject(e, "hostname", leases[j].hostname);
        cJSON_AddNumberToObject(e, "lease_remaining", leases[j].lease_timer);
        cJSON_AddItemToArray(leases_arr, e);
    }

    cJSON_AddItemToObject(root, "clients", clients_arr);
    cJSON_AddItemToObject(root, "leases",  leases_arr);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static const httpd_uri_t uri_dhcp_leases = {
    .uri      = "/api/dhcp/leases",
    .method   = HTTP_GET,
    .handler  = dhcp_leases_handler,
    .user_ctx = NULL,
};

/* POST /api/dhcp/kick — body { "mac": "aa:bb:cc:dd:ee:ff" } — deauths
 * the station so it must re-associate, which also triggers a fresh DHCP
 * exchange. Useful right after changing a reservation: clients normally
 * hold their current lease until expiry. */

static esp_err_t dhcp_kick_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char body_buf[128];
    if (recv_body(req, body_buf, sizeof body_buf, NULL) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_Parse(body_buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }
    cJSON *mac_j = cJSON_GetObjectItem(root, "mac");
    if (!cJSON_IsString(mac_j)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing mac");
        return ESP_FAIL;
    }

    uint8_t target_mac[6];
    if (!parse_mac_str(mac_j->valuestring, target_mac)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad mac");
        return ESP_FAIL;
    }
    cJSON_Delete(root);

    /* Look up the AID by walking the station list — esp_wifi_deauth_sta
     * wants an AID rather than a MAC. AID 0 means "every station". */
    wifi_sta_list_t sta_list;
    memset(&sta_list, 0, sizeof sta_list);
    if (esp_wifi_ap_get_sta_list(&sta_list) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    int matched_aid = -1;
    for (int i = 0; i < sta_list.num; i++) {
        if (memcmp(sta_list.sta[i].mac, target_mac, 6) == 0) {
            /* AID indices in this struct are 1-based from the order the
             * station joined. The wifi driver exposes them via
             * esp_wifi_ap_get_sta_aid; falling back on the array index
             * works for the common case but the API is the canonical
             * source. */
            uint16_t aid = 0;
            if (esp_wifi_ap_get_sta_aid(target_mac, &aid) == ESP_OK && aid > 0) {
                matched_aid = aid;
            }
            break;
        }
    }

    httpd_resp_set_type(req, "application/json");
    if (matched_aid < 0) {
        return httpd_resp_sendstr(req, "{\"ok\":false,\"reason\":\"not connected\"}");
    }

    esp_err_t err = esp_wifi_deauth_sta((uint16_t)matched_aid);
    if (err != ESP_OK) {
        char resp[96];
        snprintf(resp, sizeof resp, "{\"ok\":false,\"reason\":\"%s\"}", esp_err_to_name(err));
        return httpd_resp_sendstr(req, resp);
    }
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_dhcp_kick = {
    .uri      = "/api/dhcp/kick",
    .method   = HTTP_POST,
    .handler  = dhcp_kick_handler,
    .user_ctx = NULL,
};

/* ───────────────────────── Port forwarding ─────────────────────────
 * GET  /api/portmap  → { mappings:[{proto,ext_port,int_ip,int_port,name}...], max }
 * POST /api/portmap  → same shape, replaces the whole table. */

static const char *portmap_proto_str(uint8_t p)
{
    if (p == PORTMAP_PROTO_TCP) return "tcp";
    if (p == PORTMAP_PROTO_UDP) return "udp";
    return "?";
}

static uint8_t portmap_proto_from_str(const char *s)
{
    if (!s) return 0;
    if (!strcasecmp(s, "tcp")) return PORTMAP_PROTO_TCP;
    if (!strcasecmp(s, "udp")) return PORTMAP_PROTO_UDP;
    return 0;
}

static esp_err_t portmap_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    cJSON *arr  = cJSON_CreateArray();
    if (!root || !arr) {
        cJSON_Delete(root); cJSON_Delete(arr);
        httpd_resp_send_500(req); return ESP_FAIL;
    }

    for (int i = 0; i < PORTMAP_MAX; i++) {
        portmap_entry_t e;
        if (!portmap_get(i, &e)) continue;

        ip4_addr_t a = { .addr = e.int_ip };
        char ip_str[16];
        snprintf(ip_str, sizeof ip_str, IPSTR, IP2STR(&a));

        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "proto",    portmap_proto_str(e.proto));
        cJSON_AddNumberToObject(j, "ext_port", e.ext_port);
        cJSON_AddStringToObject(j, "int_ip",   ip_str);
        cJSON_AddNumberToObject(j, "int_port", e.int_port);
        cJSON_AddStringToObject(j, "name",     e.name);
        cJSON_AddItemToArray(arr, j);
    }
    cJSON_AddItemToObject(root, "mappings", arr);
    cJSON_AddNumberToObject(root, "max", PORTMAP_MAX);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static esp_err_t portmap_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    size_t buf_size = 4096;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, buf_size, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }

    cJSON *arr = cJSON_GetObjectItem(root, "mappings");
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing mappings[]");
        return ESP_FAIL;
    }

    portmap_entry_t out[PORTMAP_MAX];
    memset(out, 0, sizeof out);
    int n_in  = cJSON_GetArraySize(arr);
    int n_out = 0;

    for (int i = 0; i < n_in && n_out < PORTMAP_MAX; i++) {
        cJSON *e = cJSON_GetArrayItem(arr, i);
        if (!cJSON_IsObject(e)) continue;

        const cJSON *proto_j = cJSON_GetObjectItem(e, "proto");
        const cJSON *ep_j    = cJSON_GetObjectItem(e, "ext_port");
        const cJSON *iip_j   = cJSON_GetObjectItem(e, "int_ip");
        const cJSON *ip_j    = cJSON_GetObjectItem(e, "int_port");
        const cJSON *name_j  = cJSON_GetObjectItem(e, "name");

        if (!cJSON_IsString(proto_j) || !cJSON_IsNumber(ep_j)
            || !cJSON_IsString(iip_j) || !cJSON_IsNumber(ip_j)) continue;

        portmap_entry_t *r = &out[n_out];
        r->proto = portmap_proto_from_str(proto_j->valuestring);
        if (!r->proto) continue;

        int ep = (int)ep_j->valuedouble;
        int ip = (int)ip_j->valuedouble;
        if (ep <= 0 || ep > 65535 || ip <= 0 || ip > 65535) continue;
        r->ext_port = (uint16_t)ep;
        r->int_port = (uint16_t)ip;

        ip4_addr_t a;
        if (!ip4addr_aton(iip_j->valuestring, &a) || a.addr == 0) continue;
        r->int_ip = a.addr;

        if (cJSON_IsString(name_j)) {
            strlcpy(r->name, name_j->valuestring, sizeof r->name);
        }
        r->valid = 1;
        n_out++;
    }
    cJSON_Delete(root);

    esp_err_t err = portmap_set_all(out, n_out);

    nvs_save_errors_reset();
    if (err != ESP_OK) nvs_save_record_err("portmap", err);
    return send_save_response(req);
}

static const httpd_uri_t uri_portmap = {
    .uri      = "/api/portmap",
    .method   = HTTP_GET,
    .handler  = portmap_handler,
    .user_ctx = NULL,
};
static const httpd_uri_t uri_portmap_save = {
    .uri      = "/api/portmap",
    .method   = HTTP_POST,
    .handler  = portmap_save_handler,
    .user_ctx = NULL,
};

/* Dedicated uplink-LAN -> Tailnet forwarding. This API intentionally has
 * no AP/client-WiFi fields and persists a wholly separate rule table. */
static esp_err_t tailnet_forward_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    cJSON *root=cJSON_CreateObject(), *arr=cJSON_CreateArray();
    if(!root||!arr){cJSON_Delete(root);cJSON_Delete(arr);httpd_resp_send_500(req);return ESP_FAIL;}
    for(int i=0;i<TAILNET_FORWARD_MAX;i++){
        tailnet_forward_rule_t r; tailnet_forward_runtime_t rt;
        if(!tailnet_forward_get(i,&r,&rt))continue;
        char cidr[32], resolved[16]=""; tailnet_forward_format_cidr(r.source_network,r.source_prefix,cidr,sizeof cidr);
        if(rt.resolved_ip)snprintf(resolved,sizeof resolved,"%u.%u.%u.%u",(unsigned)(rt.resolved_ip>>24),(unsigned)((rt.resolved_ip>>16)&255),(unsigned)((rt.resolved_ip>>8)&255),(unsigned)(rt.resolved_ip&255));
        cJSON *j=cJSON_CreateObject();
        cJSON_AddStringToObject(j,"name",r.name);cJSON_AddBoolToObject(j,"enabled",r.enabled);
        cJSON_AddStringToObject(j,"protocol",r.proto==TAILNET_FORWARD_PROTO_UDP?"udp":"tcp");
        cJSON_AddNumberToObject(j,"listen_port",r.listen_port);cJSON_AddStringToObject(j,"tailnet_destination",r.destination);
        cJSON_AddNumberToObject(j,"destination_port",r.destination_port);cJSON_AddStringToObject(j,"allowed_source_subnet",cidr);
        cJSON_AddBoolToObject(j,"installed",rt.installed);cJSON_AddStringToObject(j,"resolved_ip",resolved);
        cJSON_AddNumberToObject(j,"accepted_packets",rt.accepted_packets);cJSON_AddNumberToObject(j,"blocked_packets",rt.blocked_packets);
        cJSON_AddStringToObject(j,"error",rt.error);cJSON_AddItemToArray(arr,j);
    }
    cJSON_AddItemToObject(root,"rules",arr);cJSON_AddNumberToObject(root,"max",TAILNET_FORWARD_MAX);
    char *body=cJSON_PrintUnformatted(root);cJSON_Delete(root);if(!body){httpd_resp_send_500(req);return ESP_FAIL;}
    httpd_resp_set_type(req,"application/json");esp_err_t e=httpd_resp_sendstr(req,body);free(body);return e;
}
static bool json_port_value(const cJSON *item, uint16_t *out)
{
    long value = 0;
    if (cJSON_IsNumber(item)) {
        value = item->valueint;
        if (item->valuedouble != (double)value) return false;
    } else if (cJSON_IsString(item) && item->valuestring) {
        char *end = NULL;
        value = strtol(item->valuestring, &end, 10);
        if (end == item->valuestring || *end != '\0') return false;
    } else {
        return false;
    }
    if (value < 1 || value > 65535) return false;
    *out = (uint16_t)value;
    return true;
}
static esp_err_t tailnet_forward_save_handler(httpd_req_t *req)
{
    if(require_auth(req)!=ESP_OK)return ESP_FAIL;
    char *buf=malloc_body_buf(8192);if(!buf){httpd_resp_send_500(req);return ESP_FAIL;}
    if(recv_body(req,buf,8192,NULL)!=ESP_OK){free(buf);return ESP_FAIL;}cJSON *root=cJSON_Parse(buf);free(buf);
    cJSON *arr=root?cJSON_GetObjectItem(root,"rules"):NULL;if(!cJSON_IsArray(arr)){cJSON_Delete(root);httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"missing rules[]");return ESP_FAIL;}
    int count=cJSON_GetArraySize(arr);if(count>TAILNET_FORWARD_MAX){cJSON_Delete(root);httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"too many rules");return ESP_FAIL;}
    tailnet_forward_rule_t rules[TAILNET_FORWARD_MAX];memset(rules,0,sizeof rules);
    for(int i=0;i<count;i++){
        cJSON *j=cJSON_GetArrayItem(arr,i);const cJSON *name=cJSON_GetObjectItem(j,"name"),*enabled=cJSON_GetObjectItem(j,"enabled"),*proto=cJSON_GetObjectItem(j,"protocol"),*lp=cJSON_GetObjectItem(j,"listen_port"),*dst=cJSON_GetObjectItem(j,"tailnet_destination"),*dp=cJSON_GetObjectItem(j,"destination_port"),*cidr=cJSON_GetObjectItem(j,"allowed_source_subnet");
        if(!cJSON_IsObject(j)||!cJSON_IsString(proto)||!cJSON_IsString(dst)||!cJSON_IsString(cidr)){cJSON_Delete(root);httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"incomplete rule");return ESP_FAIL;}
        uint16_t lpi=0,dpi=0;if(!json_port_value(lp,&lpi)||!json_port_value(dp,&dpi)){cJSON_Delete(root);httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"invalid port");return ESP_FAIL;}
        tailnet_forward_rule_t *r=&rules[i];r->valid=1;r->enabled=!cJSON_IsBool(enabled)||cJSON_IsTrue(enabled);r->proto=!strcasecmp(proto->valuestring,"udp")?17:(!strcasecmp(proto->valuestring,"tcp")?6:0);r->listen_port=lpi;r->destination_port=dpi;
        strlcpy(r->destination,dst->valuestring,sizeof r->destination);if(cJSON_IsString(name))strlcpy(r->name,name->valuestring,sizeof r->name);
        if(tailnet_forward_parse_cidr(cidr->valuestring,&r->source_network,&r->source_prefix)!=ESP_OK){cJSON_Delete(root);httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"invalid allowed source subnet");return ESP_FAIL;}
    }
    cJSON_Delete(root);char why[128]="";esp_err_t err=tailnet_forward_set_all(rules,count,why,sizeof why);
    if(err!=ESP_OK){httpd_resp_set_status(req,err==ESP_ERR_INVALID_STATE?"409 Conflict":"400 Bad Request");return httpd_resp_sendstr(req,why[0]?why:"invalid rules");}
    mqtt_integration_tailnet_forward_changed();httpd_resp_set_type(req,"application/json");return httpd_resp_sendstr(req,"{\"ok\":true}");
}
static const httpd_uri_t uri_tailnet_forward={.uri="/api/tailnet-forward",.method=HTTP_GET,.handler=tailnet_forward_handler};
static const httpd_uri_t uri_tailnet_forward_save={.uri="/api/tailnet-forward",.method=HTTP_POST,.handler=tailnet_forward_save_handler};

/* ─────────────────── MAC denylist ─────────────────── */

static esp_err_t mac_deny_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    cJSON *arr  = cJSON_CreateArray();
    if (!root || !arr) {
        cJSON_Delete(root); cJSON_Delete(arr);
        httpd_resp_send_500(req); return ESP_FAIL;
    }

    for (int i = 0; i < MAC_DENY_MAX; i++) {
        mac_deny_entry_t e;
        if (!mac_deny_get(i, &e)) continue;

        char mac_str[18];
        snprintf(mac_str, sizeof mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                 e.mac[0], e.mac[1], e.mac[2], e.mac[3], e.mac[4], e.mac[5]);

        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "mac",  mac_str);
        cJSON_AddStringToObject(j, "name", e.name);
        cJSON_AddItemToArray(arr, j);
    }
    cJSON_AddItemToObject(root, "denylist", arr);
    cJSON_AddNumberToObject(root, "max", MAC_DENY_MAX);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static esp_err_t mac_deny_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    size_t buf_size = 2048;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, buf_size, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }

    cJSON *arr = cJSON_GetObjectItem(root, "denylist");
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing denylist[]");
        return ESP_FAIL;
    }

    mac_deny_entry_t out[MAC_DENY_MAX];
    memset(out, 0, sizeof out);
    int n_in  = cJSON_GetArraySize(arr);
    int n_out = 0;

    for (int i = 0; i < n_in && n_out < MAC_DENY_MAX; i++) {
        cJSON *e = cJSON_GetArrayItem(arr, i);
        if (!cJSON_IsObject(e)) continue;
        cJSON *mac_j  = cJSON_GetObjectItem(e, "mac");
        cJSON *name_j = cJSON_GetObjectItem(e, "name");
        if (!cJSON_IsString(mac_j)) continue;

        mac_deny_entry_t *r = &out[n_out];
        if (!parse_mac_str(mac_j->valuestring, r->mac)) continue;
        if (cJSON_IsString(name_j)) {
            strlcpy(r->name, name_j->valuestring, sizeof r->name);
        }
        r->valid = 1;
        n_out++;
    }
    cJSON_Delete(root);

    esp_err_t err = mac_deny_set_all(out, n_out);

    /* Kick any currently-connected station whose MAC is now denied —
     * otherwise the operator has to manually click Kick. */
    if (err == ESP_OK) {
        wifi_sta_list_t sl;
        memset(&sl, 0, sizeof sl);
        if (esp_wifi_ap_get_sta_list(&sl) == ESP_OK) {
            for (int i = 0; i < sl.num; i++) {
                if (mac_deny_is_blocked(sl.sta[i].mac)) {
                    uint16_t aid = 0;
                    if (esp_wifi_ap_get_sta_aid(sl.sta[i].mac, &aid) == ESP_OK
                        && aid > 0) {
                        esp_wifi_deauth_sta(aid);
                    }
                }
            }
        }
    }

    nvs_save_errors_reset();
    if (err != ESP_OK) nvs_save_record_err("mac_deny", err);
    return send_save_response(req);
}

static const httpd_uri_t uri_mac_deny = {
    .uri      = "/api/mac/denylist",
    .method   = HTTP_GET,
    .handler  = mac_deny_handler,
    .user_ctx = NULL,
};
static const httpd_uri_t uri_mac_deny_save = {
    .uri      = "/api/mac/denylist",
    .method   = HTTP_POST,
    .handler  = mac_deny_save_handler,
    .user_ctx = NULL,
};

/* ─────────────────── Pre-crash log buffer ───────────────────
 * The RTC slow-RAM ring captures log lines all the way to the panic
 * and survives soft reset / watchdog / abort. Cleared on cold boot or
 * brown-out. UI lives in the Tools tab. */

static esp_err_t log_precrash_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    if (!root) { httpd_resp_send_500(req); return ESP_FAIL; }

    bool have = log_capture_have_precrash();
    size_t sz = log_capture_precrash_size();
    cJSON_AddBoolToObject  (root, "have", have);
    cJSON_AddNumberToObject(root, "size", (double)sz);

    if (have && sz > 0) {
        /* Cap to a reasonable web payload — same ceiling as the live
         * log_tail. Pre-crash buffer can't legally exceed the RTC ring
         * size anyway. */
        size_t cap = WEB_UI_LOG_SNAPSHOT_BYTES;
        char *buf = malloc(cap);
        if (buf) {
            size_t n = log_capture_read_precrash(buf, cap - 1);
            buf[n] = '\0';
            cJSON_AddStringToObject(root, "text", buf);
            free(buf);
        } else {
            cJSON_AddStringToObject(root, "text", "");
        }
    } else {
        cJSON_AddStringToObject(root, "text", "");
    }

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static esp_err_t log_precrash_clear_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    log_capture_clear_precrash();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_log_precrash = {
    .uri      = "/api/log/precrash",
    .method   = HTTP_GET,
    .handler  = log_precrash_handler,
    .user_ctx = NULL,
};
static const httpd_uri_t uri_log_precrash_clear = {
    .uri      = "/api/log/precrash/clear",
    .method   = HTTP_POST,
    .handler  = log_precrash_clear_handler,
    .user_ctx = NULL,
};

/* GET /api/log/raw?since=<seq> — JSON delta endpoint for the live log
 * tail poller. since=0 (the default) returns the full preserved ring;
 * non-zero asks for "everything appended after I last saw seq N".
 * "lost":true means the ring wrapped past the caller's cursor, so the
 * client should clear its view and treat data as a fresh dump. */
static esp_err_t log_raw_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    uint64_t since = 0;
    size_t qlen = httpd_req_get_url_query_len(req) + 1;
    if (qlen > 1) {
        char *q = malloc(qlen);
        if (q && httpd_req_get_url_query_str(req, q, qlen) == ESP_OK) {
            char val[32] = {0};
            if (httpd_query_key_value(q, "since", val, sizeof val) == ESP_OK) {
                since = strtoull(val, NULL, 10);
            }
        }
        free(q);
    }

    /* Scratch matches the full ring so a single poll can return
     * everything written since the client's cursor — otherwise
     * log_capture_read_since truncates to the newest scratch_sz
     * bytes, and the handler's "lost" check (caller fell behind)
     * fires spuriously on every burst that exceeds the scratch. */
    size_t cap = log_capture_capacity();
    size_t scratch_sz = cap;
    char *scratch = malloc(scratch_sz + 1);
    if (!scratch) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"error\":\"oom\"}");
    }

    uint64_t new_seq = 0;
    size_t n_raw = log_capture_read_since(since, scratch, scratch_sz + 1, &new_seq);
    /* "lost" means the ring's oldest preserved byte is newer than
     * what the caller already saw, i.e. they fell behind the ring
     * wrap. The previous formulation (new_seq - n_raw > since)
     * fired any time the scratch buffer was smaller than the gap,
     * which the bigger scratch above now prevents — but the more
     * accurate definition is "is the caller's cursor BEFORE the
     * oldest byte we kept?" which is what we test here. */
    uint64_t oldest = (new_seq > (uint64_t)log_capture_size())
                    ? new_seq - (uint64_t)log_capture_size() : 0;
    bool lost = (since != 0) && (since < oldest);

    httpd_resp_set_type(req, "application/json; charset=utf-8");
    char hdr[160];
    snprintf(hdr, sizeof hdr,
             "{\"seq\":%llu,\"lost\":%s,\"size\":%u,\"cap\":%u,\"data\":\"",
             (unsigned long long)new_seq, lost ? "true" : "false",
             (unsigned)log_capture_size(),
             (unsigned)log_capture_capacity());
    httpd_resp_sendstr_chunk(req, hdr);

    /* Stream JSON-escaped payload. Buffer into 1 KB chunks before
     * calling httpd_resp_send_chunk(): the previous one-byte-per-call
     * implementation generated one TCP PSH/ACK pair per character,
     * and the per-poll latency over a 10 KB log was ~15 s end-to-end —
     * which then stalled the SPA's other parallel fetches behind it.
     * Now: ~10 chunk-send calls per 10 KB instead of 10 000. */
    char  obuf[1024];
    size_t op = 0;
    #define LRH_FLUSH() do { \
        if (op > 0) { httpd_resp_send_chunk(req, obuf, op); op = 0; } \
    } while (0)
    #define LRH_EMIT(s, l) do { \
        if (op + (size_t)(l) > sizeof obuf) LRH_FLUSH(); \
        memcpy(obuf + op, (s), (l)); op += (l); \
    } while (0)
    for (size_t i = 0; i < n_raw; i++) {
        unsigned char c = (unsigned char)scratch[i];
        if      (c == '"')  LRH_EMIT("\\\"", 2);
        else if (c == '\\') LRH_EMIT("\\\\", 2);
        else if (c == '\n') LRH_EMIT("\\n",  2);
        else if (c == '\r') LRH_EMIT("\\r",  2);
        else if (c == '\t') LRH_EMIT("\\t",  2);
        else if (c < 0x20) {
            char esc[8];
            int el = snprintf(esc, sizeof esc, "\\u%04x", c);
            LRH_EMIT(esc, el);
        } else {
            LRH_EMIT((const char *)&c, 1);
        }
    }
    LRH_FLUSH();
    #undef LRH_EMIT
    #undef LRH_FLUSH
    free(scratch);
    httpd_resp_sendstr_chunk(req, "\"}");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

/* POST /api/log/clear — wipes the live ring (precrash buffer is on its
 * own clear endpoint). */
static esp_err_t log_clear_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    log_capture_clear();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_log_raw = {
    .uri      = "/api/log/raw",
    .method   = HTTP_GET,
    .handler  = log_raw_handler,
    .user_ctx = NULL,
};
static const httpd_uri_t uri_log_clear = {
    .uri      = "/api/log/clear",
    .method   = HTTP_POST,
    .handler  = log_clear_handler,
    .user_ctx = NULL,
};

/* Format a host-byte-order IPv4 as "a.b.c.d" — used for the accepted-
 * routes table where host order is the documented storage. */
static void ip4_hbo_to_str(uint32_t hbo, char *out, size_t out_size)
{
    snprintf(out, out_size, "%u.%u.%u.%u",
             (unsigned)((hbo >> 24) & 0xff),
             (unsigned)((hbo >> 16) & 0xff),
             (unsigned)((hbo >> 8)  & 0xff),
             (unsigned)( hbo        & 0xff));
}

static esp_err_t tailscale_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    /* Settings — auth_key itself is never serialised, but we DO emit
     * enough metadata (set flag + prefix/suffix fingerprint + length)
     * for the operator to tell *which* key is currently stored without
     * leaking the secret to anyone reading the response. */
    cJSON *settings = cJSON_CreateObject();
    cJSON_AddBoolToObject  (settings, "enabled",                 tailscale_enabled != 0);
    {
        const char *ak = tailscale_auth_key ? tailscale_auth_key : "";
        size_t alen = strlen(ak);
        cJSON_AddBoolToObject(settings, "auth_key_set", alen > 0);
        if (alen > 0) {
            cJSON_AddNumberToObject(settings, "auth_key_len", (int)alen);
            char preview[40];
            if (alen <= 8) {
                /* tiny strings (operator typed e.g. "test") — show
                 * verbatim, leaking such a value isn't meaningful. */
                snprintf(preview, sizeof preview, "%s", ak);
            } else if (alen <= 19) {
                /* short — just prefix + …, no tail fingerprint room */
                snprintf(preview, sizeof preview, "%.11s…", ak);
            } else {
                /* normal real key — 11-char protocol prefix +
                 * 4 fingerprint chars + … + last 4 chars. 8 unique
                 * chars is enough to tell two keys apart, far too few
                 * to brute-force back into the original 70+ char key. */
                snprintf(preview, sizeof preview, "%.15s…%s",
                         ak, ak + alen - 4);
            }
            cJSON_AddStringToObject(settings, "auth_key_preview", preview);
        }
    }
    if (tailscale_hostname)         cJSON_AddStringToObject(settings, "hostname",       tailscale_hostname);
    if (tailscale_login_server)     cJSON_AddStringToObject(settings, "login_server",   tailscale_login_server);
    if (tailscale_advertise_routes) cJSON_AddStringToObject(settings, "advertise_routes", tailscale_advertise_routes);
    fourvia6_status_t v6;
    fourvia6_get_status(&v6);
    cJSON *v6j = cJSON_AddObjectToObject(settings, "fourvia6");
    cJSON_AddBoolToObject(v6j, "enabled", v6.enabled);
    cJSON_AddStringToObject(v6j, "lan_cidr", v6.lan_cidr);
    cJSON_AddNumberToObject(v6j, "site_id", v6.site_id);
    cJSON_AddStringToObject(v6j, "advertised_prefix", v6.advertised_prefix);
    cJSON_AddNumberToObject(v6j, "translated_packets", v6.translated_packets);
    cJSON_AddNumberToObject(v6j, "dropped_packets", v6.dropped_packets);
    cJSON_AddNumberToObject(v6j, "active_flows", v6.active_flows);
    cJSON_AddNumberToObject(settings, "max_peers",               tailscale_max_peers);
    cJSON_AddNumberToObject(settings, "default_derp_region",     tailscale_default_derp_region);
    cJSON_AddBoolToObject  (settings, "netcheck_override",       tailscale_netcheck_override != 0);
    cJSON_AddNumberToObject(settings, "netcheck_threshold_ms",   tailscale_netcheck_threshold_ms);
    cJSON_AddBoolToObject  (settings, "lan_bypass",              tailscale_lan_bypass != 0);
    cJSON_AddBoolToObject  (settings, "accept_routes",           tailscale_accept_routes != 0);
    cJSON_AddBoolToObject  (settings, "snat_subnet_routes",      tailscale_snat_subnet_routes != 0);
    if (tailscale_exit_node_ip) {
        /* tailscale_exit_node_ip is documented as host byte order. */
        char buf[16];
        ip4_hbo_to_str(tailscale_exit_node_ip, buf, sizeof buf);
        cJSON_AddStringToObject(settings, "exit_node_ip", buf);
    }
    cJSON_AddItemToObject(root, "settings", settings);

    /* Runtime state. tailscale_is_connected() refreshes tunnel_ip from
     * microlink, so the SPA gets a live tunnel address on every fetch. */
    bool ts_runtime_connected = tailscale_is_connected();
    cJSON *runtime = cJSON_CreateObject();
    cJSON_AddBoolToObject(runtime, "connected", ts_runtime_connected);
    if (tailscale_tunnel_ip) {
        char buf[16];
        ip4_to_str(tailscale_tunnel_ip, buf, sizeof buf);
        cJSON_AddStringToObject(runtime, "tunnel_ip", buf);
    }
    /* Last RegisterResponse User block — surfaces auth_key failures
     * that Headscale wraps in a 200-OK (User.ID=0 + empty name → auth
     * invalid or stale node-key). microlink_get_diag is the cheap path:
     * it just copies cached fields, no extra round-trips. */
    {
        struct microlink_s *mlh = tailscale_get_microlink();
        if (mlh) {
            microlink_diag_t diag;
            if (microlink_get_diag(mlh, &diag) == ESP_OK) {
                cJSON_AddNumberToObject(runtime, "register_user_id",
                                        diag.register_user_id);
                if (diag.register_user_name[0]) {
                    cJSON_AddStringToObject(runtime, "register_user_name",
                                            diag.register_user_name);
                }
                cJSON_AddBoolToObject  (runtime, "identity_persistent",
                                        diag.identity_persistent);
                cJSON_AddStringToObject(runtime, "identity_pubkey_prefix",
                                        diag.identity_pubkey_prefix);
                /* DERP region diagnostics (ported from the old http_server UI,
                 * 2026-05-28). derp_home_region = the region the ESP actually
                 * connects to (netcheck may override the default); derp_rtts =
                 * the per-region STUN latencies netcheck measured. Surfacing
                 * these lets the operator SEE why a DERP home was chosen and
                 * pick a better region. */
                cJSON_AddNumberToObject(runtime, "derp_home_region",    diag.derp_home_region);
                cJSON_AddNumberToObject(runtime, "derp_region_default", diag.derp_region_default);
                /* Human-readable city for OUR active home region, so the
                 * Status page can show "DERP: #4 Frankfurt" rather than a
                 * bare number. NULL (region 0 / not in DERPMap yet) → omit. */
                const char *_hrn = microlink_get_derp_region_name(mlh, diag.derp_home_region);
                if (_hrn) cJSON_AddStringToObject(runtime, "derp_home_region_name", _hrn);
                microlink_derp_rtt_t _rtts[16];
                int _nr = microlink_get_derp_rtts(mlh, _rtts, 16);
                cJSON *derp_rtts = cJSON_CreateArray();
                for (int _i = 0; _i < _nr; _i++) {
                    cJSON *e = cJSON_CreateObject();
                    const char *nm = microlink_get_derp_region_name(mlh, _rtts[_i].region_id);
                    cJSON_AddNumberToObject(e, "region_id", _rtts[_i].region_id);
                    cJSON_AddStringToObject(e, "name", nm ? nm : "?");
                    cJSON_AddNumberToObject(e, "rtt_ms", _rtts[_i].rtt_ms);
                    cJSON_AddItemToArray(derp_rtts, e);
                }
                cJSON_AddItemToObject(runtime, "derp_rtts", derp_rtts);
            }
        }
    }
    cJSON_AddItemToObject(root, "runtime", runtime);

    /* MTU / MSS / PMTU manager — persisted fields (mode, fixed_mtu)
     * plus the live-derived effective values the AP-side netif hooks
     * actually enforce on every TCP SYN + DF=1 packet. source tells
     * the operator why the eff_mtu is what it is ("auto-direct" /
     * "auto-DERP" / "user" / "off"). */
    {
        ts_mtu_state_t mst = tailscale_mtu_get();
        cJSON *mtu = cJSON_CreateObject();
        cJSON_AddNumberToObject(mtu, "mode",      (int)mst.mode);
        cJSON_AddNumberToObject(mtu, "fixed_mtu", mst.fixed_mtu);
        cJSON_AddNumberToObject(mtu, "eff_mtu",   mst.eff_mtu);
        cJSON_AddNumberToObject(mtu, "eff_mss",   mst.eff_mss);
        cJSON_AddNumberToObject(mtu, "eff_pmtu",  mst.eff_pmtu);
        cJSON_AddStringToObject(mtu, "source",    mst.source ? mst.source : "");
        cJSON_AddItemToObject(root, "mtu", mtu);
    }

    /* Peers — empty array when microlink isn't running. While the tunnel
     * is still Registering, microlink_peer_info_t.online + .direct_path
     * are unreliable: the control plane has handed us the peer list but
     * DISCO hasn't run, so everyone briefly looks online + DERP. Mask
     * both fields to false until we're verifiably Connected — better a
     * grey dot for a few seconds than a misleading green one. */
    cJSON *peers = cJSON_CreateArray();
    struct microlink_s *ml = tailscale_get_microlink();
    if (ml) {
        int n = microlink_get_peer_count(ml);
        for (int i = 0; i < n; i++) {
            microlink_peer_info_t pi;
            if (microlink_get_peer_info(ml, i, &pi) != ESP_OK) continue;
            cJSON *p = cJSON_CreateObject();
            cJSON_AddStringToObject(p, "hostname",     pi.hostname);
            cJSON_AddBoolToObject  (p, "online",       ts_runtime_connected && pi.online);
            cJSON_AddBoolToObject  (p, "direct_path",  ts_runtime_connected && pi.direct_path);
            cJSON_AddBoolToObject  (p, "is_exit_node", pi.is_exit_node);
            /* Peer's home DERP region — relevant when direct_path is false
             * (the region this peer is relayed through). Surface the id +
             * the human-readable city so the peers table can show
             * "DERP · Frankfurt" instead of a bare "DERP". 0 = unknown. */
            cJSON_AddNumberToObject(p, "derp_region", pi.derp_region);
            if (pi.derp_region) {
                const char *_prn = microlink_get_derp_region_name(ml, pi.derp_region);
                if (_prn) cJSON_AddStringToObject(p, "derp_region_name", _prn);
            }
            /* microlink_peer_info_t.vpn_ip is host byte order. */
            char buf[16];
            ip4_hbo_to_str(pi.vpn_ip, buf, sizeof buf);
            cJSON_AddStringToObject(p, "vpn_ip", buf);
            cJSON *routes = cJSON_CreateArray();
            for (int r = 0; r < pi.subnet_route_count; r++) {
                cJSON *rt = cJSON_CreateObject();
                ip4_hbo_to_str(pi.subnet_routes[r].network, buf, sizeof buf);
                cJSON_AddStringToObject(rt, "network",    buf);
                cJSON_AddNumberToObject(rt, "prefix_len", pi.subnet_routes[r].prefix_len);
                cJSON_AddItemToArray(routes, rt);
            }
            cJSON_AddItemToObject(p, "subnet_routes", routes);
            cJSON_AddItemToArray(peers, p);
        }
    }
    cJSON_AddItemToObject(root, "peers", peers);

    /* Accepted-routes table (peer routes we've decided to honour). */
    cJSON *acc = cJSON_CreateArray();
    for (int i = 0; i < tailscale_accepted_routes_count; i++) {
        cJSON *r = cJSON_CreateObject();
        char buf[16];
        ip4_hbo_to_str(tailscale_accepted_routes[i].network, buf, sizeof buf);
        cJSON_AddStringToObject(r, "network",    buf);
        cJSON_AddNumberToObject(r, "prefix_len", tailscale_accepted_routes[i].prefix_len);
        cJSON_AddItemToArray(acc, r);
    }
    cJSON_AddItemToObject(root, "accepted_routes", acc);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static const httpd_uri_t uri_tailscale = {
    .uri      = "/api/tailscale",
    .method   = HTTP_GET,
    .handler  = tailscale_handler,
    .user_ctx = NULL,
};

static esp_err_t tailscale_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    nvs_save_errors_reset();

    /* Heap-allocate the body buffer — see network_save_handler comment. */
    size_t buf_size = 3072;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, buf_size, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }

    /* Same omit-to-keep convention as /api/network. The "settings"
     * wrapper matches the GET shape so the SPA can round-trip its
     * editable form straight back. auth_key is write-only — it's never
     * returned by the GET, and POSTing it with an empty string clears
     * the credential. */
    const cJSON *s = cJSON_GetObjectItem(root, "settings");
    if (cJSON_IsObject(s)) {
        const cJSON *enabled = cJSON_GetObjectItem(s, "enabled");
        if (cJSON_IsBool(enabled)) {
            nvs_save_int("ts_enabled", cJSON_IsTrue(enabled) ? 1 : 0);
        }
        save_str_if_present(s, "auth_key",         "ts_authkey");
        save_str_if_present(s, "hostname",         "ts_hostname");
        save_str_if_present(s, "login_server",     "ts_login");
        save_str_if_present(s, "advertise_routes", "ts_routes");

        /* tailscale_init only reads these globals at boot, so the
         * /api/tailscale GET that immediately follows this POST would
         * still serialise the stale value. Mirror the just-saved
         * strings back into the heap-allocated globals so the next
         * read-back sees the new state without waiting for a reboot. */
        #define _TS_REFRESH_STR(json_key, global_var)                       \
            do {                                                            \
                const cJSON *_v = cJSON_GetObjectItem(s, json_key);         \
                if (cJSON_IsString(_v)) {                                   \
                    free(global_var);                                       \
                    global_var = strdup(_v->valuestring);                   \
                }                                                           \
            } while (0)
        #define _TS_REFRESH_BOOL(json_key, global_var)                      \
            do {                                                            \
                const cJSON *_v = cJSON_GetObjectItem(s, json_key);         \
                if (cJSON_IsBool(_v)) global_var = cJSON_IsTrue(_v) ? 1 : 0;\
            } while (0)
        #define _TS_REFRESH_NUM(json_key, global_var)                       \
            do {                                                            \
                const cJSON *_v = cJSON_GetObjectItem(s, json_key);         \
                if (cJSON_IsNumber(_v)) global_var = (int32_t)_v->valuedouble; \
            } while (0)

        _TS_REFRESH_STR ("auth_key",                tailscale_auth_key);
        _TS_REFRESH_STR ("hostname",                tailscale_hostname);
        _TS_REFRESH_STR ("login_server",            tailscale_login_server);
        _TS_REFRESH_STR ("advertise_routes",        tailscale_advertise_routes);
        _TS_REFRESH_BOOL("enabled",                 tailscale_enabled);
        _TS_REFRESH_NUM ("max_peers",               tailscale_max_peers);
        _TS_REFRESH_NUM ("default_derp_region",     tailscale_default_derp_region);
        _TS_REFRESH_NUM ("netcheck_threshold_ms",   tailscale_netcheck_threshold_ms);
        _TS_REFRESH_BOOL("netcheck_override",       tailscale_netcheck_override);
        _TS_REFRESH_BOOL("lan_bypass",              tailscale_lan_bypass);
        _TS_REFRESH_BOOL("accept_routes",           tailscale_accept_routes);
        _TS_REFRESH_BOOL("snat_subnet_routes",      tailscale_snat_subnet_routes);

        #undef _TS_REFRESH_STR
        #undef _TS_REFRESH_BOOL
        #undef _TS_REFRESH_NUM
        save_int_if_present(s, "max_peers",        "ts_maxpeers");
        save_int_if_present(s, "default_derp_region",   "ts_def_derp");
        save_int_if_present(s, "netcheck_threshold_ms", "ts_nc_thr");

        const cJSON *bool_keys[][2] = {
            { cJSON_GetObjectItem(s, "netcheck_override"), (void *)"ts_nc_ovr"  },
            { cJSON_GetObjectItem(s, "lan_bypass"),        (void *)"ts_lan_bp"  },
            { cJSON_GetObjectItem(s, "accept_routes"),     (void *)"ts_acpt_rt" },
            { cJSON_GetObjectItem(s, "snat_subnet_routes"), (void *)"ts_snat_sr" },
        };
        for (size_t i = 0; i < sizeof bool_keys / sizeof bool_keys[0]; i++) {
            const cJSON *v = bool_keys[i][0];
            if (cJSON_IsBool(v)) {
                nvs_save_int((const char *)bool_keys[i][1], cJSON_IsTrue(v) ? 1 : 0);
            }
        }

        /* exit_node_ip is a dotted-quad string in the JSON, stored in
         * NVS as the host-order int that tailscale_init reads back, and
         * consumed by lwip_route_hook + keepalive_start which both
         * expect host byte order. ip4addr_aton fills a.addr in network
         * byte order, so we MUST ntohl before persisting and mirroring;
         * otherwise byte-reversed comparisons miss the chosen peer and
         * the supervisor never flips netif_default. */
        const cJSON *exit_node = cJSON_GetObjectItem(s, "exit_node_ip");
        if (cJSON_IsString(exit_node)) {
            ip4_addr_t a = { 0 };
            if (exit_node->valuestring[0] == '\0' || ip4addr_aton(exit_node->valuestring, &a)) {
                uint32_t hbo = lwip_ntohl(a.addr);
                nvs_save_int("ts_exit_node", (int32_t)hbo);
                tailscale_exit_node_ip = hbo;
            }
        }

        const cJSON *v6j = cJSON_GetObjectItem(s, "fourvia6");
        if (cJSON_IsObject(v6j)) {
            fourvia6_status_t current;
            fourvia6_get_status(&current);
            const cJSON *en = cJSON_GetObjectItem(v6j, "enabled");
            const cJSON *lan = cJSON_GetObjectItem(v6j, "lan_cidr");
            const cJSON *site = cJSON_GetObjectItem(v6j, "site_id");
            bool enabled4 = cJSON_IsBool(en) ? cJSON_IsTrue(en) : current.enabled;
            const char *lan4 = cJSON_IsString(lan) ? lan->valuestring : current.lan_cidr;
            int site4 = cJSON_IsNumber(site) ? site->valueint : current.site_id;
            char error[96] = "invalid 4via6 settings";
            if (site4 < 0 || site4 > 65535
                || fourvia6_set_config(enabled4, lan4, (uint16_t)site4,
                                       error, sizeof error) != ESP_OK) {
                cJSON_Delete(root);
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, error);
                return ESP_FAIL;
            }
        }
    }

    /* MTU/MSS/PMTU manager — operator can pick AUTO (peer-aware,
     * 1420 when at least one peer is direct, 1280 when only DERP) or
     * FIXED with a hand-picked MTU in [576..1500]. tailscale_mtu_set
     * persists to NVS and immediately recomputes eff_mtu / eff_mss /
     * eff_pmtu — change is live without reboot. */
    const cJSON *mtu_j = cJSON_GetObjectItem(root, "mtu");
    if (cJSON_IsObject(mtu_j)) {
        ts_mtu_state_t cur = tailscale_mtu_get();
        ts_mtu_mode_t  mode      = cur.mode;
        uint16_t       fixed_mtu = cur.fixed_mtu;
        const cJSON *m  = cJSON_GetObjectItem(mtu_j, "mode");
        const cJSON *fm = cJSON_GetObjectItem(mtu_j, "fixed_mtu");
        if (cJSON_IsNumber(m)) {
            int v = (int)m->valuedouble;
            if (v == TS_MTU_AUTO || v == TS_MTU_FIXED) mode = (ts_mtu_mode_t)v;
        }
        if (cJSON_IsNumber(fm)) {
            int v = (int)fm->valuedouble;
            if (v >= TS_MTU_MIN && v <= TS_MTU_MAX) fixed_mtu = (uint16_t)v;
        }
        tailscale_mtu_set(mode, fixed_mtu);
    }

    cJSON_Delete(root);
    /* Surface any silent NVS-out-of-space failures from the save_* path
     * in the response. The SPA renders nvs_save_error as a red toast
     * so the operator doesn't get a green "Saved" when the on-flash
     * state isn't actually changing. */
    cJSON *resp = cJSON_CreateObject();
    nvs_save_errors_attach(resp);
    cJSON_AddBoolToObject(resp, "restart_required", true);
    char *body = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    httpd_resp_set_type(req, "application/json");
    esp_err_t e = httpd_resp_sendstr(req, body ? body : "{\"ok\":false}");
    free(body);
    return e;
}

/* Forward decl — the implementation is below the tailscale block but
 * we need it for the reset-identity handler that lives up here. */
static void delayed_restart_task(void *arg);

/* POST /api/tailscale/reset_identity — clears the device's stored
 * machine / wg / disco keypairs + cached peer table so the next boot
 * generates fresh ones. Use this when the control plane no longer
 * recognises the node-key (deleted on the server, or a fresh Headscale
 * DB). microlink_factory_reset() touches its own NVS namespaces — no
 * other config is affected. Restart is required because the keys are
 * read once at microlink_init. */
static esp_err_t tailscale_reset_identity_handler(httpd_req_t *req)
{
    if (require_password_session(req) != ESP_OK) return ESP_FAIL;
    esp_err_t err = microlink_factory_reset();
    httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) {
        char resp[64];
        snprintf(resp, sizeof resp, "{\"ok\":false,\"reason\":\"%s\"}", esp_err_to_name(err));
        return httpd_resp_sendstr(req, resp);
    }
    httpd_resp_sendstr(req, "{\"ok\":true}");
    xTaskCreate(delayed_restart_task, "reboot", 2048, NULL, 5, NULL);
    return ESP_OK;
}

static const httpd_uri_t uri_tailscale_reset_identity = {
    .uri      = "/api/tailscale/reset_identity",
    .method   = HTTP_POST,
    .handler  = tailscale_reset_identity_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t uri_tailscale_save = {
    .uri      = "/api/tailscale",
    .method   = HTTP_POST,
    .handler  = tailscale_save_handler,
    .user_ctx = NULL,
};

/* Session-management forward declarations — the full implementation lives
 * further down the file, but system_handler / system_save_handler /
 * auth_setup_handler need to refer to s_session_timeout_s and a handful of
 * session_*() helpers before they're defined. C's tentative-definition rule
 * lets us put the storage class + type here; the initialiser below
 * resolves into the same object. */
static uint32_t s_session_timeout_s;
static uint32_t session_timeout_clamp(uint32_t v);
static uint32_t session_remaining_s_for_req(httpd_req_t *req);
static bool     session_alive(void);
static void     session_extend_all_alive(void);
static void     session_clear_all(void);

uint16_t web_ui_configured_port(void)
{
    uint16_t port = 80;
    if (nvs_param_get_u16("web_port", &port) != ESP_OK || port == 0) port = 80;
    return port;
}

static esp_err_t system_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    const esp_app_desc_t *desc = esp_app_get_description();
    if (desc) {
        cJSON_AddStringToObject(root, "version",    desc->version);
        cJSON_AddStringToObject(root, "build_date", desc->date);
        cJSON_AddStringToObject(root, "build_time", desc->time);
        cJSON_AddStringToObject(root, "idf_ver",    desc->idf_ver);
    }

    /* Device label (the friendly name shown in the nav). */
    {
        char *name = device_name_dup();
        if (name) { cJSON_AddStringToObject(root, "device_name", name); free(name); }
    }

    /* POSIX timezone string (e.g. "CET-1CEST,M3.5.0,M10.5.0/3"). Empty
     * means UTC. Surfaced to the UI so it can render local clock times. */
    {
        char *tz = nvs_param_get_str("tz");
        if (tz) { cJSON_AddStringToObject(root, "tz", tz); free(tz); }
        else    { cJSON_AddStringToObject(root, "tz", ""); }
    }

    /* Web-session idle timeout — operator-configurable from the System
     * tab. session_remaining_s lets the SPA render a discrete countdown
     * next to the lock button without needing its own /api/auth poll. */
    cJSON_AddNumberToObject(root, "session_timeout_s",   s_session_timeout_s);
    cJSON_AddNumberToObject(root, "session_remaining_s", session_remaining_s_for_req(req));
    cJSON_AddBoolToObject(root, "web_auth_enabled", s_web_auth_enabled);
    cJSON_AddBoolToObject(root, "web_password_set", is_web_password_set());
    cJSON_AddNumberToObject(root, "web_port", web_ui_configured_port());

    /* TX-power override (0 = IDF default ≈ 20 dBm, 8..84 = custom in
     * 0.25 dBm steps). Reading via the live API gives whatever was
     * actually applied, not the NVS persisted value — they match
     * unless the operator changed it without a reboot. */
    {
        int8_t live_pwr = 0;
        if (esp_wifi_get_max_tx_power(&live_pwr) == ESP_OK) {
            cJSON_AddNumberToObject(root, "tx_power", live_pwr);
        }
        uint8_t nvs_pwr = 0;
        if (nvs_param_get_u8("tx_pwr", &nvs_pwr) == ESP_OK) {
            cJSON_AddNumberToObject(root, "tx_power_nvs", nvs_pwr);
        }
    }

    /* Log tail — read into a heap buffer to keep the request handler
     * stack small. Truncated to a known size so the JSON stays bounded. */
    char *log_buf = malloc(WEB_UI_LOG_SNAPSHOT_BYTES);
    if (log_buf) {
        size_t n = log_capture_read(log_buf, WEB_UI_LOG_SNAPSHOT_BYTES - 1);
        log_buf[n] = '\0';
        cJSON_AddStringToObject(root, "log_tail", log_buf);
        free(log_buf);
    }

    /* Reset history — last 10 boots, [0] is the most recent. The recorder
     * runs at app_main() time, the coredump backfill writes hist[0].crash
     * when a panic-from-prior-boot was decoded on this boot. */
    {
        reset_history_entry_t hist[RESET_HISTORY_MAX] = {0};
        int n = reset_history_load(hist, RESET_HISTORY_MAX);
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < n; i++) {
            cJSON *e = cJSON_CreateObject();
            cJSON_AddNumberToObject(e, "wallclock", hist[i].wallclock);
            cJSON_AddStringToObject(e, "reason",    hist[i].reason);
            cJSON_AddStringToObject(e, "who",       hist[i].who);
            cJSON_AddStringToObject(e, "crash",     hist[i].crash);
            cJSON_AddItemToArray(arr, e);
        }
        cJSON_AddItemToObject(root, "reset_history", arr);
    }

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static const httpd_uri_t uri_system = {
    .uri      = "/api/system",
    .method   = HTTP_GET,
    .handler  = system_handler,
    .user_ctx = NULL,
};

static void delayed_restart_task(void *arg)
{
    /* Give the HTTP response a moment to flush + the TCP socket to close
     * cleanly before we yank the power. */
    vTaskDelay(pdMS_TO_TICKS(1000));
    /* Persist the SD flight-recorder tail before the restart (bounded /
     * best-effort — never blocks the reboot if the card stalls). */
    sdlog_flush();
    esp_restart();
}

static esp_err_t system_save_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    nvs_save_errors_reset();

    char buf[512];
    if (recv_body(req, buf, sizeof buf, NULL) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }

    bool web_port_changed = false;
    const cJSON *wp = cJSON_GetObjectItem(root, "web_port");
    if (cJSON_IsNumber(wp)) {
        int requested = (int)wp->valuedouble;
        if (wp->valuedouble != (double)requested || requested < 1 || requested > 65535) {
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                "web_port must be a whole number from 1 to 65535");
            return ESP_FAIL;
        }
        if (portmap_listen_conflicts(PORTMAP_PROTO_TCP, (uint16_t)requested) ||
            tailnet_forward_listen_conflicts(TAILNET_FORWARD_PROTO_TCP, (uint16_t)requested)) {
            cJSON_Delete(root);
            httpd_resp_set_status(req, "409 Conflict");
            return httpd_resp_sendstr(req, "Web UI port conflicts with a TCP forwarding rule");
        }
        web_port_changed = (uint16_t)requested != web_ui_configured_port();
        nvs_save_record_err("web_port", nvs_param_set_u16("web_port", (uint16_t)requested));
    }

    /* Device-name update — operator-defined label persisted under
     * NVS "dev_name", surfaced everywhere the SPA reads /api/auth/status
     * or /api/system. */
    const cJSON *dn = cJSON_GetObjectItem(root, "device_name");
    if (cJSON_IsString(dn)) {
        nvs_save_str("dev_name", dn->valuestring);
    }

    /* Timezone — POSIX string. tzset() pulls in the new rule for any
     * fresh localtime() call, but the IDF log subsystem reads TZ once
     * at boot and caches it, so the operator's main "where do my log
     * timestamps live" question only resolves after a reboot.
     * Compare against the persisted value so we only flip the
     * restart_required flag when the operator actually changed it. */
    bool tz_changed = false;
    const cJSON *tz_j = cJSON_GetObjectItem(root, "tz");
    if (cJSON_IsString(tz_j)) {
        char *cur_tz = nvs_param_get_str("tz");
        const char *cur_str = cur_tz ? cur_tz : "";
        if (strcmp(cur_str, tz_j->valuestring) != 0) {
            tz_changed = true;
        }
        free(cur_tz);
        nvs_save_str("tz", tz_j->valuestring);
        setenv("TZ", tz_j->valuestring[0] ? tz_j->valuestring : "UTC0", 1);
        tzset();
    }

    /* Web-session idle timeout (seconds). Persisted under NVS "auth_to_s".
     * Zero explicitly disables expiry; non-zero values are clamped to
     * [60, 28800]. The
     * sliding-window logic in request_authenticated() uses the new value
     * on the very next authenticated hit — no reboot needed. */
    const cJSON *st = cJSON_GetObjectItem(root, "session_timeout_s");
    if (cJSON_IsNumber(st)) {
        uint32_t v = (uint32_t)st->valuedouble;
        v = session_timeout_clamp(v);
        nvs_save_u32("auth_to_s", v);
        s_session_timeout_s = v;
        session_extend_all_alive();
    }

    /* Web password gate. This switch does not delete the stored password:
     * the same credential keeps protecting the optional remote console and
     * is ready if the operator enables the web gate again. */
    const cJSON *wa = cJSON_GetObjectItem(root, "web_auth_enabled");
    if (cJSON_IsBool(wa)) {
        bool enabled = cJSON_IsTrue(wa);
        nvs_save_u8("web_auth_en", enabled ? 1 : 0);
        s_web_auth_enabled = enabled;
    }

    /* TX-power override — clamp + persist + apply live. 0 disables the
     * override (next boot will skip the call and let the IDF default
     * stand). */
    const cJSON *tx_j = cJSON_GetObjectItem(root, "tx_power");
    if (cJSON_IsNumber(tx_j)) {
        int v = (int)tx_j->valuedouble;
        if (v < 0)  v = 0;
        if (v > 84) v = 84;
        if (v != 0 && v < 8) v = 8;        /* IDF rejects values below 8 */
        nvs_save_u8("tx_pwr", (uint8_t)v);
        if (v >= 8) esp_wifi_set_max_tx_power((int8_t)v);
    }

    cJSON_Delete(root);
    /* Surface any NVS write failures from the save path — see the
     * twin block in tailscale_save_handler. */
    cJSON *resp = cJSON_CreateObject();
    nvs_save_errors_attach(resp);
    if (tz_changed || web_port_changed) cJSON_AddBoolToObject(resp, "restart_required", true);
    char *body = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    httpd_resp_set_type(req, "application/json");
    esp_err_t e = httpd_resp_sendstr(req, body ? body : "{\"ok\":false}");
    free(body);
    return e;
}

static esp_err_t system_restart_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, "{\"ok\":true,\"restarting\":true}");
    xTaskCreate(delayed_restart_task, "reboot", 2048, NULL, 5, NULL);
    return err;
}

static esp_err_t system_factory_reset_handler(httpd_req_t *req)
{
    if (require_password_session(req) != ESP_OK) return ESP_FAIL;
    nvs_param_erase_all();
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, "{\"ok\":true,\"restarting\":true}");
    xTaskCreate(delayed_restart_task, "reboot", 2048, NULL, 5, NULL);
    return err;
}

/* Deliberately abort() the device for testing the panic-capture chain.
 * Auth-gated; not exposed in the SPA UI — only useful via curl from a
 * developer's workstation. After a 200 ms delay (let the JSON flush),
 * calls abort() so the IDF panic handler fires for real — coredump
 * lands in the partition, panic_print_* output funnels into the RTC
 * pre-crash ring via __wrap_panic_print_char. */
static void delayed_abort_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(200));
    abort();
}
static esp_err_t system_debug_crash_handler(httpd_req_t *req)
{
    if (require_password_session(req) != ESP_OK) return ESP_FAIL;
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, "{\"ok\":true,\"aborting\":true}");
    xTaskCreate(delayed_abort_task, "crash", 2048, NULL, 5, NULL);
    return err;
}
static const httpd_uri_t uri_system_debug_crash = {
    .uri = "/api/debug/crash", .method = HTTP_POST, .handler = system_debug_crash_handler,
};

static const httpd_uri_t uri_system_save = {
    .uri = "/api/system", .method = HTTP_POST, .handler = system_save_handler,
};
static const httpd_uri_t uri_system_restart = {
    .uri = "/api/system/restart", .method = HTTP_POST, .handler = system_restart_handler,
};
static const httpd_uri_t uri_system_factory_reset = {
    .uri = "/api/system/factory_reset", .method = HTTP_POST, .handler = system_factory_reset_handler,
};

/* Manual OTA firmware upload. Body is raw .bin bytes (Content-Type is
 * irrelevant to the writer); auth is required and gated here so the
 * actual ota_upload_handler can stay agnostic. */
static esp_err_t system_ota_upload_handler(httpd_req_t *req)
{
    if (require_password_session(req) != ESP_OK) return ESP_FAIL;
    esp_err_t err = ota_upload_handler(req);
    if (err == ESP_OK) {
        /* Schedule a delayed reboot — same pattern as /api/system/restart
         * so the success JSON has time to flush over the socket. */
        xTaskCreate(delayed_restart_task, "reboot", 2048, NULL, 5, NULL);
    }
    return err;
}
static const httpd_uri_t uri_system_ota = {
    .uri = "/api/system/ota", .method = HTTP_POST, .handler = system_ota_upload_handler,
};

/* ---- Encrypted-secrets backup endpoints ---------------------------------
 * Plain-text secrets bundle. NEVER reached without a valid session, and
 * the SPA passphrase-encrypts the response BEFORE writing the backup
 * file to disk. Restore is the mirror image — SPA decrypts in the
 * browser, POSTs the plain bundle here, NVS writes happen atomically
 * through the same nvs_save_* helpers as every other config handler. */
static esp_err_t system_secrets_get_handler(httpd_req_t *req)
{
    if (require_password_session(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    if (!root) { httpd_resp_send_500(req); return ESP_FAIL; }

    /* Tailscale auth key + AP password — both are write-only NVS strings
     * that the normal GET endpoints intentionally redact. */
    {
        char *s = nvs_param_get_str("ts_authkey");
        cJSON_AddStringToObject(root, "auth_key", s ? s : "");
        free(s);
    }
    {
        char *s = nvs_param_get_str("ap_passwd");
        cJSON_AddStringToObject(root, "ap_password", s ? s : "");
        free(s);
    }
    {
        char *s = nvs_param_get_str("mqtt_pass");
        cJSON_AddStringToObject(root, "mqtt_password", s ? s : "");
        free(s);
    }
    {
        char *s = nvs_param_get_str("ntfy_token");
        cJSON_AddStringToObject(root, "ntfy_token", s ? s : "");
        free(s);
    }

    /* Full network table including PSK + EAP credentials. Mirrors the
     * wifi_network_t layout so a round-trip restore reproduces the
     * exact NVS state. */
    cJSON *nets = cJSON_CreateArray();
    int count = wifi_networks_count();
    for (int i = 0; i < count; i++) {
        wifi_network_t n;
        if (!wifi_networks_get(i, &n)) continue;
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "ssid",        n.ssid);
        cJSON_AddStringToObject(e, "password",    n.passwd);
        cJSON_AddNumberToObject(e, "eap_method",  n.eap_method);
        cJSON_AddNumberToObject(e, "eap_phase2",  n.eap_phase2);
        cJSON_AddBoolToObject  (e, "eap_cert_bundle",
                                n.eap_use_cert_bundle != 0);
        cJSON_AddStringToObject(e, "eap_identity", n.eap_identity);
        cJSON_AddStringToObject(e, "eap_username", n.eap_username);
        cJSON_AddStringToObject(e, "eap_password", n.eap_password);
        cJSON_AddItemToArray(nets, e);
    }
    cJSON_AddItemToObject(root, "networks", nets);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}
static const httpd_uri_t uri_system_secrets_get = {
    .uri = "/api/system/secrets", .method = HTTP_GET,
    .handler = system_secrets_get_handler,
};

static esp_err_t system_secrets_post_handler(httpd_req_t *req)
{
    if (require_password_session(req) != ESP_OK) return ESP_FAIL;
    nvs_save_errors_reset();

    /* Worst-case bundle: 5 networks × ~400 B of EAP/static fields + a few
     * top-level strings. 4 KB leaves plenty of slack while still fitting
     * comfortably on the stack via malloc. */
    size_t buf_size = 4096;
    char *buf = malloc_body_buf(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (recv_body(req, buf, buf_size, NULL) != ESP_OK) { free(buf); return ESP_FAIL; }

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }

    save_str_if_present(root, "auth_key",    "ts_authkey");
    save_str_if_present(root, "ap_password", "ap_passwd");
    save_str_if_present(root, "mqtt_password", "mqtt_pass");
    save_str_if_present(root, "ntfy_token", "ntfy_token");

    /* Network array — only rewrite NVS when the client actually sent one,
     * so a partial restore (e.g. just the auth_key) doesn't wipe the
     * existing uplink table. */
    cJSON *nets_j = cJSON_GetObjectItem(root, "networks");
    if (cJSON_IsArray(nets_j)) {
        wifi_network_t arr[WIFI_NETWORKS_MAX];
        memset(arr, 0, sizeof arr);
        int n_out = 0;
        cJSON *e;
        cJSON_ArrayForEach(e, nets_j) {
            if (n_out >= WIFI_NETWORKS_MAX) break;
            const cJSON *ssid_j = cJSON_GetObjectItem(e, "ssid");
            if (!cJSON_IsString(ssid_j) || !ssid_j->valuestring[0]) continue;
            wifi_network_t *n = &arr[n_out];
            strlcpy(n->ssid, ssid_j->valuestring, sizeof n->ssid);

            const cJSON *pw  = cJSON_GetObjectItem(e, "password");
            const cJSON *m   = cJSON_GetObjectItem(e, "eap_method");
            const cJSON *p2  = cJSON_GetObjectItem(e, "eap_phase2");
            const cJSON *cb  = cJSON_GetObjectItem(e, "eap_cert_bundle");
            const cJSON *id  = cJSON_GetObjectItem(e, "eap_identity");
            const cJSON *un  = cJSON_GetObjectItem(e, "eap_username");
            const cJSON *epw = cJSON_GetObjectItem(e, "eap_password");
            if (cJSON_IsString(pw))  strlcpy(n->passwd,       pw->valuestring,  sizeof n->passwd);
            if (cJSON_IsNumber(m))   n->eap_method = (uint8_t)m->valueint;
            if (cJSON_IsNumber(p2))  n->eap_phase2 = (uint8_t)p2->valueint;
            if (cJSON_IsBool(cb))    n->eap_use_cert_bundle = cJSON_IsTrue(cb) ? 1 : 0;
            if (cJSON_IsString(id))  strlcpy(n->eap_identity, id->valuestring,  sizeof n->eap_identity);
            if (cJSON_IsString(un))  strlcpy(n->eap_username, un->valuestring,  sizeof n->eap_username);
            if (cJSON_IsString(epw)) strlcpy(n->eap_password, epw->valuestring, sizeof n->eap_password);
            n->valid = 1;
            n_out++;
        }
        esp_err_t serr = wifi_networks_set_all(arr, n_out);
        if (serr != ESP_OK) nvs_save_record_err("wifi_nets", serr);
    }
    cJSON_Delete(root);

    /* Mirror the standard save-handler response: { ok, nvs_save_error? }. */
    cJSON *resp = cJSON_CreateObject();
    nvs_save_errors_attach(resp);
    char *out = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    httpd_resp_set_type(req, "application/json");
    esp_err_t e = httpd_resp_sendstr(req, out ? out : "{\"ok\":true}");
    free(out);
    return e;
}
static const httpd_uri_t uri_system_secrets_post = {
    .uri = "/api/system/secrets", .method = HTTP_POST,
    .handler = system_secrets_post_handler,
};

/* ---- Hardware diagnostics endpoint --------------------------------------
 * Wide-band snapshot of chip / heap / flash / partitions / coredump /
 * MAC / tasks. Pulls everything the Diagnostics tab shows in one
 * request so the SPA stays single-fetch. Read-only — no NVS writes,
 * no state mutation. Roughly 4-8 KB of JSON. */
static const char *part_type_str(esp_partition_type_t t, uint8_t subtype)
{
    if (t == ESP_PARTITION_TYPE_APP) {
        if (subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) return "app/factory";
        if (subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MIN
            && subtype <= ESP_PARTITION_SUBTYPE_APP_OTA_MAX) {
            static char buf[16];
            snprintf(buf, sizeof buf, "app/ota_%u",
                     (unsigned)(subtype - ESP_PARTITION_SUBTYPE_APP_OTA_MIN));
            return buf;
        }
        if (subtype == ESP_PARTITION_SUBTYPE_APP_TEST) return "app/test";
        return "app/?";
    }
    if (t == ESP_PARTITION_TYPE_DATA) {
        switch (subtype) {
            case ESP_PARTITION_SUBTYPE_DATA_OTA:      return "data/ota";
            case ESP_PARTITION_SUBTYPE_DATA_PHY:      return "data/phy";
            case ESP_PARTITION_SUBTYPE_DATA_NVS:      return "data/nvs";
            case ESP_PARTITION_SUBTYPE_DATA_COREDUMP: return "data/coredump";
            case ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS: return "data/nvs_keys";
            case ESP_PARTITION_SUBTYPE_DATA_EFUSE_EM: return "data/efuse";
            case ESP_PARTITION_SUBTYPE_DATA_UNDEFINED:return "data/undef";
            case ESP_PARTITION_SUBTYPE_DATA_ESPHTTPD: return "data/esphttpd";
            case ESP_PARTITION_SUBTYPE_DATA_FAT:      return "data/fat";
            case ESP_PARTITION_SUBTYPE_DATA_SPIFFS:   return "data/spiffs";
            default:                                  return "data/?";
        }
    }
    return "?";
}

static esp_err_t system_diag_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    if (!root) { httpd_resp_send_500(req); return ESP_FAIL; }

    /* --- A) Chip + memory ------------------------------------------------ */
    {
        cJSON *c = cJSON_CreateObject();
        esp_chip_info_t ci;
        esp_chip_info(&ci);
        const char *model = "?";
        switch (ci.model) {
            case CHIP_ESP32:    model = "ESP32";    break;
            case CHIP_ESP32S2:  model = "ESP32-S2"; break;
            case CHIP_ESP32S3:  model = "ESP32-S3"; break;
            case CHIP_ESP32C3:  model = "ESP32-C3"; break;
            case CHIP_ESP32H2:  model = "ESP32-H2"; break;
            case CHIP_ESP32C6:  model = "ESP32-C6"; break;
            default: break;
        }
        cJSON_AddStringToObject(c, "model",    model);
        cJSON_AddNumberToObject(c, "revision", ci.revision);
        cJSON_AddNumberToObject(c, "cores",    ci.cores);
        /* features bitmask: wifi / bt / ble / 802.15.4 / embedded flash / psram */
        cJSON *feat = cJSON_CreateArray();
        if (ci.features & CHIP_FEATURE_WIFI_BGN)         cJSON_AddItemToArray(feat, cJSON_CreateString("wifi"));
        if (ci.features & CHIP_FEATURE_BT)               cJSON_AddItemToArray(feat, cJSON_CreateString("bt"));
        if (ci.features & CHIP_FEATURE_BLE)              cJSON_AddItemToArray(feat, cJSON_CreateString("ble"));
        if (ci.features & CHIP_FEATURE_IEEE802154)       cJSON_AddItemToArray(feat, cJSON_CreateString("802.15.4"));
        if (ci.features & CHIP_FEATURE_EMB_FLASH)        cJSON_AddItemToArray(feat, cJSON_CreateString("emb_flash"));
        if (ci.features & CHIP_FEATURE_EMB_PSRAM)        cJSON_AddItemToArray(feat, cJSON_CreateString("emb_psram"));
        cJSON_AddItemToObject(c, "features", feat);

        uint32_t flash_size = 0;
        if (esp_flash_get_size(NULL, &flash_size) == ESP_OK) {
            cJSON_AddNumberToObject(c, "flash_size", flash_size);
        }
        uint32_t flash_id = 0;
        if (esp_flash_read_id(NULL, &flash_id) == ESP_OK) {
            cJSON_AddNumberToObject(c, "flash_jedec_id", flash_id);
        }

        size_t psram_total = esp_psram_get_size();
        cJSON_AddNumberToObject(c, "psram_total", psram_total);

        cJSON_AddItemToObject(root, "chip", c);
    }

    {
        cJSON *m = cJSON_CreateObject();
        cJSON_AddNumberToObject(m, "internal_total",    heap_caps_get_total_size(MALLOC_CAP_INTERNAL));
        cJSON_AddNumberToObject(m, "internal_free",     heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        cJSON_AddNumberToObject(m, "internal_min_free", heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
        cJSON_AddNumberToObject(m, "internal_largest",  heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
        cJSON_AddNumberToObject(m, "spiram_total",      heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
        cJSON_AddNumberToObject(m, "spiram_free",       heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
        cJSON_AddNumberToObject(m, "spiram_min_free",   heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM));
        cJSON_AddNumberToObject(m, "spiram_largest",    heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));
        cJSON_AddItemToObject(root, "memory", m);
    }

    /* --- B) Partitions --------------------------------------------------- */
    {
        const esp_partition_t *running = esp_ota_get_running_partition();
        const esp_partition_t *boot    = esp_ota_get_boot_partition();

        cJSON *parts = cJSON_CreateArray();
        esp_partition_iterator_t it = esp_partition_find(
            ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, NULL);
        while (it) {
            const esp_partition_t *p = esp_partition_get(it);
            cJSON *e = cJSON_CreateObject();
            cJSON_AddStringToObject(e, "name",   p->label);
            cJSON_AddStringToObject(e, "kind",   part_type_str(p->type, p->subtype));
            cJSON_AddNumberToObject(e, "offset", p->address);
            cJSON_AddNumberToObject(e, "size",   p->size);
            cJSON_AddBoolToObject  (e, "running", running && p->address == running->address);
            cJSON_AddBoolToObject  (e, "bootnext", boot && p->address == boot->address);
            cJSON_AddItemToArray(parts, e);
            it = esp_partition_next(it);
        }
        esp_partition_iterator_release(it);
        cJSON_AddItemToObject(root, "partitions", parts);
    }

    /* NVS namespace stats — uses the default "nvs" partition. */
    {
        cJSON *n = cJSON_CreateObject();
        nvs_stats_t st;
        if (nvs_get_stats(NULL, &st) == ESP_OK) {
            cJSON_AddNumberToObject(n, "used_entries",       st.used_entries);
            cJSON_AddNumberToObject(n, "free_entries",       st.free_entries);
            cJSON_AddNumberToObject(n, "total_entries",      st.total_entries);
            cJSON_AddNumberToObject(n, "namespace_count",    st.namespace_count);
        }
        cJSON_AddItemToObject(root, "nvs", n);
    }

    /* Coredump partition state. */
    {
        cJSON *cd = cJSON_CreateObject();
        size_t cd_addr = 0, cd_size = 0;
        esp_err_t cd_err = esp_core_dump_image_get(&cd_addr, &cd_size);
        cJSON_AddBoolToObject  (cd, "present", cd_err == ESP_OK);
        if (cd_err == ESP_OK) {
            cJSON_AddNumberToObject(cd, "addr", cd_addr);
            cJSON_AddNumberToObject(cd, "size", cd_size);
        }
        cJSON_AddItemToObject(root, "coredump", cd);
    }

    /* --- C) MAC addresses ------------------------------------------------ */
    {
        cJSON *macs = cJSON_CreateObject();
        uint8_t m[6]; char s[18];
        if (esp_wifi_get_mac(WIFI_IF_STA, m) == ESP_OK) {
            snprintf(s, sizeof s, "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
            cJSON_AddStringToObject(macs, "sta", s);
        }
        if (esp_wifi_get_mac(WIFI_IF_AP, m) == ESP_OK) {
            snprintf(s, sizeof s, "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
            cJSON_AddStringToObject(macs, "ap", s);
        }
        if (esp_read_mac(m, ESP_MAC_BT) == ESP_OK) {
            snprintf(s, sizeof s, "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
            cJSON_AddStringToObject(macs, "bt", s);
        }
        cJSON_AddItemToObject(root, "mac", macs);
    }

    /* --- D) System ------------------------------------------------------- */
    {
        cJSON *s = cJSON_CreateObject();
        cJSON_AddStringToObject(s, "reset_reason", reset_reason_str());
        cJSON_AddStringToObject(s, "idf_version",  esp_get_idf_version());

        /* Shared sample_cpu_temp_c() handles install + enable + read;
         * having a second copy here used to race-fail the second install
         * with ESP_ERR_INVALID_STATE and silently drop cpu_temp_c from
         * whichever endpoint lost the race. */
        float tc = sample_cpu_temp_c();
        if (tc > -100.0f) cJSON_AddNumberToObject(s, "cpu_temp_c", tc);
        cJSON_AddItemToObject(root, "system", s);
    }

    /* --- D2) DNS relay + SPIRAM response cache --------------------------- */
    {
        dns_relay_stats_t ds;
        dns_relay_get_stats(&ds);
        cJSON *dc = cJSON_CreateObject();
        cJSON_AddBoolToObject  (dc, "enabled",   ds.enabled);
        cJSON_AddBoolToObject  (dc, "healthy",   ds.healthy);
        cJSON_AddNumberToObject(dc, "queries",   ds.queries);
        cJSON_AddNumberToObject(dc, "hits",      ds.hits);
        cJSON_AddNumberToObject(dc, "misses",    ds.misses);
        cJSON_AddNumberToObject(dc, "hit_pct",   ds.hit_pct);
        cJSON_AddNumberToObject(dc, "entries",   ds.entries);
        cJSON_AddNumberToObject(dc, "capacity",  ds.capacity);
        cJSON_AddNumberToObject(dc, "evictions", ds.evictions);
        cJSON_AddNumberToObject(dc, "cache_bytes", ds.cache_bytes);
        cJSON_AddItemToObject(root, "dns_cache", dc);
    }

    /* --- D3) microSD card (separate from flash; mounted FAT at /sdcard) -- */
    {
        sdlog_status_t sl;
        sdlog_get_status(&sl);
        cJSON *sdj = cJSON_CreateObject();
        cJSON_AddBoolToObject  (sdj, "present",    sl.present);
        cJSON_AddNumberToObject(sdj, "card_mb",    sl.card_mb);
        cJSON_AddNumberToObject(sdj, "free_mb",    sl.free_mb);
        cJSON_AddNumberToObject(sdj, "file_count", sl.file_count);
        cJSON_AddItemToObject(root, "sd", sdj);
    }

    /* --- E) FreeRTOS task list ------------------------------------------- */
    {
        UBaseType_t n = uxTaskGetNumberOfTasks();
        TaskStatus_t *arr = malloc(sizeof(TaskStatus_t) * n);
        cJSON *tasks = cJSON_CreateArray();
        if (arr) {
            UBaseType_t got = uxTaskGetSystemState(arr, n, NULL);
            for (UBaseType_t i = 0; i < got; i++) {
                cJSON *t = cJSON_CreateObject();
                cJSON_AddStringToObject(t, "name",     arr[i].pcTaskName ? arr[i].pcTaskName : "?");
                cJSON_AddNumberToObject(t, "prio",     arr[i].uxCurrentPriority);
                cJSON_AddNumberToObject(t, "stack_hwm", arr[i].usStackHighWaterMark);
                const char *st = "?";
                switch (arr[i].eCurrentState) {
                    case eRunning:   st = "running";   break;
                    case eReady:     st = "ready";     break;
                    case eBlocked:   st = "blocked";   break;
                    case eSuspended: st = "suspended"; break;
                    case eDeleted:   st = "deleted";   break;
                    case eInvalid:   st = "invalid";   break;
                }
                cJSON_AddStringToObject(t, "state", st);
                cJSON_AddItemToArray(tasks, t);
            }
            free(arr);
        }
        cJSON_AddItemToObject(root, "tasks", tasks);
    }

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    esp_err_t e = httpd_resp_sendstr(req, body);
    free(body);
    return e;
}
static const httpd_uri_t uri_system_diag = {
    .uri = "/api/system/diag", .method = HTTP_GET,
    .handler = system_diag_handler,
};

/* ---- Session management -------------------------------------------------
 * Single in-memory session, like the OLD repo. 32-byte random token hex-
 * encoded into a cookie. The token never touches NVS — reboot logs
 * everyone out, which is the intended fail-safe for a router that may
 * be repurposed. Timeout is an idle/sliding window: every authenticated
 * request bumps the expiry to now + s_session_timeout_s, so the
 * operator only gets kicked out after that many seconds of real
 * inactivity. The window length itself is operator-configurable from
 * the System tab and persisted under NVS key "auth_to_s". */
#define WEB_UI_SESSION_TOKEN_LEN     32
#define WEB_UI_SESSION_TIMEOUT_DEF_S (30 * 60)
#define WEB_UI_SESSION_TIMEOUT_MIN_S 60
#define WEB_UI_SESSION_TIMEOUT_MAX_S (8 * 60 * 60)

/* Multi-session table. The original "one global s_session_token" model
 * kicked any earlier session as soon as anyone (operator's other tab,
 * a curl probe, this very file's smoke tests) called /api/auth/login
 * — the new login overwrote the only slot and the previous holder
 * started bouncing off the login overlay. WEB_UI_SESSION_MAX
 * concurrent slots let the operator keep a tab on phone + laptop and
 * still allow scripted diag access without logging anyone out. */
#define WEB_UI_SESSION_MAX 4

typedef struct {
    char     token[WEB_UI_SESSION_TOKEN_LEN * 2 + 1];   /* hex; "" = unused */
    uint64_t expires_us;
} web_session_t;

static web_session_t s_sessions[WEB_UI_SESSION_MAX] = {0};
static uint32_t      s_session_timeout_s = WEB_UI_SESSION_TIMEOUT_DEF_S;
static bool          s_web_auth_enabled = true;

static void hex_encode(const uint8_t *src, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) sprintf(out + i * 2, "%02x", src[i]);
    out[len * 2] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Passwords arrive over operator-controlled local endpoints and must not
 * linger in reusable HTTP-task stack/heap blocks after verification. A
 * volatile byte loop prevents the compiler from removing the wipe as a
 * dead store. */
static void secure_wipe(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

static void wipe_json_string(cJSON *item)
{
    if (cJSON_IsString(item) && item->valuestring) {
        secure_wipe(item->valuestring, strlen(item->valuestring));
    }
}

static bool hex_decode_exact(const char *src, uint8_t *dst, size_t len)
{
    if (!src || strlen(src) != len * 2) return false;
    for (size_t i = 0; i < len; i++) {
        int hi = hex_nibble(src[i * 2]);
        int lo = hex_nibble(src[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static uint32_t session_timeout_clamp(uint32_t v)
{
    if (v == 0) return 0;  /* explicitly disabled */
    if (v < WEB_UI_SESSION_TIMEOUT_MIN_S) return WEB_UI_SESSION_TIMEOUT_MIN_S;
    if (v > WEB_UI_SESSION_TIMEOUT_MAX_S) return WEB_UI_SESSION_TIMEOUT_MAX_S;
    return v;
}

static void session_timeout_load(void)
{
    uint32_t v = 0;
    if (nvs_param_get_u32("auth_to_s", &v) == ESP_OK) {
        s_session_timeout_s = session_timeout_clamp(v);
    } else {
        s_session_timeout_s = WEB_UI_SESSION_TIMEOUT_DEF_S;
    }
}

static void web_auth_setting_load(void)
{
    uint8_t enabled = 1;
    if (nvs_param_get_u8("web_auth_en", &enabled) == ESP_OK) {
        s_web_auth_enabled = enabled != 0;
    } else {
        s_web_auth_enabled = true;
    }
}

/* Returns the slot index of any non-expired live session, or -1 if
 * the whole table is empty. Used by anonymous endpoints that just
 * want to know "is anyone logged in right now". */
static bool session_alive(void)
{
    uint64_t now = (uint64_t)esp_timer_get_time();
    for (int i = 0; i < WEB_UI_SESSION_MAX; i++) {
        if (s_sessions[i].token[0] && now < s_sessions[i].expires_us) return true;
    }
    return false;
}

/* Wipe every slot. Used by password-change and password-clear so a
 * credential rotation invalidates ALL existing tabs. Regular logout
 * uses session_clear_slot(). */
static void session_clear_all(void)
{
    for (int i = 0; i < WEB_UI_SESSION_MAX; i++) {
        s_sessions[i].token[0]   = '\0';
        s_sessions[i].expires_us = 0;
    }
}

/* Locate the slot a request's ts_session cookie points at. Returns
 * the index, or -1 if no cookie / no match / matched-but-expired. */
static int session_find_for_req(httpd_req_t *req)
{
    char hdr[160];
    if (httpd_req_get_hdr_value_str(req, "Cookie", hdr, sizeof hdr) != ESP_OK) return -1;
    const char *p = strstr(hdr, "ts_session=");
    if (!p) return -1;
    p += strlen("ts_session=");
    uint64_t now = (uint64_t)esp_timer_get_time();
    for (int i = 0; i < WEB_UI_SESSION_MAX; i++) {
        if (!s_sessions[i].token[0])    continue;
        if (now >= s_sessions[i].expires_us) continue;
        size_t n = strlen(s_sessions[i].token);
        if (strncmp(p, s_sessions[i].token, n) == 0
            && (p[n] == '\0' || p[n] == ';')) {
            return i;
        }
    }
    return -1;
}

/* Pick a slot for a fresh session: prefer an empty one; otherwise
 * recycle the slot whose expiry is the oldest (LRU). */
static int session_pick_new_slot(void)
{
    int      oldest_idx = 0;
    uint64_t oldest_exp = UINT64_MAX;
    for (int i = 0; i < WEB_UI_SESSION_MAX; i++) {
        if (!s_sessions[i].token[0]) return i;
        if (s_sessions[i].expires_us < oldest_exp) {
            oldest_exp  = s_sessions[i].expires_us;
            oldest_idx  = i;
        }
    }
    return oldest_idx;
}

/* Forge a fresh token, install it in the slot, return a pointer to
 * the token string (still owned by the slot). */
static const char *session_create(void)
{
    int idx = session_pick_new_slot();
    uint8_t raw[WEB_UI_SESSION_TOKEN_LEN];
    esp_fill_random(raw, sizeof raw);
    hex_encode(raw, sizeof raw, s_sessions[idx].token);
    s_sessions[idx].expires_us = s_session_timeout_s == 0
                               ? UINT64_MAX
                               : (uint64_t)esp_timer_get_time()
                                 + (uint64_t)s_session_timeout_s * 1000000ULL;
    return s_sessions[idx].token;
}

static void session_clear_slot(int idx)
{
    if (idx < 0 || idx >= WEB_UI_SESSION_MAX) return;
    s_sessions[idx].token[0]   = '\0';
    s_sessions[idx].expires_us = 0;
}

/* Push every alive slot's expiry to (now + current timeout). Hooked
 * from the System tab's timeout-change save so a freshly-extended
 * window applies to existing tabs immediately, not just to the next
 * authenticated request. */
static void session_extend_all_alive(void)
{
    uint64_t now = (uint64_t)esp_timer_get_time();
    uint64_t new_exp = s_session_timeout_s == 0
                     ? UINT64_MAX
                     : now + (uint64_t)s_session_timeout_s * 1000000ULL;
    for (int i = 0; i < WEB_UI_SESSION_MAX; i++) {
        if (s_sessions[i].token[0] && now < s_sessions[i].expires_us) {
            s_sessions[i].expires_us = new_exp;
        }
    }
}

/* Remaining seconds for the request's session, or 0 if none / expired. */
static uint32_t session_remaining_s_for_req(httpd_req_t *req)
{
    int idx = session_find_for_req(req);
    if (idx < 0) return 0;
    if (s_session_timeout_s == 0) return 0;
    uint64_t now = (uint64_t)esp_timer_get_time();
    if (now >= s_sessions[idx].expires_us) return 0;
    return (uint32_t)((s_sessions[idx].expires_us - now) / 1000000ULL);
}

static bool request_authenticated(httpd_req_t *req)
{
    /* The operator may intentionally expose ordinary configuration without
     * a password. Secret export/import remains independently protected. */
    if (!s_web_auth_enabled || !is_web_password_set()) return true;
    int idx = session_find_for_req(req);
    if (idx < 0) return false;
    /* Sliding window: every authenticated hit pushes the matching slot's
     * expiry out, so a tab the operator is actively poking never times out. */
    s_sessions[idx].expires_us = s_session_timeout_s == 0
                               ? UINT64_MAX
                               : (uint64_t)esp_timer_get_time()
                                 + (uint64_t)s_session_timeout_s * 1000000ULL;
    return true;
}

/* Read the operator-defined device label out of NVS, falling back to a
 * generic 'ESP32 Router' name. Caller frees the returned buffer. */
static char *device_name_dup(void)
{
    char *s = nvs_param_get_str("dev_name");
    if (s && s[0]) return s;
    free(s);
    return strdup("ESP32 Router");
}

static esp_err_t auth_status_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "auth_enabled", s_web_auth_enabled);
    cJSON_AddBoolToObject(root, "password_set", is_web_password_set());
    cJSON_AddBoolToObject(root, "auth_required",
                          s_web_auth_enabled && is_web_password_set());
    cJSON_AddBoolToObject(root, "authenticated", request_authenticated(req));
    /* Device name is fine to expose pre-auth — it's a label, not a secret. */
    char *name = device_name_dup();
    if (name) { cJSON_AddStringToObject(root, "device_name", name); free(name); }
    /* Idle-timeout window + remaining seconds so the SPA can drive the
     * discreet countdown next to the lock button without an extra round
     * trip. Both are safe pre-auth — they tell you the policy, not who's
     * logged in. */
    cJSON_AddNumberToObject(root, "session_timeout_s",   s_session_timeout_s);
    cJSON_AddNumberToObject(root, "session_remaining_s", session_remaining_s_for_req(req));
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

/* Per-client login throttling. Weak passwords are intentionally permitted by
 * policy, so the HTTP endpoint must not also be an unlimited online guessing
 * oracle. Sixteen buckets cover the ESP HTTP server's concurrent-client
 * limit without putting attacker-controlled state in NVS. */
typedef struct {
    uint32_t peer_ip;
    uint8_t failures;
    uint64_t blocked_until_us;
    uint64_t last_seen_us;
} login_guard_t;

#define LOGIN_GUARD_SLOTS 16
static login_guard_t s_login_guards[LOGIN_GUARD_SLOTS];

static uint32_t request_peer_ipv4(httpd_req_t *req)
{
    struct sockaddr_storage addr = {0};
    socklen_t len = sizeof addr;
    int fd = httpd_req_to_sockfd(req);
    if (fd < 0 || getpeername(fd, (struct sockaddr *)&addr, &len) != 0
        || addr.ss_family != AF_INET) return 0;
    return ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
}

static login_guard_t *login_guard_for(httpd_req_t *req)
{
    uint32_t ip = request_peer_ipv4(req);
    int oldest = 0;
    uint64_t oldest_seen = UINT64_MAX;
    for (int i = 0; i < LOGIN_GUARD_SLOTS; i++) {
        if (s_login_guards[i].peer_ip == ip && s_login_guards[i].last_seen_us)
            return &s_login_guards[i];
        if (!s_login_guards[i].last_seen_us) {
            oldest = i;
            oldest_seen = 0;
            break;
        }
        if (s_login_guards[i].last_seen_us < oldest_seen) {
            oldest_seen = s_login_guards[i].last_seen_us;
            oldest = i;
        }
    }
    memset(&s_login_guards[oldest], 0, sizeof s_login_guards[oldest]);
    s_login_guards[oldest].peer_ip = ip;
    return &s_login_guards[oldest];
}

static bool login_guard_reject(httpd_req_t *req, login_guard_t **out)
{
    login_guard_t *guard = login_guard_for(req);
    uint64_t now = (uint64_t)esp_timer_get_time();
    guard->last_seen_us = now;
    if (out) *out = guard;
    if (now >= guard->blocked_until_us) return false;
    uint32_t retry_s = (uint32_t)((guard->blocked_until_us - now + 999999ULL) / 1000000ULL);
    char retry[12];
    snprintf(retry, sizeof retry, "%u", (unsigned)retry_s);
    httpd_resp_set_status(req, "429 Too Many Requests");
    httpd_resp_set_hdr(req, "Retry-After", retry);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":false,\"reason\":\"rate_limited\"}");
    return true;
}

static void login_guard_failed(login_guard_t *guard)
{
    if (!guard) return;
    if (guard->failures < UINT8_MAX) guard->failures++;
    if (guard->failures < 3) return;
    unsigned shift = guard->failures - 3;
    uint32_t delay_s = shift >= 6 ? 60U : (1U << shift);
    guard->blocked_until_us = (uint64_t)esp_timer_get_time()
                            + (uint64_t)delay_s * 1000000ULL;
}


#define LOGIN_CHALLENGE_SLOTS 8
#define LOGIN_CHALLENGE_NONCE_LEN 16
#define LOGIN_CHALLENGE_TTL_US (30ULL * 1000000ULL)
static const char s_login_proof_context[] = "esp32-router-login-v1";

typedef struct {
    uint32_t peer_ip;
    uint8_t nonce[LOGIN_CHALLENGE_NONCE_LEN];
    uint64_t expires_us;
} login_challenge_t;

static login_challenge_t s_login_challenges[LOGIN_CHALLENGE_SLOTS];

static login_challenge_t *login_challenge_issue(httpd_req_t *req)
{
    uint64_t now = (uint64_t)esp_timer_get_time();
    int slot = 0;
    uint64_t oldest_expiry = UINT64_MAX;
    for (int i = 0; i < LOGIN_CHALLENGE_SLOTS; i++) {
        if (now >= s_login_challenges[i].expires_us) { slot = i; break; }
        if (s_login_challenges[i].expires_us < oldest_expiry) {
            oldest_expiry = s_login_challenges[i].expires_us;
            slot = i;
        }
    }
    login_challenge_t *challenge = &s_login_challenges[slot];
    challenge->peer_ip = request_peer_ipv4(req);
    esp_fill_random(challenge->nonce, sizeof challenge->nonce);
    challenge->expires_us = now + LOGIN_CHALLENGE_TTL_US;
    return challenge;
}

static bool login_challenge_consume(httpd_req_t *req, const uint8_t *nonce)
{
    uint64_t now = (uint64_t)esp_timer_get_time();
    uint32_t peer_ip = request_peer_ipv4(req);
    for (int i = 0; i < LOGIN_CHALLENGE_SLOTS; i++) {
        login_challenge_t *challenge = &s_login_challenges[i];
        if (challenge->expires_us > now && challenge->peer_ip == peer_ip
            && memcmp(challenge->nonce, nonce, sizeof challenge->nonce) == 0) {
            memset(challenge, 0, sizeof *challenge);
            return true;
        }
    }
    return false;
}

static esp_err_t auth_challenge_handler(httpd_req_t *req)
{
    login_guard_t *guard = NULL;
    if (login_guard_reject(req, &guard)) return ESP_FAIL;
    (void)guard;

    uint32_t iterations = 0;
    uint8_t salt[WEB_PASSWORD_SALT_LEN];
    cJSON *root = cJSON_CreateObject();
    if (!root) { httpd_resp_send_500(req); return ESP_FAIL; }
    if (!web_password_get_proof_params(&iterations, salt)) {
        cJSON_AddBoolToObject(root, "supported", false);
    } else {
        login_challenge_t *challenge = login_challenge_issue(req);
        char salt_hex[WEB_PASSWORD_SALT_LEN * 2 + 1];
        char nonce_hex[LOGIN_CHALLENGE_NONCE_LEN * 2 + 1];
        hex_encode(salt, sizeof salt, salt_hex);
        hex_encode(challenge->nonce, sizeof challenge->nonce, nonce_hex);
        cJSON_AddBoolToObject(root, "supported", true);
        cJSON_AddStringToObject(root, "algorithm", "PBKDF2-HMAC-SHA256");
        cJSON_AddNumberToObject(root, "iterations", iterations);
        cJSON_AddStringToObject(root, "salt", salt_hex);
        cJSON_AddStringToObject(root, "nonce", nonce_hex);
        cJSON_AddStringToObject(root, "context", s_login_proof_context);
    }
    memset(salt, 0, sizeof salt);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static esp_err_t auth_login_handler(httpd_req_t *req)
{
    login_guard_t *guard = NULL;
    if (login_guard_reject(req, &guard)) return ESP_FAIL;
    /* Cap the body at a sane size so a misbehaving client can't make us
     * allocate megabytes for a password field. */
    char buf[256];
    if (recv_body(req, buf, sizeof buf, NULL) != ESP_OK) {
        secure_wipe(buf, sizeof buf);
        return ESP_FAIL;
    }

    cJSON *body = cJSON_Parse(buf);
    secure_wipe(buf, sizeof buf);
    cJSON *pw = body ? cJSON_GetObjectItem(body, "password") : NULL;
    cJSON *nonce_json = body ? cJSON_GetObjectItem(body, "nonce") : NULL;
    cJSON *proof_json = body ? cJSON_GetObjectItem(body, "proof") : NULL;
    bool has_proof = cJSON_IsString(nonce_json) && cJSON_IsString(proof_json);
    if (!cJSON_IsString(pw) && !has_proof) {
        cJSON_Delete(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing password or proof");
        return ESP_FAIL;
    }

    bool ok = false;
    bool proof_required = false;
    if (has_proof) {
        uint8_t nonce[LOGIN_CHALLENGE_NONCE_LEN], proof[WEB_PASSWORD_PROOF_LEN];
        if (hex_decode_exact(nonce_json->valuestring, nonce, sizeof nonce)
            && hex_decode_exact(proof_json->valuestring, proof, sizeof proof)
            && login_challenge_consume(req, nonce)) {
            uint8_t message[sizeof s_login_proof_context - 1 + LOGIN_CHALLENGE_NONCE_LEN];
            memcpy(message, s_login_proof_context, sizeof s_login_proof_context - 1);
            memcpy(message + sizeof s_login_proof_context - 1, nonce, sizeof nonce);
            ok = verify_web_password_proof(message, sizeof message, proof);
            memset(message, 0, sizeof message);
        }
        memset(nonce, 0, sizeof nonce);
        memset(proof, 0, sizeof proof);
    } else {
        uint32_t proof_iterations = 0;
        uint8_t proof_salt[WEB_PASSWORD_SALT_LEN] = {0};
        proof_required = web_password_get_proof_params(&proof_iterations, proof_salt);
        (void)proof_iterations;
        memset(proof_salt, 0, sizeof proof_salt);
        if (!proof_required) ok = verify_web_password(pw->valuestring);
        secure_wipe(pw->valuestring, strlen(pw->valuestring));
    }
    cJSON_Delete(body);
    if (proof_required) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "challenge-response proof required");
        return ESP_FAIL;
    }


    if (!ok) {
        login_guard_failed(guard);
        /* Don't leak whether a password is set or just wrong — same 401
         * either way. */
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "unauthorised");
        return ESP_FAIL;
    }

    memset(guard, 0, sizeof *guard);

    const char *new_token = session_create();
    char cookie[160];
    if (s_session_timeout_s == 0) {
        snprintf(cookie, sizeof cookie,
                 "ts_session=%s; Path=/; HttpOnly; SameSite=Strict", new_token);
    } else {
        snprintf(cookie, sizeof cookie,
                 "ts_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%u",
                 new_token, (unsigned)s_session_timeout_s);
    }
    httpd_resp_set_hdr(req, "Set-Cookie", cookie);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t auth_logout_handler(httpd_req_t *req)
{
    /* Clear only the slot this request authenticates against — the
     * operator's other tabs (or a parallel scripted session) survive. */
    session_clear_slot(session_find_for_req(req));
    httpd_resp_set_hdr(req, "Set-Cookie", "ts_session=; Path=/; HttpOnly; Max-Age=0");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_auth_status = {
    .uri = "/api/auth/status", .method = HTTP_GET,  .handler = auth_status_handler,
};
static const httpd_uri_t uri_auth_challenge = {
    .uri = "/api/auth/challenge", .method = HTTP_GET, .handler = auth_challenge_handler,
};
static const httpd_uri_t uri_auth_login = {
    .uri = "/api/auth/login",  .method = HTTP_POST, .handler = auth_login_handler,
};
static const httpd_uri_t uri_auth_logout = {
    .uri = "/api/auth/logout", .method = HTTP_POST, .handler = auth_logout_handler,
};

#define WEB_UI_PASSWORD_MIN_LEN 4

/* Returns NULL if the password meets the admin-policy requirements,
 * otherwise a static, human-readable error string. The same wording
 * is shown by the SPA next to the password input. */
static const char *check_password_policy(const char *pw)
{
    if (!pw) return "missing password";
    size_t len = strlen(pw);
    if (len < WEB_UI_PASSWORD_MIN_LEN) {
        return "password must be at least 4 characters";
    }
    return NULL;
}

/* The unauthenticated setup endpoint must only be reachable through the
 * device's own access point. Otherwise, whenever no password is configured,
 * any client on the upstream LAN could claim the router by setting one first.
 * Comparing the accepted socket's local address (rather than trusting Host or
 * Origin headers) also covers custom AP subnets without adding configuration
 * coupling here. */
static bool request_arrived_on_ap(httpd_req_t *req)
{
    if (!wifi_ap_runtime_enabled()) return false;

    struct sockaddr_storage local = {0};
    socklen_t local_len = sizeof local;
    int fd = httpd_req_to_sockfd(req);
    if (fd < 0 || getsockname(fd, (struct sockaddr *)&local, &local_len) != 0
        || local.ss_family != AF_INET) return false;

    esp_netif_t *ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    esp_netif_ip_info_t ap_ip = {0};
    if (!ap || esp_netif_get_ip_info(ap, &ap_ip) != ESP_OK) return false;
    return ((struct sockaddr_in *)&local)->sin_addr.s_addr == ap_ip.ip.addr;
}

static esp_err_t auth_setup_handler(httpd_req_t *req)
{
    /* First-boot wizard endpoint — only accessible while no password is
     * set. Once one exists, the client must use change_password (with
     * auth + the old password) instead. */
    if (is_web_password_set()) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "password already set");
        return ESP_FAIL;
    }
    if (!request_arrived_on_ap(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                            "initial password setup is only allowed through the device AP");
        return ESP_FAIL;
    }

    char buf[256];
    if (recv_body(req, buf, sizeof buf, NULL) != ESP_OK) {
        secure_wipe(buf, sizeof buf);
        return ESP_FAIL;
    }

    cJSON *body = cJSON_Parse(buf);
    secure_wipe(buf, sizeof buf);
    cJSON *pw   = body ? cJSON_GetObjectItem(body, "password") : NULL;
    const char *pw_value = NULL;
    if (pw != NULL && cJSON_IsString(pw)) pw_value = pw->valuestring;
    const char *policy_err = check_password_policy(pw_value);
    if (policy_err) {
        wipe_json_string(pw);
        cJSON_Delete(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, policy_err);
        return ESP_FAIL;
    }

    esp_err_t err = set_web_password_hashed(pw_value);
    wipe_json_string(pw);
    cJSON_Delete(body);
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    /* Log the new operator in straight away so the SPA can transition
     * from the wizard into the normal dashboard without a second POST. */
    const char *setup_token = session_create();
    char cookie[160];
    if (s_session_timeout_s == 0) {
        snprintf(cookie, sizeof cookie,
                 "ts_session=%s; Path=/; HttpOnly; SameSite=Strict", setup_token);
    } else {
        snprintf(cookie, sizeof cookie,
                 "ts_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%u",
                 setup_token, (unsigned)s_session_timeout_s);
    }
    httpd_resp_set_hdr(req, "Set-Cookie", cookie);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_auth_setup = {
    .uri = "/api/auth/setup", .method = HTTP_POST, .handler = auth_setup_handler,
};

static esp_err_t auth_change_password_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    /* When the ordinary web gate is intentionally disabled, require_auth()
     * permits access by design. Keep old-password verification from becoming
     * an unlimited online guessing oracle by applying the same per-client
     * progressive delay as /api/auth/login. */
    login_guard_t *guard = NULL;
    if (login_guard_reject(req, &guard)) return ESP_FAIL;

    char buf[512];
    if (recv_body(req, buf, sizeof buf, NULL) != ESP_OK) {
        secure_wipe(buf, sizeof buf);
        return ESP_FAIL;
    }

    cJSON *body = cJSON_Parse(buf);
    secure_wipe(buf, sizeof buf);
    cJSON *old_pw = body ? cJSON_GetObjectItem(body, "old_password") : NULL;
    cJSON *new_pw = body ? cJSON_GetObjectItem(body, "new_password") : NULL;
    if (!cJSON_IsString(old_pw) || !cJSON_IsString(new_pw)) {
        wipe_json_string(old_pw);
        wipe_json_string(new_pw);
        cJSON_Delete(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing old_password or new_password");
        return ESP_FAIL;
    }

    if (!verify_web_password(old_pw->valuestring)) {
        login_guard_failed(guard);
        wipe_json_string(old_pw);
        wipe_json_string(new_pw);
        cJSON_Delete(body);
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "wrong old password");
        return ESP_FAIL;
    }

    const char *policy_err = check_password_policy(new_pw->valuestring);
    if (policy_err) {
        wipe_json_string(old_pw);
        wipe_json_string(new_pw);
        cJSON_Delete(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, policy_err);
        return ESP_FAIL;
    }

    esp_err_t err = set_web_password_hashed(new_pw->valuestring);
    wipe_json_string(old_pw);
    wipe_json_string(new_pw);
    cJSON_Delete(body);
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    memset(guard, 0, sizeof *guard);

    /* Force re-login after a successful change — matches the OLD repo's
     * behaviour and means a stolen-cookie attacker stays out even if the
     * operator updates the password from a separate browser tab. Wipes
     * every slot, not just the requesting one. */
    session_clear_all();
    httpd_resp_set_hdr(req, "Set-Cookie", "ts_session=; Path=/; HttpOnly; Max-Age=0");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_auth_change_password = {
    .uri = "/api/auth/change_password", .method = HTTP_POST, .handler = auth_change_password_handler,
};

static esp_err_t auth_clear_password_handler(httpd_req_t *req)
{
    /* Always require a real password-backed session, even when the ordinary
     * web gate is disabled, otherwise any LAN client could erase the
     * credential that protects secret backups and the remote console. */
    if (require_password_session(req) != ESP_OK) return ESP_FAIL;
    set_web_password_hashed("");
    session_clear_all();
    httpd_resp_set_hdr(req, "Set-Cookie", "ts_session=; Path=/; HttpOnly; Max-Age=0");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static const httpd_uri_t uri_auth_clear_password = {
    .uri = "/api/auth/clear_password", .method = HTTP_POST, .handler = auth_clear_password_handler,
};

/* ===================== SD flight-recorder ============================ */

/* GET /api/sdlog — recorder status: card presence/size, enable state,
 * verbosity, active file, file count, drops, bytes written. */
static esp_err_t sdlog_status_get_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    sdlog_status_t st;
    sdlog_get_status(&st);

    cJSON *root = cJSON_CreateObject();
    if (!root) { httpd_resp_send_500(req); return ESP_FAIL; }
    cJSON_AddBoolToObject  (root, "present",       st.present);
    cJSON_AddBoolToObject  (root, "enabled",       st.enabled);
    cJSON_AddNumberToObject(root, "sd_level",      st.sd_level);
    cJSON_AddNumberToObject(root, "console_level", st.console_level);
    cJSON_AddNumberToObject(root, "card_mb",       st.card_mb);
    cJSON_AddNumberToObject(root, "free_mb",       st.free_mb);
    cJSON_AddStringToObject(root, "current_file",  st.cur_file);
    cJSON_AddNumberToObject(root, "file_count",    st.file_count);
    cJSON_AddNumberToObject(root, "dropped",       st.dropped);
    cJSON_AddNumberToObject(root, "bytes_written", (double)st.bytes_written);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

/* POST /api/sdlog — { enabled:bool, sd_level:int, console_level:int } (all
 * optional/independent: SD enable+level, and the live console sink level).
 * Toggling enabled
 * starts/stops the writer. No-op (still 200) if no card is present. */
static esp_err_t sdlog_status_post_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char buf[128];
    if (recv_body(req, buf, sizeof buf, NULL) != ESP_OK) return ESP_FAIL;
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
        return ESP_FAIL;
    }

    const cJSON *en = cJSON_GetObjectItem(root, "enabled");
    const cJSON *sd = cJSON_GetObjectItem(root, "sd_level");
    uint8_t sd_level = SDLOG_LVL_WARN;
    if (cJSON_IsNumber(sd)) {
        int v = (int)sd->valuedouble;
        if (v < SDLOG_LVL_ERROR) v = SDLOG_LVL_ERROR;   /* SD: ERROR..INFO (OFF == disable) */
        if (v > SDLOG_LVL_INFO)  v = SDLOG_LVL_INFO;
        sd_level = (uint8_t)v;
    }
    if (cJSON_IsBool(en) && cJSON_IsTrue(en)) {
        sdlog_enable(sd_level);
    } else if (cJSON_IsBool(en) && cJSON_IsFalse(en)) {
        sdlog_disable();
    }
    /* Console (UART) output level — independent of the SD recorder,
     * applied live. Absent → unchanged, so the SD toggle and the console
     * selector can post separately. */
    const cJSON *cl = cJSON_GetObjectItem(root, "console_level");
    if (cJSON_IsNumber(cl)) {
        int v = (int)cl->valuedouble;
        if (v < SDLOG_LVL_OFF)  v = SDLOG_LVL_OFF;
        if (v > SDLOG_LVL_INFO) v = SDLOG_LVL_INFO;
        sdlog_set_console_level((uint8_t)v);
    }
    cJSON_Delete(root);

    /* Echo the resulting state so the SPA can re-render without a 2nd GET. */
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "present", sdlog_card_present());
    cJSON_AddBoolToObject(resp, "enabled", sdlog_is_enabled());
    char *body = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    httpd_resp_set_type(req, "application/json");
    esp_err_t e = httpd_resp_sendstr(req, body ? body : "{\"ok\":false}");
    free(body);
    return e;
}

/* GET /sdlog/list — [{name,size,mtime}], newest first. */
static esp_err_t sdlog_list_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    const int MAXN = 160;
    sdlog_file_info_t *files = malloc(sizeof(sdlog_file_info_t) * MAXN);
    if (!files) { httpd_resp_send_500(req); return ESP_FAIL; }
    int n = sdlog_list_files(files, MAXN);

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "name",  files[i].name);
        cJSON_AddNumberToObject(e, "size",  files[i].size);
        cJSON_AddNumberToObject(e, "mtime", files[i].mtime);
        cJSON_AddItemToArray(arr, e);
    }
    free(files);

    char *body = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

/* Pull a single query-string value into out (NUL-terminated). Returns
 * ESP_OK only when the key was present. */
static esp_err_t sdlog_query_str(httpd_req_t *req, const char *key,
                                 char *out, size_t out_sz)
{
    out[0] = '\0';
    size_t qlen = httpd_req_get_url_query_len(req) + 1;
    if (qlen <= 1) return ESP_FAIL;
    char *q = malloc(qlen);
    if (!q) return ESP_FAIL;
    esp_err_t err = ESP_FAIL;
    if (httpd_req_get_url_query_str(req, q, qlen) == ESP_OK)
        err = httpd_query_key_value(q, key, out, out_sz);
    free(q);
    return err;
}

/* Forward each file chunk straight into the HTTP response. */
static esp_err_t sdlog_dl_chunk_cb(void *ctx, const char *buf, size_t len)
{
    httpd_req_t *req = ctx;
    return (httpd_resp_send_chunk(req, buf, len) == ESP_OK) ? ESP_OK : ESP_FAIL;
}

/* GET /sdlog/download?file=NAME — streams the raw log file. */
static esp_err_t sdlog_download_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char name[SDLOG_NAME_MAX];
    if (sdlog_query_str(req, "file", name, sizeof name) != ESP_OK || !name[0]) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "file required");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    char disp[64];
    snprintf(disp, sizeof disp, "attachment; filename=\"%s\"", name);
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    esp_err_t err = sdlog_read_file(name, sdlog_dl_chunk_cb, req);
    if (err != ESP_OK) {
        /* If nothing was streamed yet, a 404 is still valid; once chunks
         * are in flight we can only cut the stream. */
        if (err == ESP_ERR_NOT_FOUND || err == ESP_ERR_INVALID_ARG) {
            httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no such log file");
            return ESP_FAIL;
        }
    }
    httpd_resp_send_chunk(req, NULL, 0);   /* terminate chunked response */
    return ESP_OK;
}

/* GET /sdlog/tail?file=NAME&n=N — last N lines as plain text. */
static esp_err_t sdlog_tail_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;

    char name[SDLOG_NAME_MAX];
    if (sdlog_query_str(req, "file", name, sizeof name) != ESP_OK || !name[0]) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "file required");
        return ESP_FAIL;
    }
    char nbuf[8] = {0};
    int n_lines = 100;
    if (sdlog_query_str(req, "n", nbuf, sizeof nbuf) == ESP_OK) {
        int v = atoi(nbuf);
        if (v > 0 && v <= 1000) n_lines = v;
    }

    /* PSRAM buffer so up to ~1000 lines fit (a 16 KB internal buffer capped
     * the tail at ~150 lines, making the 500/1000 line choices meaningless). */
    const size_t cap = 96 * 1024;
    char *buf = heap_caps_malloc(cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
    size_t out_len = 0;
    esp_err_t err = sdlog_tail_file(name, n_lines, buf, cap, &out_len);
    if (err != ESP_OK) {
        free(buf);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no such log file");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    err = httpd_resp_send(req, buf, out_len);
    free(buf);
    return err;
}

/* POST /api/sdlog/erase — delete every *.LOG file. */
static esp_err_t sdlog_erase_handler(httpd_req_t *req)
{
    if (require_auth(req) != ESP_OK) return ESP_FAIL;
    esp_err_t err = sdlog_erase_all();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, err == ESP_OK ? "{\"ok\":true}"
                                                 : "{\"ok\":false}");
}

static const httpd_uri_t uri_sdlog_status_get = {
    .uri = "/api/sdlog", .method = HTTP_GET, .handler = sdlog_status_get_handler,
};
static const httpd_uri_t uri_sdlog_status_post = {
    .uri = "/api/sdlog", .method = HTTP_POST, .handler = sdlog_status_post_handler,
};
static const httpd_uri_t uri_sdlog_list = {
    .uri = "/sdlog/list", .method = HTTP_GET, .handler = sdlog_list_handler,
};
static const httpd_uri_t uri_sdlog_download = {
    .uri = "/sdlog/download", .method = HTTP_GET, .handler = sdlog_download_handler,
};
static const httpd_uri_t uri_sdlog_tail = {
    .uri = "/sdlog/tail", .method = HTTP_GET, .handler = sdlog_tail_handler,
};
static const httpd_uri_t uri_sdlog_erase = {
    .uri = "/api/sdlog/erase", .method = HTTP_POST, .handler = sdlog_erase_handler,
};

/* Wrapper with the URI-handler signature (no err code) so the same
 * redirect can be both a wildcard URI handler AND a 404 fallback.
 * Wildcard match avoids the "httpd_uri: URI ... not found" WARN
 * spam the 404-only path used to emit. */
void web_ui_init(void)
{
    static httpd_handle_t server = NULL;
    if (server) return;

    /* Pick up the operator-configured session idle timeout before we
     * start handing out cookies, so the very first login uses the
     * persisted Max-Age instead of the compile-time default. */
    session_timeout_load();
    web_auth_setting_load();

    /* HTTPS→HTTP swap (2026-05-24): the self-signed esp_https_server
     * + mbedTLS combo cost ~20 KB heap per active TLS session and was
     * intermittently failing the handshake (mbedtls_ssl_handshake -0x7780
     * = MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) under load, which the
     * operator saw as "the web UI keeps logging me out". The original
     * reason we moved to HTTPS was that the encrypted-secrets backup
     * needs browser WebCrypto SubtleCrypto, and SubtleCrypto requires
     * a secure context. The SPA now ships SJCL as a pure-JS fallback
     * (vendor/sjcl.min.js, injected by gen_index_html_gz.py) and the
     * encrypt/decrypt helpers prefer SubtleCrypto when present but
     * gracefully fall back — so the backup feature still works over
     * plain HTTP, just with a one-time ~3 s PBKDF2 cost in pure JS
     * instead of WebCrypto's ~100 ms. */
    httpd_config_t conf           = HTTPD_DEFAULT_CONFIG();
    conf.uri_match_fn             = httpd_uri_match_wildcard;
    conf.max_uri_handlers         = 72;
    conf.stack_size               = 12288;
    /* The HTTP server needs three lwIP sockets internally. Four client slots
     * are enough for this SPA's post-login burst while preserving descriptors
     * for DERP, ntfy, MQTT and DNS. Also clamp against stale/generated
     * sdkconfig values so httpd_start still succeeds. */
    const size_t httpd_internal_sockets = 3;
    const size_t desired_http_clients = 4;
    if (CONFIG_LWIP_MAX_SOCKETS <= httpd_internal_sockets) {
        ESP_LOGE(TAG, "CONFIG_LWIP_MAX_SOCKETS=%d leaves no sockets for HTTP clients",
                 CONFIG_LWIP_MAX_SOCKETS);
        return;
    }
    const size_t available_http_clients =
        CONFIG_LWIP_MAX_SOCKETS - httpd_internal_sockets;
    conf.max_open_sockets = available_http_clients < desired_http_clients
                          ? available_http_clients
                          : desired_http_clients;
    conf.lru_purge_enable         = true;
    conf.server_port              = web_ui_configured_port();

    if (httpd_start(&server, &conf) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed");
        return;
    }
    httpd_register_uri_handler(server, &uri_index);
    httpd_register_uri_handler(server, &uri_status);
    httpd_register_uri_handler(server, &uri_network);
    httpd_register_uri_handler(server, &uri_network_save);
    httpd_register_uri_handler(server, &uri_network_scan);
    httpd_register_uri_handler(server, &uri_network_scan_result);
    httpd_register_uri_handler(server, &uri_wol);
    httpd_register_uri_handler(server, &uri_wol_save);
    httpd_register_uri_handler(server, &uri_wol_send);
    httpd_register_uri_handler(server, &uri_mqtt);
    httpd_register_uri_handler(server, &uri_mqtt_save);
    httpd_register_uri_handler(server, &uri_mqtt_publish);
    httpd_register_uri_handler(server, &uri_ntfy);
    httpd_register_uri_handler(server, &uri_ntfy_save);
    httpd_register_uri_handler(server, &uri_ntfy_test);
    httpd_register_uri_handler(server, &uri_tools_route);
    httpd_register_uri_handler(server, &uri_tools_ping);
    httpd_register_uri_handler(server, &uri_tools_trace);
    httpd_register_uri_handler(server, &uri_firewall);
    httpd_register_uri_handler(server, &uri_firewall_add);
    httpd_register_uri_handler(server, &uri_firewall_delete);
    httpd_register_uri_handler(server, &uri_firewall_clear);
    httpd_register_uri_handler(server, &uri_dhcp_reservations);
    httpd_register_uri_handler(server, &uri_dhcp_reservations_save);
    httpd_register_uri_handler(server, &uri_dhcp_leases);
    httpd_register_uri_handler(server, &uri_dhcp_kick);
    httpd_register_uri_handler(server, &uri_portmap);
    httpd_register_uri_handler(server, &uri_portmap_save);
    httpd_register_uri_handler(server, &uri_tailnet_forward);
    httpd_register_uri_handler(server, &uri_tailnet_forward_save);
    httpd_register_uri_handler(server, &uri_mac_deny);
    httpd_register_uri_handler(server, &uri_mac_deny_save);
    httpd_register_uri_handler(server, &uri_log_raw);
    httpd_register_uri_handler(server, &uri_log_clear);
    httpd_register_uri_handler(server, &uri_log_precrash);
    httpd_register_uri_handler(server, &uri_log_precrash_clear);
    httpd_register_uri_handler(server, &uri_tailscale);
    httpd_register_uri_handler(server, &uri_tailscale_save);
    httpd_register_uri_handler(server, &uri_tailscale_reset_identity);
    httpd_register_uri_handler(server, &uri_system);
    httpd_register_uri_handler(server, &uri_system_save);
    httpd_register_uri_handler(server, &uri_system_restart);
    httpd_register_uri_handler(server, &uri_system_factory_reset);
    httpd_register_uri_handler(server, &uri_system_ota);
    httpd_register_uri_handler(server, &uri_system_secrets_get);
    httpd_register_uri_handler(server, &uri_system_secrets_post);
    httpd_register_uri_handler(server, &uri_system_diag);
    httpd_register_uri_handler(server, &uri_system_debug_crash);
    httpd_register_uri_handler(server, &uri_auth_status);
    httpd_register_uri_handler(server, &uri_auth_challenge);
    httpd_register_uri_handler(server, &uri_auth_login);
    httpd_register_uri_handler(server, &uri_auth_logout);
    httpd_register_uri_handler(server, &uri_auth_setup);
    httpd_register_uri_handler(server, &uri_auth_change_password);
    httpd_register_uri_handler(server, &uri_auth_clear_password);
    httpd_register_uri_handler(server, &uri_sdlog_status_get);
    httpd_register_uri_handler(server, &uri_sdlog_status_post);
    httpd_register_uri_handler(server, &uri_sdlog_list);
    httpd_register_uri_handler(server, &uri_sdlog_download);
    httpd_register_uri_handler(server, &uri_sdlog_tail);
    httpd_register_uri_handler(server, &uri_sdlog_erase);
    ESP_LOGI(TAG, "web UI listening on :%d (HTTP)", conf.server_port);
    /* HTTPS redirect server gone with HTTPS itself — direct HTTP-on-80
     * is now the only listener, so nothing to redirect anywhere. */
}
