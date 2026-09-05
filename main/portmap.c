/* See portmap.h for the rationale.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs.h"
#include "lwip/lwip_napt.h"
#include "lwip/tcpip.h"
#include "nvs_params.h"
#include "portmap.h"
#include "tailnet_forward.h"
#include "web_ui.h"

static const char *TAG = "portmap";

#define NVS_KEY "portmap"

static portmap_entry_t s_table[PORTMAP_MAX];
static int             s_count  = 0;
static bool            s_loaded = false;
typedef struct { uint8_t proto; uint16_t port; } installed_t;
static installed_t s_installed[PORTMAP_MAX + TAILNET_FORWARD_MAX];
static int s_installed_count;

static void clear_cache(void)
{
    memset(s_table, 0, sizeof s_table);
    s_count = 0;
}

void portmap_init(void)
{
    clear_cache();

    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
        size_t expected = sizeof s_table;
        size_t actual   = expected;
        if (nvs_get_blob(nvs, NVS_KEY, s_table, &actual) == ESP_OK
            && actual == expected) {
            for (int i = 0; i < PORTMAP_MAX; i++) {
                if (s_table[i].valid) s_count++;
            }
            ESP_LOGI(TAG, "loaded %d portmap(s) from NVS", s_count);
        } else {
            clear_cache();
        }
        nvs_close(nvs);
    }

    s_loaded = true;
}

int portmap_count(void)
{
    if (!s_loaded) portmap_init();
    return s_count;
}

bool portmap_get(int i, portmap_entry_t *out)
{
    if (!s_loaded) portmap_init();
    if (!out || i < 0 || i >= PORTMAP_MAX) return false;
    if (!s_table[i].valid) return false;
    memcpy(out, &s_table[i], sizeof *out);
    return true;
}

static bool entry_is_filled(const portmap_entry_t *e)
{
    if (!e->ext_port || !e->int_port || !e->int_ip) return false;
    if (e->proto != PORTMAP_PROTO_TCP && e->proto != PORTMAP_PROTO_UDP) return false;
    return true;
}

bool portmap_listen_conflicts(uint8_t proto, uint16_t port)
{
    for (int i = 0; i < PORTMAP_MAX; i++)
        if (s_table[i].valid && s_table[i].proto == proto && s_table[i].ext_port == port) return true;
    return false;
}

esp_err_t portmap_set_all(const portmap_entry_t *arr, int count)
{
    if (!arr) return ESP_ERR_INVALID_ARG;
    if (count < 0) count = 0;
    if (count > PORTMAP_MAX) count = PORTMAP_MAX;

    for (int i = 0; i < count; i++) {
        if (!entry_is_filled(&arr[i])) continue;
        if (tailnet_forward_listen_conflicts(arr[i].proto, arr[i].ext_port)) return ESP_ERR_INVALID_STATE;
        if (arr[i].proto == PORTMAP_PROTO_TCP && arr[i].ext_port == web_ui_configured_port()) return ESP_ERR_INVALID_STATE;
        for (int j = 0; j < i; j++)
            if (entry_is_filled(&arr[j]) && arr[j].proto == arr[i].proto && arr[j].ext_port == arr[i].ext_port)
                return ESP_ERR_INVALID_STATE;
    }
    clear_cache();
    for (int i = 0; i < count; i++) {
        if (!entry_is_filled(&arr[i])) continue;
        memcpy(&s_table[s_count], &arr[i], sizeof s_table[0]);
        s_table[s_count].valid = 1;
        s_count++;
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(nvs, NVS_KEY, s_table, sizeof s_table);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "saved %d portmap(s) to NVS", s_count);
        /* Re-install so the live NAPT bindings track the new table. */
        portmap_install_all();
    } else {
        ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(err));
    }
    s_loaded = true;
    return err;
}

static void portmap_install_cb(void *arg)
{
    (void)arg;
    if (!s_loaded) portmap_init();

    /* Pull the current STA IP — without it the NAPT bind has nothing to
     * tie the external side to. Skip silently when STA isn't up yet;
     * we'll be called again from IP_GOT_IP. */
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info = {0};
    if (!sta || esp_netif_get_ip_info(sta, &ip_info) != ESP_OK || !ip_info.ip.addr) {
        ESP_LOGI(TAG, "STA has no IP yet; deferring portmap install");
        return;
    }
    uint32_t bind_ip = ip_info.ip.addr;

    /* The lwIP table is global. Remove everything we installed last time,
     * including deleted rules, before rebuilding both independent tables. */
    for (int i = 0; i < s_installed_count; i++)
        ip_portmap_remove(s_installed[i].proto, s_installed[i].port);
    s_installed_count = 0;
    tailnet_forward_prepare_install();
    int ap_installed = 0, tailnet_installed = 0;
    for (int i = 0; i < PORTMAP_MAX; i++) {
        if (!s_table[i].valid) continue;
        if (ip_portmap_add(s_table[i].proto, bind_ip, s_table[i].ext_port,
                           s_table[i].int_ip, s_table[i].int_port)) {
            s_installed[s_installed_count++] = (installed_t){s_table[i].proto, s_table[i].ext_port};
            ap_installed++;
        }
    }
    for (int i = 0; i < TAILNET_FORWARD_MAX; i++) {
        uint8_t proto; uint16_t listen, dport; uint32_t destination;
        if (!tailnet_forward_get_mapping(i, &proto, &listen, &destination, &dport)) continue;
        bool ok = ip_portmap_add(proto, bind_ip, listen, destination, dport);
        if (ok) {
            s_installed[s_installed_count++] = (installed_t){proto, listen};
            tailnet_installed++;
        }
        tailnet_forward_mark_installed(i, ok, ok ? NULL : "lwIP port-map table full");
    }
    ESP_LOGI(TAG, "installed %d AP-side + %d LAN-to-Tailnet mapping(s) on STA " IPSTR,
             ap_installed, tailnet_installed, IP2STR(&ip_info.ip));
}

void portmap_install_all(void)
{
    /* ip_portmap_* mutates lwIP-global tables. Serialize it on tcpip_thread
     * instead of racing packet input from the HTTP/event/manager tasks. */
    err_t err = tcpip_callback_with_block(portmap_install_cb, NULL, 1);
    if (err != ERR_OK) ESP_LOGE(TAG, "portmap refresh scheduling failed: %d", err);
}
