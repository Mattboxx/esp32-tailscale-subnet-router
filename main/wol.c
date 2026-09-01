/* Wake-on-LAN persistence + UDP magic-packet transport. */
#include "wol.h"

#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "nvs_params.h"

#define WOL_NVS_KEY "wol_devices"

static const char *TAG = "wol";
static wol_device_t s_devices[WOL_MAX_DEVICES];
static int s_count;
static bool s_loaded;
static SemaphoreHandle_t s_lock;

static void ensure_lock(void)
{
    if (!s_lock) s_lock = xSemaphoreCreateMutex();
}

bool wol_parse_mac(const char *text, uint8_t out[6])
{
    if (!text || !out) return false;
    unsigned v[6];
    int consumed = 0;
    int matched = sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%n",
                         &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &consumed);
    if (matched != 6) {
        consumed = 0;
        matched = sscanf(text, "%2x-%2x-%2x-%2x-%2x-%2x%n",
                         &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &consumed);
    }
    while (text[consumed] == ' ' || text[consumed] == '\t') consumed++;
    if (matched != 6 || text[consumed] != '\0') {
        return false;
    }
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return true;
}

void wol_format_mac(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void wol_init(void)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_devices, 0, sizeof s_devices);
    s_count = 0;

    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
        size_t size = sizeof s_devices;
        if (nvs_get_blob(nvs, WOL_NVS_KEY, s_devices, &size) == ESP_OK
            && size == sizeof s_devices) {
            for (int i = 0; i < WOL_MAX_DEVICES; i++) {
                if (!s_devices[i].valid) continue;
                if (s_devices[i].port == 0) s_devices[i].port = 9;
                s_count++;
            }
        }
        nvs_close(nvs);
    }
    s_loaded = true;
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "loaded %d Wake-on-LAN target(s)", s_count);
}

static void ensure_loaded(void)
{
    if (!s_loaded) wol_init();
}

int wol_count(void)
{
    ensure_loaded();
    return s_count;
}

bool wol_get(int index, wol_device_t *out)
{
    ensure_loaded();
    if (!out || index < 0) return false;
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int logical = 0;
    bool found = false;
    for (int i = 0; i < WOL_MAX_DEVICES; i++) {
        if (!s_devices[i].valid) continue;
        if (logical++ == index) {
            memcpy(out, &s_devices[i], sizeof *out);
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_lock);
    return found;
}

esp_err_t wol_set_all(const wol_device_t *devices, int count)
{
    if (!devices && count > 0) return ESP_ERR_INVALID_ARG;
    if (count < 0) count = 0;
    if (count > WOL_MAX_DEVICES) count = WOL_MAX_DEVICES;
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_devices, 0, sizeof s_devices);
    s_count = 0;
    for (int i = 0; i < count; i++) {
        bool nonzero = false;
        for (int b = 0; b < 6; b++) nonzero |= devices[i].mac[b] != 0;
        if (!nonzero) continue;
        s_devices[s_count] = devices[i];
        s_devices[s_count].valid = 1;
        if (s_devices[s_count].port == 0) s_devices[s_count].port = 9;
        s_count++;
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_set_blob(nvs, WOL_NVS_KEY, s_devices, sizeof s_devices);
        if (err == ESP_OK) err = nvs_commit(nvs);
        nvs_close(nvs);
    }
    s_loaded = true;
    xSemaphoreGive(s_lock);
    if (err == ESP_OK) ESP_LOGI(TAG, "saved %d Wake-on-LAN target(s)", s_count);
    else ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(err));
    return err;
}

static bool derive_sta_broadcast(char out[16])
{
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info = {0};
    if (!sta || esp_netif_get_ip_info(sta, &info) != ESP_OK || !info.ip.addr) return false;
    ip4_addr_t broadcast = { .addr = info.ip.addr | ~info.netmask.addr };
    snprintf(out, 16, IPSTR, IP2STR(&broadcast));
    return true;
}

esp_err_t wol_send_mac(const uint8_t mac[6], const char *broadcast, uint16_t port)
{
    if (!mac) return ESP_ERR_INVALID_ARG;
    char derived[16];
    if (!broadcast || !broadcast[0]) {
        if (!derive_sta_broadcast(derived)) return ESP_ERR_INVALID_STATE;
        broadcast = derived;
    }
    if (port == 0) port = 9;

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (inet_pton(AF_INET, broadcast, &dst.sin_addr) != 1) return ESP_ERR_INVALID_ARG;

    uint8_t packet[6 + 16 * 6];
    memset(packet, 0xff, 6);
    for (int i = 0; i < 16; i++) memcpy(packet + 6 + i * 6, mac, 6);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return ESP_FAIL;
    int yes = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof yes) != 0) {
        close(sock);
        return ESP_FAIL;
    }
    esp_err_t result = ESP_OK;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (sendto(sock, packet, sizeof packet, 0,
                   (struct sockaddr *)&dst, sizeof dst) != sizeof packet) {
            result = ESP_FAIL;
            break;
        }
        if (attempt < 2) vTaskDelay(pdMS_TO_TICKS(30));
    }
    close(sock);

    char mac_text[18];
    wol_format_mac(mac, mac_text);
    if (result == ESP_OK) ESP_LOGI(TAG, "magic packet -> %s via %s:%u", mac_text, broadcast, port);
    else ESP_LOGE(TAG, "magic packet send failed for %s", mac_text);
    return result;
}

esp_err_t wol_send_index(int index)
{
    wol_device_t device;
    if (!wol_get(index, &device)) return ESP_ERR_NOT_FOUND;
    return wol_send_mac(device.mac, device.broadcast, device.port);
}

esp_err_t wol_send_saved_mac_text(const char *mac_text)
{
    uint8_t wanted[6];
    if (!wol_parse_mac(mac_text, wanted)) return ESP_ERR_INVALID_ARG;
    int count = wol_count();
    for (int i = 0; i < count; i++) {
        wol_device_t device;
        if (wol_get(i, &device) && memcmp(device.mac, wanted, 6) == 0) {
            return wol_send_mac(device.mac, device.broadcast, device.port);
        }
    }
    return ESP_ERR_NOT_FOUND;
}
