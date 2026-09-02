/* Tailscale 4via6 translation.
 *
 * Tailscale encodes a site ID and IPv4 destination inside
 * fd7a:115c:a1e0:b1a::/64. This module translates matching inner WireGuard
 * IPv6 packets to ordinary IPv4 before lwIP forwards them to the LAN. A small
 * flow table translates the corresponding IPv4 replies back to IPv6 before
 * WireGuard encrypts them. Existing lwIP NAPT therefore continues to provide
 * the Source-NAT advertised-routes behaviour selected by the operator.
 */
#include "fourvia6.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"
#include "nvs_params.h"

#define FOURVIA6_FLOW_COUNT 48
#define FOURVIA6_TCP_TIMEOUT_US (15LL * 60LL * 1000000LL)
#define FOURVIA6_UDP_TIMEOUT_US (2LL * 60LL * 1000000LL)
#define FOURVIA6_ICMP_TIMEOUT_US (30LL * 1000000LL)

static const char *TAG = "4via6";
static const uint8_t VIA_PREFIX[8] = {0xfd,0x7a,0x11,0x5c,0xa1,0xe0,0x0b,0x1a};

typedef struct {
    bool valid;
    uint8_t protocol;
    uint8_t client_v6[16];
    uint32_t peer_v4;       /* host byte order */
    uint32_t target_v4;     /* host byte order */
    uint16_t client_port;
    uint16_t target_port;
    int64_t last_seen_us;
} fourvia6_flow_t;

static bool s_enabled;
static uint32_t s_network;
static uint8_t s_prefix_len;
static uint16_t s_site_id;
static char s_lan_cidr[19];
static char s_prefix_text[64];
static fourvia6_flow_t s_flows[FOURVIA6_FLOW_COUNT];
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_translated;
static uint32_t s_dropped;

static bool parse_cidr(const char *text, uint32_t *network, uint8_t *prefix)
{
    if (!text || !text[0]) return false;
    unsigned a, b, c, d, bits;
    char tail;
    if (sscanf(text, "%u.%u.%u.%u/%u%c", &a, &b, &c, &d, &bits, &tail) != 5
        || a > 255 || b > 255 || c > 255 || d > 255 || bits > 32) return false;
    uint32_t ip = (a << 24) | (b << 16) | (c << 8) | d;
    uint32_t mask = bits == 0 ? 0 : (0xffffffffUL << (32 - bits));
    *network = ip & mask;
    *prefix = (uint8_t)bits;
    return true;
}

bool fourvia6_calculate_prefix(const char *lan_cidr, uint16_t site_id,
                               char *out, size_t out_size)
{
    uint32_t network;
    uint8_t bits;
    if (!out || out_size == 0 || !parse_cidr(lan_cidr, &network, &bits)) return false;
    /* The first 64 bits are Tailscale's fixed 4via6 range, followed by
     * a 32-bit site field. Site IDs are intentionally limited to the
     * documented 16-bit UI range, so its high half remains zero. */
    return snprintf(out, out_size,
                    "fd7a:115c:a1e0:b1a:0:%x:%x:%x/%u",
                    site_id, (unsigned)((network >> 16) & 0xffff),
                    (unsigned)(network & 0xffff), (unsigned)(96 + bits))
           < (int)out_size;
}

void fourvia6_init(void)
{
    uint8_t flag = 0;
    uint16_t site = 0;
    char *cidr = nvs_param_get_str("ts_4v6_lan");
    (void)nvs_param_get_u8("ts_4v6_en", &flag);
    (void)nvs_param_get_u16("ts_4v6_site", &site);
    uint32_t network = 0;
    uint8_t prefix = 0;
    bool valid = cidr && parse_cidr(cidr, &network, &prefix);
    taskENTER_CRITICAL(&s_lock);
    s_enabled = flag != 0 && valid;
    s_network = valid ? network : 0;
    s_prefix_len = valid ? prefix : 0;
    s_site_id = site;
    strlcpy(s_lan_cidr, valid ? cidr : "", sizeof s_lan_cidr);
    s_prefix_text[0] = '\0';
    if (valid) fourvia6_calculate_prefix(cidr, site, s_prefix_text, sizeof s_prefix_text);
    memset(s_flows, 0, sizeof s_flows);
    taskEXIT_CRITICAL(&s_lock);
    free(cidr);
    ESP_LOGI(TAG, "state=%s LAN=%s site=%u prefix=%s", s_enabled ? "enabled" : "disabled",
             s_lan_cidr[0] ? s_lan_cidr : "unset", s_site_id,
             s_prefix_text[0] ? s_prefix_text : "unset");
}

esp_err_t fourvia6_set_config(bool enabled, const char *lan_cidr,
                              uint16_t site_id, char *error, size_t error_size)
{
    uint32_t network = 0;
    uint8_t prefix = 0;
    if (enabled && !parse_cidr(lan_cidr, &network, &prefix)) {
        if (error) snprintf(error, error_size, "IPv4 LAN subnet must be a valid CIDR");
        return ESP_ERR_INVALID_ARG;
    }
    if (lan_cidr && lan_cidr[0] && !parse_cidr(lan_cidr, &network, &prefix)) {
        if (error) snprintf(error, error_size, "Invalid IPv4 LAN subnet");
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = nvs_param_set_u8("ts_4v6_en", enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_param_set_str("ts_4v6_lan", lan_cidr ? lan_cidr : "");
    if (err == ESP_OK) err = nvs_param_set_u16("ts_4v6_site", site_id);
    if (err != ESP_OK) {
        if (error) snprintf(error, error_size, "NVS write failed: %s", esp_err_to_name(err));
        return err;
    }
    fourvia6_init();
    return ESP_OK;
}

void fourvia6_get_status(fourvia6_status_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof *out);
    int64_t now = esp_timer_get_time();
    taskENTER_CRITICAL(&s_lock);
    out->enabled = s_enabled;
    out->site_id = s_site_id;
    strlcpy(out->lan_cidr, s_lan_cidr, sizeof out->lan_cidr);
    strlcpy(out->advertised_prefix, s_prefix_text, sizeof out->advertised_prefix);
    out->translated_packets = s_translated;
    out->dropped_packets = s_dropped;
    for (int i = 0; i < FOURVIA6_FLOW_COUNT; i++) {
        int64_t timeout = s_flows[i].protocol == 6 ? FOURVIA6_TCP_TIMEOUT_US
                        : s_flows[i].protocol == 17 ? FOURVIA6_UDP_TIMEOUT_US
                        : FOURVIA6_ICMP_TIMEOUT_US;
        if (s_flows[i].valid && now - s_flows[i].last_seen_us <= timeout) out->active_flows++;
    }
    taskEXIT_CRITICAL(&s_lock);
}

void fourvia6_effective_routes(const char *ipv4_routes, char *out, size_t out_size)
{
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (ipv4_routes && ipv4_routes[0]) strlcpy(out, ipv4_routes, out_size);
    taskENTER_CRITICAL(&s_lock);
    bool add = s_enabled && s_prefix_text[0];
    char prefix[64];
    strlcpy(prefix, s_prefix_text, sizeof prefix);
    taskEXIT_CRITICAL(&s_lock);
    if (add) {
        size_t used = strlen(out);
        snprintf(out + used, out_size - used, "%s%s", used ? "\n" : "", prefix);
    }
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t length)
{
    while (length >= 2) {
        sum += ((uint16_t)data[0] << 8) | data[1];
        data += 2; length -= 2;
    }
    if (length) sum += (uint16_t)data[0] << 8;
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t checksum_plain(const uint8_t *data, size_t length)
{
    return checksum_finish(checksum_add(0, data, length));
}

static uint16_t checksum_v4(uint32_t src, uint32_t dst, uint8_t protocol,
                            const uint8_t *payload, size_t length)
{
    uint8_t pseudo[12] = {
        (uint8_t)(src >> 24), (uint8_t)(src >> 16), (uint8_t)(src >> 8), (uint8_t)src,
        (uint8_t)(dst >> 24), (uint8_t)(dst >> 16), (uint8_t)(dst >> 8), (uint8_t)dst,
        0, protocol, (uint8_t)(length >> 8), (uint8_t)length
    };
    return checksum_finish(checksum_add(checksum_add(0, pseudo, sizeof pseudo), payload, length));
}

static uint16_t checksum_v6(const uint8_t src[16], const uint8_t dst[16],
                            uint8_t next_header, const uint8_t *payload, size_t length)
{
    uint32_t sum = checksum_add(checksum_add(0, src, 16), dst, 16);
    uint8_t tail[8] = {(uint8_t)(length >> 24), (uint8_t)(length >> 16),
                       (uint8_t)(length >> 8), (uint8_t)length, 0, 0, 0, next_header};
    return checksum_finish(checksum_add(checksum_add(sum, tail, sizeof tail), payload, length));
}

static uint16_t read16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static void write16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static bool target_allowed(uint32_t ip)
{
    if ((ip >> 24) == 127 || (ip >> 28) == 0xe || ip == 0 || ip == 0xffffffffUL) return false;
    if ((ip & 0xffc00000UL) == 0x64400000UL) return false;
    uint32_t mask = s_prefix_len == 0 ? 0 : (0xffffffffUL << (32 - s_prefix_len));
    return (ip & mask) == s_network;
}

static void flow_remember(const uint8_t client_v6[16], uint32_t peer_v4,
                          uint32_t target_v4, uint8_t protocol,
                          uint16_t client_port, uint16_t target_port)
{
    int64_t now = esp_timer_get_time();
    taskENTER_CRITICAL(&s_lock);
    int slot = -1;
    int64_t oldest = INT64_MAX;
    for (int i = 0; i < FOURVIA6_FLOW_COUNT; i++) {
        if (s_flows[i].valid && s_flows[i].protocol == protocol
            && s_flows[i].peer_v4 == peer_v4 && s_flows[i].target_v4 == target_v4
            && s_flows[i].client_port == client_port && s_flows[i].target_port == target_port
            && memcmp(s_flows[i].client_v6, client_v6, 16) == 0) { slot = i; break; }
        if (!s_flows[i].valid) slot = i;
        else if (slot < 0 && s_flows[i].last_seen_us < oldest) {
            oldest = s_flows[i].last_seen_us; slot = i;
        }
    }
    if (slot >= 0) {
        s_flows[slot] = (fourvia6_flow_t){.valid=true,.protocol=protocol,
            .peer_v4=peer_v4,.target_v4=target_v4,.client_port=client_port,
            .target_port=target_port,.last_seen_us=now};
        memcpy(s_flows[slot].client_v6, client_v6, 16);
    }
    taskEXIT_CRITICAL(&s_lock);
}

static bool flow_lookup(uint32_t peer_v4, uint32_t target_v4, uint8_t protocol,
                        uint16_t client_port, uint16_t target_port,
                        fourvia6_flow_t *out)
{
    int64_t now = esp_timer_get_time();
    bool found = false;
    taskENTER_CRITICAL(&s_lock);
    for (int i = 0; i < FOURVIA6_FLOW_COUNT; i++) {
        if (!s_flows[i].valid) continue;
        int64_t timeout = protocol == 6 ? FOURVIA6_TCP_TIMEOUT_US
                        : protocol == 17 ? FOURVIA6_UDP_TIMEOUT_US
                        : FOURVIA6_ICMP_TIMEOUT_US;
        if (now - s_flows[i].last_seen_us > timeout) { s_flows[i].valid = false; continue; }
        if (s_flows[i].protocol == protocol && s_flows[i].peer_v4 == peer_v4
            && s_flows[i].target_v4 == target_v4
            && s_flows[i].client_port == client_port && s_flows[i].target_port == target_port) {
            s_flows[i].last_seen_us = now;
            *out = s_flows[i]; found = true; break;
        }
    }
    taskEXIT_CRITICAL(&s_lock);
    return found;
}

bool fourvia6_translate_wg_input(struct pbuf *packet, struct netif *wg_netif,
                                 const ip_addr_t *peer_tailscale_ip)
{
    uint8_t header[40];
    if (!packet || packet->tot_len < 40 || pbuf_copy_partial(packet, header, 40, 0) != 40
        || (header[0] >> 4) != 6) return false;
    if (!s_enabled || memcmp(header + 24, VIA_PREFIX, 8) != 0) return false;
    uint32_t site = ((uint32_t)header[32] << 24) | ((uint32_t)header[33] << 16)
                  | ((uint32_t)header[34] << 8) | header[35];
    if (site != s_site_id) return false;

    uint32_t target = ((uint32_t)header[36] << 24) | ((uint32_t)header[37] << 16)
                    | ((uint32_t)header[38] << 8) | header[39];
    uint16_t payload_len = read16(header + 4);
    uint8_t protocol = header[6];
    uint32_t peer_v4 = 0;
    if (peer_tailscale_ip && IP_IS_V4(peer_tailscale_ip))
        peer_v4 = lwip_ntohl(ip4_addr_get_u32(ip_2_ip4(peer_tailscale_ip)));
    if (!target_allowed(target) || peer_v4 == 0 || packet->tot_len < 40 + payload_len
        || header[7] <= 1 || (protocol != 6 && protocol != 17 && protocol != 58)) {
        taskENTER_CRITICAL(&s_lock); s_dropped++; taskEXIT_CRITICAL(&s_lock);
        pbuf_free(packet);
        return true;
    }

    size_t v4_payload_len = payload_len;
    struct pbuf *out = pbuf_alloc(PBUF_RAW, 20 + v4_payload_len, PBUF_RAM);
    if (!out) { pbuf_free(packet); return true; }
    uint8_t *bytes = out->payload;
    memset(bytes, 0, 20);
    if (pbuf_copy_partial(packet, bytes + 20, payload_len, 40) != payload_len) {
        pbuf_free(out); pbuf_free(packet); return true;
    }
    uint16_t client_port = 0, target_port = 0;
    uint8_t v4_protocol = protocol;
    if (protocol == 6 || protocol == 17) {
        if (payload_len < 8 || (protocol == 6 && payload_len < 20)) {
            pbuf_free(out); pbuf_free(packet); return true;
        }
        client_port = read16(bytes + 20);
        target_port = read16(bytes + 22);
        size_t checksum_offset = protocol == 6 ? 16 : 6;
        write16(bytes + 20 + checksum_offset, 0);
        uint16_t check = checksum_v4(peer_v4, target, protocol, bytes + 20, payload_len);
        if (protocol == 17 && check == 0) check = 0xffff;
        write16(bytes + 20 + checksum_offset, check);
    } else {
        if (payload_len < 8 || (bytes[20] != 128 && bytes[20] != 129)) {
            pbuf_free(out); pbuf_free(packet); return true;
        }
        bytes[20] = bytes[20] == 128 ? 8 : 0;
        v4_protocol = 1;
        client_port = read16(bytes + 24);
        write16(bytes + 22, 0);
        write16(bytes + 22, checksum_plain(bytes + 20, payload_len));
    }
    bytes[0] = 0x45;
    bytes[1] = header[0] & 0x0f;
    write16(bytes + 2, (uint16_t)(20 + payload_len));
    write16(bytes + 4, (uint16_t)esp_random());
    write16(bytes + 6, 0x4000);
    bytes[8] = header[7] - 1;
    bytes[9] = v4_protocol;
    bytes[12] = (uint8_t)(peer_v4 >> 24); bytes[13] = (uint8_t)(peer_v4 >> 16);
    bytes[14] = (uint8_t)(peer_v4 >> 8);  bytes[15] = (uint8_t)peer_v4;
    bytes[16] = (uint8_t)(target >> 24); bytes[17] = (uint8_t)(target >> 16);
    bytes[18] = (uint8_t)(target >> 8);  bytes[19] = (uint8_t)target;
    write16(bytes + 10, checksum_plain(bytes, 20));
    flow_remember(header + 8, peer_v4, target, v4_protocol, client_port, target_port);
    taskENTER_CRITICAL(&s_lock); s_translated++; taskEXIT_CRITICAL(&s_lock);
    pbuf_free(packet);
    if (tcpip_input(out, wg_netif) != ERR_OK) pbuf_free(out);
    return true;
}

struct pbuf *fourvia6_translate_wg_output(struct pbuf *packet)
{
    uint8_t h[60];
    if (!s_enabled || !packet || packet->tot_len < 20
        || pbuf_copy_partial(packet, h, sizeof h, 0) < 20 || (h[0] >> 4) != 4) return NULL;
    size_t ihl = (h[0] & 0x0f) * 4;
    uint16_t total = read16(h + 2);
    uint16_t fragment = read16(h + 6);
    uint8_t protocol = h[9];
    if (ihl < 20 || total < ihl || total > packet->tot_len || (fragment & 0x3fff)
        || (protocol != 6 && protocol != 17 && protocol != 1)) return NULL;
    uint32_t target = ((uint32_t)h[12] << 24) | ((uint32_t)h[13] << 16)
                    | ((uint32_t)h[14] << 8) | h[15];
    uint32_t peer = ((uint32_t)h[16] << 24) | ((uint32_t)h[17] << 16)
                  | ((uint32_t)h[18] << 8) | h[19];
    if (total < ihl + 8) return NULL;
    uint8_t ports[8];
    if (pbuf_copy_partial(packet, ports, sizeof ports, ihl) != sizeof ports) return NULL;
    uint16_t target_port = 0, client_port = 0;
    if (protocol == 6 || protocol == 17) {
        target_port = read16(ports);
        client_port = read16(ports + 2);
    } else {
        if (ports[0] != 0 && ports[0] != 8) return NULL;
        client_port = read16(ports + 4);
    }
    fourvia6_flow_t flow;
    if (!flow_lookup(peer, target, protocol, client_port, target_port, &flow)) return NULL;

    size_t payload_len = total - ihl;
    struct pbuf *out = pbuf_alloc(PBUF_RAW, 40 + payload_len, PBUF_RAM);
    if (!out) return NULL;
    uint8_t *bytes = out->payload;
    memset(bytes, 0, 40);
    if (pbuf_copy_partial(packet, bytes + 40, payload_len, ihl) != payload_len) {
        pbuf_free(out); return NULL;
    }
    bytes[0] = 0x60 | (h[1] >> 4);
    write16(bytes + 4, (uint16_t)payload_len);
    bytes[6] = protocol == 1 ? 58 : protocol;
    bytes[7] = h[8] > 1 ? h[8] - 1 : 1;
    memcpy(bytes + 8, VIA_PREFIX, 8);
    bytes[18] = (uint8_t)(s_site_id >> 8); bytes[19] = (uint8_t)s_site_id;
    bytes[20] = (uint8_t)(target >> 24); bytes[21] = (uint8_t)(target >> 16);
    bytes[22] = (uint8_t)(target >> 8); bytes[23] = (uint8_t)target;
    memcpy(bytes + 24, flow.client_v6, 16);
    if (protocol == 6 || protocol == 17) {
        size_t offset = protocol == 6 ? 16 : 6;
        write16(bytes + 40 + offset, 0);
        uint16_t check = checksum_v6(bytes + 8, bytes + 24, protocol, bytes + 40, payload_len);
        if (protocol == 17 && check == 0) check = 0xffff;
        write16(bytes + 40 + offset, check);
    } else {
        bytes[40] = bytes[40] == 0 ? 129 : 128;
        write16(bytes + 42, 0);
        write16(bytes + 42, checksum_v6(bytes + 8, bytes + 24, 58, bytes + 40, payload_len));
    }
    taskENTER_CRITICAL(&s_lock); s_translated++; taskEXIT_CRITICAL(&s_lock);
    return out;
}
