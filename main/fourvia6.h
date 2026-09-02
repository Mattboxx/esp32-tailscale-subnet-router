/* Optional Tailscale 4via6 translator for overlapping IPv4 LANs. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool enabled;
    char lan_cidr[19];
    uint16_t site_id;
    char advertised_prefix[64];
    uint32_t translated_packets;
    uint32_t dropped_packets;
    uint32_t active_flows;
} fourvia6_status_t;

void fourvia6_init(void);
void fourvia6_get_status(fourvia6_status_t *out);
esp_err_t fourvia6_set_config(bool enabled, const char *lan_cidr,
                              uint16_t site_id, char *error, size_t error_size);
bool fourvia6_calculate_prefix(const char *lan_cidr, uint16_t site_id,
                               char *out, size_t out_size);
void fourvia6_effective_routes(const char *ipv4_routes, char *out, size_t out_size);

/* Called from the WireGuard receive/output paths. */
bool fourvia6_translate_wg_input(struct pbuf *packet, struct netif *wg_netif,
                                 const ip_addr_t *peer_tailscale_ip);
struct pbuf *fourvia6_translate_wg_output(struct pbuf *ipv4_packet);

#ifdef __cplusplus
}
#endif
