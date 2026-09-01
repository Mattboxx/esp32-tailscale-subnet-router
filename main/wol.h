/* Saved Wake-on-LAN targets and magic-packet sender. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WOL_MAX_DEVICES 12

typedef struct {
    char     name[32];
    uint8_t  mac[6];
    uint8_t  valid;
    uint8_t  _reserved0;
    char     broadcast[16]; /* empty = derive from live STA address/mask */
    uint16_t port;          /* 0 = UDP/9 */
    uint8_t  _reserved1[2];
} wol_device_t;

void      wol_init(void);
int       wol_count(void);
bool      wol_get(int index, wol_device_t *out);
esp_err_t wol_set_all(const wol_device_t *devices, int count);
bool      wol_parse_mac(const char *text, uint8_t out[6]);
void      wol_format_mac(const uint8_t mac[6], char out[18]);
esp_err_t wol_send_index(int index);
esp_err_t wol_send_mac(const uint8_t mac[6], const char *broadcast, uint16_t port);
esp_err_t wol_send_saved_mac_text(const char *mac_text);

#ifdef __cplusplus
}
#endif
