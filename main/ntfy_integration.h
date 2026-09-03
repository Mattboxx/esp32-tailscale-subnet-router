/* Optional ntfy alerts and remote Wake-on-LAN commands. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

typedef struct {
    bool enabled;
    bool tailscale_alerts;
    bool commands_enabled;
    bool commands_only_when_tailscale_down;
    bool allow_direct_mac;
    bool info_enabled;
    bool info_include_details;
    char server[160];
    char topic[96];
    char token[160];
    uint16_t failure_delay_seconds;
    uint16_t poll_interval_seconds;
} ntfy_integration_config_t;

typedef struct {
    bool last_publish_ok;
    uint32_t alerts_sent;
    uint32_t commands_received;
    uint32_t command_errors;
} ntfy_integration_status_t;

void ntfy_integration_init(void);
void ntfy_integration_get_config(ntfy_integration_config_t *out);
void ntfy_integration_get_status(ntfy_integration_status_t *out);
esp_err_t ntfy_integration_set_config(const ntfy_integration_config_t *config);
esp_err_t ntfy_integration_send_test(void);
