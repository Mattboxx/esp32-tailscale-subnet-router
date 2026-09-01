/* MQTT telemetry, commands, and Home Assistant discovery. */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool enabled;
    bool home_assistant_discovery;
    char uri[160];
    char username[64];
    char password[96];
    char base_topic[96];
    char discovery_prefix[48];
    uint16_t interval_seconds;
} mqtt_integration_config_t;

void mqtt_integration_init(void);
void mqtt_integration_get_config(mqtt_integration_config_t *out);
esp_err_t mqtt_integration_set_config(const mqtt_integration_config_t *config);
bool mqtt_integration_connected(void);
void mqtt_integration_publish_now(void);
void mqtt_integration_wol_changed(void);

#ifdef __cplusplus
}
#endif

