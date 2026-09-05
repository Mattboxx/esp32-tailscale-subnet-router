/* Single-page web UI server.
 *
 * Boots an esp_http_server on port 80 and serves the embedded SPA at /.
 * JSON API endpoints under /api and the auth gate land in follow-up commits.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Start the HTTP server. Idempotent — subsequent calls are no-ops. */
void web_ui_init(void);

/* Persisted listener port (default 80); changes take effect after restart. */
uint16_t web_ui_configured_port(void);

#ifdef __cplusplus
}
#endif
