/* Local, operator-initiated firmware upload only. */
#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Stream an authenticated HTTP request into the inactive OTA partition and
 * mark it bootable. This module never contacts an update server. */
esp_err_t ota_upload_handler(httpd_req_t *req);
#ifdef __cplusplus
}
#endif
