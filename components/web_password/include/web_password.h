/* Web interface password — set, verify, query.
 *
 * Storage: NVS key "web_password" under the project namespace. New values
 * use versioned PBKDF2-HMAC-SHA256 records; legacy salt+SHA-256 records are
 * transparently upgraded after the next successful verification.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* True if a non-empty password is stored. */
bool      is_web_password_set(void);

/* Constant-time verify against the stored hash. */
bool      verify_web_password(const char *plaintext);

/* Salt + hash + persist. Empty string disables protection. */
esp_err_t set_web_password_hashed(const char *plaintext);

#ifdef __cplusplus
}
#endif
