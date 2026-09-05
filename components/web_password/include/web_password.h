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
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* True if a non-empty password is stored. */
bool      is_web_password_set(void);

/* Constant-time verification. The first success after boot checks the stored
 * PBKDF2 record and seeds a non-persistent exact-match cache so later UI
 * unlocks do not repeatedly block the ESP HTTP task. */
bool      verify_web_password(const char *plaintext);

/* Challenge-response support for the browser UI. The browser derives the
 * stored PBKDF2 key and proves possession with HMAC-SHA256 over a one-time
 * server nonce, avoiding a multi-second PBKDF2 calculation on the ESP and
 * avoiding plaintext-password transmission on the normal UI login path. */
#define WEB_PASSWORD_SALT_LEN 16
#define WEB_PASSWORD_PROOF_LEN 32
bool web_password_get_proof_params(uint32_t *iterations,
                                   uint8_t salt[WEB_PASSWORD_SALT_LEN]);
bool verify_web_password_proof(const uint8_t *message, size_t message_len,
                               const uint8_t proof[WEB_PASSWORD_PROOF_LEN]);

/* Salt + hash + persist. Empty string disables protection. */
esp_err_t set_web_password_hashed(const char *plaintext);

#ifdef __cplusplus
}
#endif
