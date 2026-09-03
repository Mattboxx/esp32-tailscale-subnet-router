/* Web interface password — set, verify, query.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "esp_err.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

#include "web_password.h"

/* Must match the NVS_NAMESPACE define in main/nvs_params.h. Duplicated
 * here so web_password can live as its own component and be required
 * by both main and remote_console without a cycle. */
#define PW_NVS_NAMESPACE "tsr"
#define PW_NVS_KEY       "web_password"
#define PW_SALT_LEN      16
#define PW_HASH_LEN      32  /* SHA-256 output */
#define PW_PBKDF2_PREFIX "pbkdf2-sha256$"
#define PW_PBKDF2_ITERS  60000U
#define PW_PBKDF2_ITERS_MIN 10000U
#define PW_PBKDF2_ITERS_MAX 500000U

/* A successful PBKDF2 verification seeds a boot-local, salted exact-match
 * cache.  It is deliberately never persisted: the strong PBKDF2 record
 * remains the only password verifier in NVS and the first login after every
 * reboot still proves the password against it.  Subsequent correct unlocks
 * (for example after an idle session timeout) avoid repeatedly blocking the
 * ESP HTTP task for the full PBKDF2 run.  Cache misses still fall through to
 * PBKDF2, preserving the cost of wrong guesses in addition to endpoint rate
 * limiting. */
static portMUX_TYPE s_fast_cache_mux = portMUX_INITIALIZER_UNLOCKED;
static bool    s_fast_cache_valid;
static uint8_t s_fast_cache_salt[PW_SALT_LEN];
static uint8_t s_fast_cache_hash[PW_HASH_LEN];

/* Local helpers — raw NVS instead of nvs_params.h to avoid pulling a
 * cross-component dep on main. */
static char *nvs_dup_str(const char *key)
{
    nvs_handle_t h;
    if (nvs_open(PW_NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return NULL;
    size_t len = 0;
    if (nvs_get_str(h, key, NULL, &len) != ESP_OK || len == 0) {
        nvs_close(h);
        return NULL;
    }
    char *buf = malloc(len);
    if (!buf) { nvs_close(h); return NULL; }
    if (nvs_get_str(h, key, buf, &len) != ESP_OK) {
        free(buf);
        nvs_close(h);
        return NULL;
    }
    nvs_close(h);
    return buf;
}

static esp_err_t nvs_write_str(const char *key, const char *value)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(PW_NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, key, value);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

static void bytes_to_hex(const uint8_t *src, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", src[i]);
    }
    out[len * 2] = '\0';
}

static int hex_to_bytes(const char *src, uint8_t *dst, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(src + i * 2, "%2x", &b) != 1) return -1;
        dst[i] = (uint8_t)b;
    }
    return 0;
}

static void compute_hash(const uint8_t *salt, size_t salt_len,
                         const char *plaintext, uint8_t *hash_out)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, salt, salt_len);
    mbedtls_sha256_update(&ctx, (const uint8_t *)plaintext, strlen(plaintext));
    mbedtls_sha256_finish(&ctx, hash_out);
    mbedtls_sha256_free(&ctx);
}

/* PBKDF2-HMAC-SHA256, one 32-byte block.  Keeping the implementation here
 * avoids depending on Mbed TLS private headers in IDF 5.3.  The reusable HMAC
 * context preserves the keyed inner/outer pads across iterations. */
static bool compute_pbkdf2(const uint8_t *salt, size_t salt_len,
                           const char *plaintext, uint32_t iterations,
                           uint8_t hash_out[PW_HASH_LEN])
{
    if (!salt || !plaintext || iterations < PW_PBKDF2_ITERS_MIN
        || iterations > PW_PBKDF2_ITERS_MAX) return false;

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return false;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md, 1) != 0
        || mbedtls_md_hmac_starts(&ctx, (const unsigned char *)plaintext,
                                  strlen(plaintext)) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    static const uint8_t block_one[4] = {0, 0, 0, 1};
    uint8_t u[PW_HASH_LEN];
    int rc = mbedtls_md_hmac_update(&ctx, salt, salt_len);
    if (rc == 0) rc = mbedtls_md_hmac_update(&ctx, block_one, sizeof block_one);
    if (rc == 0) rc = mbedtls_md_hmac_finish(&ctx, u);
    if (rc == 0) memcpy(hash_out, u, sizeof u);

    for (uint32_t i = 1; rc == 0 && i < iterations; i++) {
        rc = mbedtls_md_hmac_reset(&ctx);
        if (rc == 0) rc = mbedtls_md_hmac_update(&ctx, u, sizeof u);
        if (rc == 0) rc = mbedtls_md_hmac_finish(&ctx, u);
        if (rc == 0) {
            for (size_t j = 0; j < sizeof u; j++) hash_out[j] ^= u[j];
        }
    }
    volatile uint8_t *wipe = u;
    for (size_t i = 0; i < sizeof u; i++) wipe[i] = 0;
    mbedtls_md_free(&ctx);
    return rc == 0;
}

static bool hashes_equal(const uint8_t a[PW_HASH_LEN],
                         const uint8_t b[PW_HASH_LEN])
{
    volatile unsigned diff = 0;
    for (size_t i = 0; i < PW_HASH_LEN; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static void fast_cache_invalidate(void)
{
    portENTER_CRITICAL(&s_fast_cache_mux);
    s_fast_cache_valid = false;
    memset(s_fast_cache_salt, 0, sizeof s_fast_cache_salt);
    memset(s_fast_cache_hash, 0, sizeof s_fast_cache_hash);
    portEXIT_CRITICAL(&s_fast_cache_mux);
}

static void fast_cache_store(const char *plaintext)
{
    uint8_t salt[PW_SALT_LEN];
    uint8_t hash[PW_HASH_LEN];
    esp_fill_random(salt, sizeof salt);
    compute_hash(salt, sizeof salt, plaintext, hash);

    portENTER_CRITICAL(&s_fast_cache_mux);
    memcpy(s_fast_cache_salt, salt, sizeof salt);
    memcpy(s_fast_cache_hash, hash, sizeof hash);
    s_fast_cache_valid = true;
    portEXIT_CRITICAL(&s_fast_cache_mux);

    volatile uint8_t *wipe = hash;
    for (size_t i = 0; i < sizeof hash; i++) wipe[i] = 0;
}

static bool fast_cache_matches(const char *plaintext)
{
    uint8_t salt[PW_SALT_LEN];
    uint8_t expected[PW_HASH_LEN];

    portENTER_CRITICAL(&s_fast_cache_mux);
    bool valid = s_fast_cache_valid;
    if (valid) {
        memcpy(salt, s_fast_cache_salt, sizeof salt);
        memcpy(expected, s_fast_cache_hash, sizeof expected);
    }
    portEXIT_CRITICAL(&s_fast_cache_mux);
    if (!valid) return false;

    uint8_t computed[PW_HASH_LEN];
    compute_hash(salt, sizeof salt, plaintext, computed);
    bool match = hashes_equal(expected, computed);
    volatile uint8_t *wipe_computed = computed;
    volatile uint8_t *wipe_expected = expected;
    for (size_t i = 0; i < sizeof computed; i++) {
        wipe_computed[i] = 0;
        wipe_expected[i] = 0;
    }
    return match;
}

static bool verify_legacy_sha256(const char *stored, const char *plaintext)
{
    const char *colon = strchr(stored, ':');
    if (!colon || (size_t)(colon - stored) != PW_SALT_LEN * 2
        || strlen(colon + 1) != PW_HASH_LEN * 2) return false;

    uint8_t salt[PW_SALT_LEN], expected[PW_HASH_LEN], computed[PW_HASH_LEN];
    if (hex_to_bytes(stored, salt, PW_SALT_LEN) != 0
        || hex_to_bytes(colon + 1, expected, PW_HASH_LEN) != 0) return false;
    compute_hash(salt, sizeof salt, plaintext, computed);
    return hashes_equal(expected, computed);
}

static bool verify_pbkdf2(const char *stored, const char *plaintext)
{
    const size_t prefix_len = strlen(PW_PBKDF2_PREFIX);
    if (strncmp(stored, PW_PBKDF2_PREFIX, prefix_len) != 0) return false;
    const char *iterations_text = stored + prefix_len;
    char *iterations_end = NULL;
    unsigned long iterations = strtoul(iterations_text, &iterations_end, 10);
    if (!iterations_end || iterations_end == iterations_text || *iterations_end != '$'
        || iterations < PW_PBKDF2_ITERS_MIN || iterations > PW_PBKDF2_ITERS_MAX)
        return false;

    const char *salt_hex = iterations_end + 1;
    const char *separator = strchr(salt_hex, '$');
    if (!separator || (size_t)(separator - salt_hex) != PW_SALT_LEN * 2
        || strlen(separator + 1) != PW_HASH_LEN * 2) return false;

    uint8_t salt[PW_SALT_LEN], expected[PW_HASH_LEN], computed[PW_HASH_LEN];
    if (hex_to_bytes(salt_hex, salt, PW_SALT_LEN) != 0
        || hex_to_bytes(separator + 1, expected, PW_HASH_LEN) != 0
        || !compute_pbkdf2(salt, sizeof salt, plaintext, (uint32_t)iterations,
                           computed)) return false;
    return hashes_equal(expected, computed);
}

bool is_web_password_set(void)
{
    char *s = nvs_dup_str(PW_NVS_KEY);
    if (!s) return false;
    bool set = (s[0] != '\0');
    free(s);
    return set;
}

bool verify_web_password(const char *plaintext)
{
    if (!plaintext) return false;
    if (fast_cache_matches(plaintext)) return true;

    char *stored = nvs_dup_str(PW_NVS_KEY);
    if (!stored) return false;

    bool modern = strncmp(stored, PW_PBKDF2_PREFIX,
                          strlen(PW_PBKDF2_PREFIX)) == 0;
    bool ok = modern ? verify_pbkdf2(stored, plaintext)
                     : verify_legacy_sha256(stored, plaintext);

    free(stored);
    /* Seamless upgrade: an old salt+SHA-256 verifier remains accepted once,
     * then is immediately replaced with the slower version. Login still
     * succeeds if the NVS rewrite fails; availability must not depend on a
     * migration write, and the next successful login will retry it. */
    if (ok && !modern) {
        /* set_web_password_hashed() also seeds the fast cache after the
         * upgraded verifier has reached NVS. */
        if (set_web_password_hashed(plaintext) != ESP_OK) {
            fast_cache_store(plaintext);
        }
    } else if (ok) {
        fast_cache_store(plaintext);
    }
    return ok;
}

esp_err_t set_web_password_hashed(const char *plaintext)
{
    if (!plaintext) return ESP_ERR_INVALID_ARG;
    /* Never let a cached verifier survive a password change or clear. */
    fast_cache_invalidate();
    if (plaintext[0] == '\0') {
        return nvs_write_str(PW_NVS_KEY, "");
    }

    uint8_t salt[PW_SALT_LEN], hash[PW_HASH_LEN];
    esp_fill_random(salt, PW_SALT_LEN);
    if (!compute_pbkdf2(salt, sizeof salt, plaintext, PW_PBKDF2_ITERS, hash))
        return ESP_FAIL;

    char salt_hex[PW_SALT_LEN * 2 + 1];
    char hash_hex[PW_HASH_LEN * 2 + 1];
    bytes_to_hex(salt, sizeof salt, salt_hex);
    bytes_to_hex(hash, sizeof hash, hash_hex);
    char buf[sizeof PW_PBKDF2_PREFIX + 10 + sizeof salt_hex + sizeof hash_hex + 2];
    snprintf(buf, sizeof buf, PW_PBKDF2_PREFIX "%u$%s$%s",
             (unsigned)PW_PBKDF2_ITERS, salt_hex, hash_hex);

    esp_err_t err = nvs_write_str(PW_NVS_KEY, buf);
    if (err == ESP_OK) fast_cache_store(plaintext);
    return err;
}
