#ifndef KEY_SCHEDULE_H
#define KEY_SCHEDULE_H

#include <stdint.h>

/**
 * @brief traffic_key_t contains the secrets necessary to encrypt and decrypt data
 *        from an authenticated stream cipher (AEAD) like chacha20-poly1305.
 */
typedef struct traffic_key {
    uint8_t secret[32];
    uint8_t key[32];
    uint8_t iv[12];
    int64_t nonce;
} traffic_key_t;

typedef struct handshake_keys {
    uint8_t early_secret[32];
    uint8_t shared_secret[32];
    uint8_t derived_secret[32];
    uint8_t handshake_secret[32];
    traffic_key_t server_traffic;
    traffic_key_t client_traffic;
} handshake_keys_t;

typedef struct application_keys {
    uint8_t derived_secret[32];
    uint8_t master_secret[32];
    traffic_key_t server_traffic;
    traffic_key_t client_traffic;
} application_keys_t;

void compute_handshake_keys(
    const uint8_t *msg_hash,
    const uint8_t *shared_secret,
    handshake_keys_t *handshake_keys
);

void compute_application_keys(
    const uint8_t *msg_hash,
    const handshake_keys_t *handshake_keys,
    application_keys_t *application_keys
);

#endif /* KEY_SCHEDULE_H */