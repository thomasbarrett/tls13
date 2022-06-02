#include <key_schedule.h>
#include <hkdf.h>
#include <stdio.h>
#include <sha256.h>
#include <hmac.h>

void compute_handshake_keys(
    const uint8_t *msg_hash,
    const uint8_t *shared_secret,
    handshake_keys_t *handshake_keys
) {

    uint8_t zero[32] = {0};
    hmac_sha256_sign(zero, 32, zero, 32, handshake_keys->early_secret);
    uint8_t empty_hash[32];
    sha256(NULL, 0, empty_hash);

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->early_secret}, 
        "derived",
        (buffer_t){32, empty_hash},
        (buffer_t){32, handshake_keys->derived_secret}
    );

    hmac_sha256_sign(shared_secret, 32, handshake_keys->derived_secret, 32, handshake_keys->handshake_secret);

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->handshake_secret}, 
        "c hs traffic",
        (buffer_t){32, msg_hash},
        (buffer_t){32, handshake_keys->client_traffic.secret}
    );

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->handshake_secret}, 
        "s hs traffic",
        (buffer_t){32, msg_hash},
        (buffer_t){32, handshake_keys->server_traffic.secret}
    );

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->client_traffic.secret}, 
        "key",
        (buffer_t){0, NULL},
        (buffer_t){32, handshake_keys->client_traffic.key}
    );

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->server_traffic.secret}, 
        "key",
        (buffer_t){0, NULL},
        (buffer_t){32, handshake_keys->server_traffic.key}
    );

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->client_traffic.secret}, 
        "iv",
        (buffer_t){0, NULL},
        (buffer_t){12, handshake_keys->client_traffic.iv}
    );

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->server_traffic.secret}, 
        "iv",
        (buffer_t){0, NULL},
        (buffer_t){12, handshake_keys->server_traffic.iv}
    );

    handshake_keys->client_traffic.nonce = 0;
    handshake_keys->server_traffic.nonce = 0;
}

void compute_application_keys(
    const uint8_t *msg_hash,
    const handshake_keys_t *handshake_keys,
    application_keys_t *application_keys
) {
    uint8_t zero[32] = {0};
    uint8_t empty_hash[32];
    sha256(NULL, 0, empty_hash);

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->handshake_secret}, 
        "derived",
        (buffer_t){32, empty_hash},
        (buffer_t){32, application_keys->derived_secret}
    );

    hmac_sha256_sign(zero, 32, application_keys->derived_secret, 32, application_keys->master_secret);

    hkdf_expand_label(
        (buffer_t){32, application_keys->master_secret}, 
        "c ap traffic",
        (buffer_t){32, msg_hash},
        (buffer_t){32, application_keys->client_traffic.secret}
    );

    hkdf_expand_label(
        (buffer_t){32, application_keys->master_secret}, 
        "s ap traffic",
        (buffer_t){32, msg_hash},
        (buffer_t){32, application_keys->server_traffic.secret}
    );

    hkdf_expand_label(
        (buffer_t){32, application_keys->client_traffic.secret}, 
        "key",
        (buffer_t){0, NULL},
        (buffer_t){32, application_keys->client_traffic.key}
    );

    hkdf_expand_label(
        (buffer_t){32, application_keys->server_traffic.secret}, 
        "key",
        (buffer_t){0, NULL},
        (buffer_t){32, application_keys->server_traffic.key}
    );

    hkdf_expand_label(
        (buffer_t){32, application_keys->client_traffic.secret}, 
        "iv",
        (buffer_t){0, NULL},
        (buffer_t){12, application_keys->client_traffic.iv}
    );

    hkdf_expand_label(
        (buffer_t){32, application_keys->server_traffic.secret}, 
        "iv",
        (buffer_t){0, NULL},
        (buffer_t){12, application_keys->server_traffic.iv}
    );

    application_keys->client_traffic.nonce = 0;
    application_keys->server_traffic.nonce = 0;
}
