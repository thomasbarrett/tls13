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
    printf("early_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", handshake_keys->early_secret[i]);
    }
    printf("\n");
    uint8_t empty_hash[32];
    sha256(NULL, 0, empty_hash);
    printf("empty_hash: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", empty_hash[i]);
    }
    printf("\n");

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->early_secret}, 
        "derived",
        (buffer_t){32, empty_hash},
        (buffer_t){32, handshake_keys->derived_secret}
    );
    printf("derived_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", handshake_keys->derived_secret[i]);
    }
    printf("\n");

    hmac_sha256_sign(shared_secret, 32, handshake_keys->derived_secret, 32, handshake_keys->handshake_secret);
    printf("handshake_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", handshake_keys->handshake_secret[i]);
    }
    printf("\n");

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->handshake_secret}, 
        "c hs traffic",
        (buffer_t){32, msg_hash},
        (buffer_t){32, handshake_keys->client_traffic.secret}
    );
    printf("client_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", handshake_keys->client_traffic.secret[i]);
    }
    printf("\n");


    hkdf_expand_label(
        (buffer_t){32, handshake_keys->handshake_secret}, 
        "s hs traffic",
        (buffer_t){32, msg_hash},
        (buffer_t){32, handshake_keys->server_traffic.secret}
    );
    printf("server_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", handshake_keys->server_traffic.secret[i]);
    }
    printf("\n");


    hkdf_expand_label(
        (buffer_t){32, handshake_keys->client_traffic.secret}, 
        "key",
        (buffer_t){0, NULL},
        (buffer_t){32, handshake_keys->client_traffic.key}
    );
    printf("client_handshake_key: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", handshake_keys->client_traffic.key[i]);
    }
    printf("\n");


    hkdf_expand_label(
        (buffer_t){32, handshake_keys->server_traffic.secret}, 
        "key",
        (buffer_t){0, NULL},
        (buffer_t){32, handshake_keys->server_traffic.key}
    );
    printf("server_handshake_key: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", handshake_keys->server_traffic.key[i]);
    }
    printf("\n");


    hkdf_expand_label(
        (buffer_t){32, handshake_keys->client_traffic.secret}, 
        "iv",
        (buffer_t){0, NULL},
        (buffer_t){12, handshake_keys->client_traffic.iv}
    );
    printf("client_handshake_iv: ");
    for (size_t i = 0; i < 12; i++) {
        printf("%02x", handshake_keys->client_traffic.iv[i]);
    }
    printf("\n");

    hkdf_expand_label(
        (buffer_t){32, handshake_keys->server_traffic.secret}, 
        "iv",
        (buffer_t){0, NULL},
        (buffer_t){12, handshake_keys->server_traffic.iv}
    );
    printf("server_handshake_iv: ");
    for (size_t i = 0; i < 12; i++) {
        printf("%02x", handshake_keys->server_traffic.iv[i]);
    }
    printf("\n");

    handshake_keys->client_traffic.nonce = 0;
    handshake_keys->server_traffic.nonce = 0;
}

void compute_application_keys(
    const uint8_t *msg_hash,
    const handshake_keys_t *handshake_keys,
    traffic_key_t *application_keys
) {
    
}
