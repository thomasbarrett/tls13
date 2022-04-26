#include <hmac.h>
#include <sha256.h>
#include <string.h>

void hmac_sha256_sign(uint8_t *data, size_t data_len, uint8_t *secret, size_t secret_len, uint8_t *res) {
    uint8_t key[64] = {0};
    if (secret_len > 64) {
        sha256(secret, secret_len, key);
    } else {
        memcpy(key, secret, secret_len);
    }

    uint8_t o_key_pad[96];
    uint8_t i_key_pad[64 + data_len];
    for (size_t i = 0; i < 64; i++) {
        o_key_pad[i] = key[i] ^ 0x5c;
        i_key_pad[i] = key[i] ^ 0x36;
    }
    memcpy(i_key_pad + 64, data, data_len);
    sha256(i_key_pad, 64 + data_len, o_key_pad + 64);
    sha256(o_key_pad, 96, res);
}
