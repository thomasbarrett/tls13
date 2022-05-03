#include <hkdf.h>
#include <hmac.h>
#include <stdlib.h>
#include <string.h>

#define min(a, b) (a < b ? a: b)

void hkdf_expand(uint8_t *prk, size_t prk_len, uint8_t *info, size_t info_len, size_t len, uint8_t *output) {
    size_t n = len / 32U + (len % 32U != 0);
    uint8_t t0[32];
    size_t t0_len = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t *tmp = malloc(t0_len + info_len + 1);
        size_t tmp_len = t0_len + info_len + 1;
        memcpy(tmp, t0, t0_len);
        memcpy(tmp + t0_len, info, info_len);
        tmp[t0_len + info_len] = i + 1;
        hmac_sha256_sign(tmp, tmp_len, prk, prk_len, t0);
        memcpy(output + 32 * i, t0, min(32, len - 32 * i));
        t0_len = 32;
    }
}
