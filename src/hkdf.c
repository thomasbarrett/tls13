#include <hkdf.h>
#include <hmac.h>
#include <stdlib.h>
#include <string.h>

#define min(a, b) (a < b ? a: b)

void hkdf_expand(buffer_t prk, buffer_t info, buffer_t output) {
    size_t n = output.length / 32U + (output.length % 32U != 0);
    uint8_t t0[32];
    size_t t0_len = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t *tmp = malloc(t0_len + info.length + 1);
        size_t tmp_len = t0_len + info.length + 1;
        memcpy(tmp, t0, t0_len);
        memcpy(tmp + t0_len, info.data, info.length);
        tmp[t0_len + info.length] = i + 1;
        hmac_sha256_sign(tmp, tmp_len, prk.data, prk.length, t0);
        memcpy(output.data + 32 * i, t0, min(32, output.length - 32 * i));
        t0_len = 32;
    }
}

void hkdf_expand_label(buffer_t prk, const char *label, buffer_t ctx, buffer_t output) {
    uint8_t info[518];
    uint8_t label_len = strlen(label);
    size_t info_len = 10 + label_len + ctx.length;
    uint8_t *iter = info;

    uint16_t len = htons(output.length);
    memcpy(iter, &len, 2);
    iter += 2;

    *iter = 6 + label_len;
    iter += 1;

    memcpy(iter, "tls13 ", 6);
    iter += 6;

    memcpy(iter, label, label_len);
    iter += label_len;

    *iter = ctx.length;
    iter += 1;
    memcpy(iter, ctx.data, ctx.length);
    
    hkdf_expand(prk, (buffer_t){label_len, label}, output);
}
