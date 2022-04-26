#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr32 (uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}


void sha256(uint8_t *in, uint64_t len, uint8_t out[32]) {

    uint32_t res[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    size_t l = (((len + 8) / 64) + 1) * 64;
    uint8_t m[l];
    memset(m, 0, l);
    memcpy(m, in, len);
    m[len] = 0x80;
    *(((uint64_t*)(&m[l])) - 1) = htonll(8 * len);

    for (size_t j = 0; j < l; j += 64) {
        uint32_t w[64];
        memset(w, 0, 64 * sizeof(uint32_t));
        for (size_t i = 0; i < 16; i += 1) {
            w[i] = ntohl(*(uint32_t*)(m + j + 4 * i));
        }

        for (size_t i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = res[0];
        uint32_t b = res[1];
        uint32_t c = res[2];
        uint32_t d = res[3];
        uint32_t e = res[4];
        uint32_t f = res[5];
        uint32_t g = res[6];
        uint32_t h = res[7];

        for (size_t i = 0; i < 64; i++) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        res[0] = res[0] + a;
        res[1] = res[1] + b;
        res[2] = res[2] + c;
        res[3] = res[3] + d;
        res[4] = res[4] + e;
        res[5] = res[5] + f;
        res[6] = res[6] + g;
        res[7] = res[7] + h;
    }

    for (size_t i = 0; i < 8; i++) {
        ((uint32_t*)out)[i] = htonl(res[i]);
    }
}
