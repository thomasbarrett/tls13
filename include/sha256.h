#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

void sha256(uint8_t *in, uint64_t len, uint8_t out[32]);

#endif /* SHA256_H */
