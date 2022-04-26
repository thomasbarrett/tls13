#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

void hmac_sha256_sign(uint8_t *data, size_t data_len, uint8_t *secret, size_t secret_len, uint8_t *res);

#endif /* HMAC_H */
