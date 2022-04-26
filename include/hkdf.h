#ifndef HKDF_H
#define HKDF_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief 
 * 
 * https://datatracker.ietf.org/doc/html/rfc5869
 */
void hkdf_expand(uint8_t *prk, size_t prk_len, uint8_t *info, size_t info_len, size_t len, uint8_t *output);

#endif /* HKDF_H */