#ifndef HKDF_H
#define HKDF_H

#include <buffer.h>

/**
 * @brief 
 * 
 * https://datatracker.ietf.org/doc/html/rfc5869
 */
void hkdf_expand(buffer_t prk, buffer_t info, buffer_t output);
void hkdf_expand_label(buffer_t prk, const char *label, buffer_t ctx, buffer_t output);


#endif /* HKDF_H */
