#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include <assert.h>

typedef struct buffer {
    size_t length;
    uint8_t *data;
} buffer_t;

buffer_t buffer_slice(buffer_t buf, size_t i);

typedef struct dyn_buf {
    size_t length;
    size_t capacity;
    uint8_t *data;
} dyn_buf_t;

dyn_buf_t dyn_buf_create(size_t initial_capacity);
void dyn_buf_destroy(dyn_buf_t *buf);
void dyn_buf_write(dyn_buf_t *buf, void *data, size_t len);
#endif /* BUFFER_H */
