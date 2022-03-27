#include <buffer.h>
#include <stdlib.h>
#include <string.h>

buffer_t buffer_slice(buffer_t buf, size_t i) {
    assert(i <= buf.length);
    return (buffer_t){buf.length - i, buf.data + i};
}

dyn_buf_t dyn_buf_create(size_t initial_capacity) {
    void *data = malloc(initial_capacity);
    assert(data != NULL && "out of memory");
    return (dyn_buf_t) {0, initial_capacity, data};
}

void dyn_buf_destroy(dyn_buf_t *buf) {
    free(buf->data);
    buf->data = NULL;
}

void dyn_buf_write(dyn_buf_t *buf, void *data, size_t len) {
    size_t free_capacity = buf->capacity - buf->length;
    if (free_capacity < len) {
        buf->capacity = buf->length + len;
        buf->data = realloc(buf->data, buf->capacity);
        assert(buf->data != NULL);
    }
    memmove(buf->data + buf->length, data, len);
    buf->length += len;
}
