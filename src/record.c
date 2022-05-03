#include <record.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

const char* content_type_str(content_type_t t) {
    switch (t) {
        case CONTENT_TYPE_INVALID: return "INVALID";
        case CONTENT_TYPE_CHANGE_CIPHER_CPEC: return "CHANGE_CIPHER_CPEC";
        case CONTENT_TYPE_ALERT: return "ALERT";
        case CONTENT_TYPE_HANDSHAKE: return "HANDSHAKE";
        case CONTENT_TYPE_APPLICATION_DATA: return "APPLICATION_DATA";
        case CONTENT_TYPE_HEARTBEAT: return "HEARTBEAT";
        default: return NULL;
    }
}

const char* cipher_suite_str(cipher_suite_t s) {
    switch (s) {
    case TLS_AES_128_GCM_SHA256: return "TLS_AES_128_GCM_SHA256";
    case TLS_AES_256_GCM_SHA384: return "TLS_AES_256_GCM_SHA384";
    case TLS_CHACHA20_POLY1305_SHA256: return "TLS_CHACHA20_POLY1305_SHA256";
    case TLS_AES_128_CCM_SHA256: return "TLS_AES_128_CCM_SHA256";
    case TLS_AES_128_CCM_8_SHA256: return "TLS_AES_128_CCM_8_SHA256";
    default: return NULL;
    }
}

const char* extension_type_str(extension_type_t t) {
    switch (t) {
        case SERVER_NAME: return "SERVER_NAME";
        case MAX_FRAGMENT_LENGTH: return "MAX_FRAGMENT_LENGTH";
        case STATUS_REQUESTS: return "STATUS_REQUESTS";
        case SUPPORTED_GROUPS: return "SUPPORTED_GROUPS";
        case EC_POINT_FORMATS: return "EC_POINT_FORMATS";
        case SIGNATURE_ALGORITHMS: return "SIGNATURE_ALGORITHMS";
        case USE_SRTP: return "USE_SRTP";
        case HEARTBEAT: return "HEARTBEAT";
        case APPLICATION_LAYER_PROTOCOL_NEGOTIATION: return "APPLICATION_LAYER_PROTOCOL_NEGOTIATION";
        case SIGNED_CERTIFICATE_TIMESTAMP: return "SIGNED_CERTIFICATE_TIMESTAMP";
        case CLIENT_CERTIFICATE_TYPE: return "CLIENT_CERTIFICATE_TYPE";
        case SERVER_CERTIFICATE_TYPE: return "SERVER_CERTIFICATE_TYPE";
        case PADDING: return "PADDING";
        case ENCRYPT_THEN_MAC: return "ENCRYPT_THEN_MAC";
        case EXTENDED_MASTER_SECRET: return "EXTENDED_MASTER_SECRET";
        case SESSION_TICKET: return "SESSION_TICKET";
        case PRE_SHARED_KEY: return "PRE_SHARED_KEY";
        case EARLY_DATA: return "EARLY_DATA";
        case SUPPORTED_VERSION: return "SUPPORTED_VERSION";
        case COOKIE: return "COOKIE";
        case PSK_KEY_EXCHANGE_MODES: return "PSK_KEY_EXCHANGE_MODES";
        case CERTIFICATE_AUTHORITIES: return "CERTIFICATE_AUTHORITIES";
        case OID_FILTERS: return "OID_FILTERS";
        case POST_HANDSHAKE_AUTH: return "POST_HANDSHAKE_AUTH";
        case SIGNATURE_ALGORITHMS_CERT: return "SIGNATURE_ALGORITHMS_CERT";
        case KEY_SHARE: return "KEY_SHARE";
        default: return NULL;
    }
}

const char* ec_point_format_str(ec_point_format_t f) {
    switch (f) {
    case EC_POINT_FORMAT_UNCOMPRESSED: return "UNCOMPRESSED";
    default: return NULL;
    }
}

const char* supported_group_str(supported_group_t g) {
    switch (g) {
    case SECP256R1: return "SECP256R1";
    case SECP284R1: return "SECP284R1";
    case SECP521R1: return "SECP521R1";
    case X25519: return "X25519";
    case X448: return "X448";
    default: return NULL;
    }
}

const char* signature_scheme_str(signature_scheme_t s) {
    switch (s) {
    case RSA_PKCS1_SHA256: return "RSA_PKCS1_SHA256";
    case RSA_PKCS1_SHA384: return "RSA_PKCS1_SHA384";
    case RSA_PKCS1_SHA512: return "RSA_PKCS1_SHA512";
    case ECDSA_SECP256R1_SHA256: return "ECDSA_SECP256R1_SHA256";
    case ECDSA_SECP384R1_SHA384: return "ECDSA_SECP384R1_SHA384";
    case ECDSA_SECP521R1_SHA512: return "ECDSA_SECP521R1_SHA512";
    case RSA_PSS_RSAE_SHA256: return "RSA_PSS_RSAE_SHA256";
    case RSA_PSS_RSAE_SHA384: return "RSA_PSS_RSAE_SHA384";
    case RSA_PSS_RSAE_SHA512: return "RSA_PSS_RSAE_SHA512";
    case ED25519: return "ED25519";
    case ED448: return "ED448";
    case RSA_PSS_PSS_SHA256: return "RSA_PSS_PSS_SHA256";
    case RSA_PSS_PSS_SHA384: return "RSA_PSS_PSS_SHA384";
    case RSA_PSS_PSS_SHA512: return "RSA_PSS_PSS_SHA512";
    case RSA_PKCS1_SHA1: return "RSA_PKCS1_SHA1";
    case ECDSA_SHA1: return "ECDSA_SHA1";
    default: return NULL;
    }
}

const char *protocol_version_str(protocol_version_t v) {
    switch (v) {
    case TLS_10: return "TLS 1.0";
    case TLS_12: return "TLS 1.2";
    case TLS_13: return "TLS 1.3";
    default: return NULL;
    }
}

int64_t tls_plaintext_parse(buffer_t buffer, tls_plaintext_t *res) {
    buffer_t iter = buffer;
    if (buffer.length < 5) return TLS_PARSE_INCOMPLETE;
    res->type = *((uint8_t*) iter.data);
    res->legacy_record_version = ntohs(*(uint16_t*) (iter.data+1));
    res->length = ntohs(*(uint16_t*) (iter.data+3));
    if (res->length > (1 << 14)) return TLS_PARSE_ERROR;
    iter = buffer_slice(iter, 5);

    if (iter.length < res->length) return TLS_PARSE_INCOMPLETE;
    res->fragment = malloc(res->length);
    assert(res->fragment != NULL && "out of memory");
    memcpy(res->fragment, iter.data, res->length);
    return 5 + res->length;
}

void tls_plaintext_write(dyn_buf_t *buf, tls_plaintext_t *msg) {
    dyn_buf_write(buf, &msg->type, 1);
    uint16_t legacy_record_version = htons(msg->legacy_record_version);
    dyn_buf_write(buf, &legacy_record_version, sizeof(uint16_t));
    uint16_t length = htons(msg->length);
    dyn_buf_write(buf, &length, sizeof(uint16_t));
    dyn_buf_write(buf, msg->fragment, msg->length);
}

int64_t handshake_message_parse(buffer_t buffer, handshake_message_t *msg) {
    buffer_t iter = buffer;
    
    /* parse 8-bit msg_type */
    if (iter.length < 1) return TLS_PARSE_INCOMPLETE;
    msg->msg_type = iter.data[0];
    iter = buffer_slice(iter, 1);

    /* parse 24-bit msg length */
    if (iter.length < 3) return TLS_PARSE_INCOMPLETE;
    msg->length |= iter.data[0];
    msg->length <<= 8;
    msg->length |= iter.data[1];
    msg->length <<= 8;
    msg->length |= iter.data[2];
    iter = buffer_slice(iter, 3);
    if (msg->length > iter.length) return TLS_PARSE_INCOMPLETE;

    /* parse msg variant */
    int64_t res;
    switch (msg->msg_type) {
        case CLIENT_HELLO:
            res = client_hello_parse((buffer_t){msg->length, iter.data}, &msg->client_hello);
            break;
        case SERVER_HELLO:
            res = server_hello_parse((buffer_t){msg->length, iter.data}, &msg->server_hello);
            break;
        default:
            assert(0 && "not implemented");
    }
    if (res < 0) return TLS_PARSE_ERROR;
    iter = buffer_slice(iter, res);

    if (iter.length > 0) {
        printf("WARN: %zu bytes not consumed\n", iter.length);
    }
    return iter.data - buffer.data;
}

void handshake_message_write(dyn_buf_t *buf, handshake_message_t *msg) {
    dyn_buf_write(buf, &msg->msg_type, 1);
    uint8_t *length_be = buf->data + buf->length;
    dyn_buf_write(buf, length_be, 3);
    size_t message_start = buf->length;
    switch (msg->msg_type) {
        case CLIENT_HELLO:
            client_hello_write(buf, &msg->client_hello);
            break;
        case SERVER_HELLO:
            server_hello_write(buf, &msg->server_hello);
            break;
        default:
            assert(0 && "unsupported");
    }
    size_t message_end = buf->length;
    uint32_t length = message_end - message_start;
    length_be[2] = (uint8_t) length;
    length >>= 8;
    length_be[1] = (uint8_t) length;
    length >>= 8;
    length_be[0] = (uint8_t) length;
}

int64_t server_name_parse(buffer_t buffer, server_name_t *name) {
    buffer_t iter = buffer;

    if (iter.length < 1) return TLS_PARSE_INCOMPLETE;
    if (iter.data[0] != HOSTNAME) return TLS_PARSE_ERROR;
    name->name_type = iter.data[0];
    iter = buffer_slice(iter, 1);

    if (iter.length < sizeof(uint16_t)) return TLS_PARSE_INCOMPLETE;
    size_t len = ntohs(*(uint16_t*)iter.data);
    iter = buffer_slice(iter, sizeof(uint16_t));

    if (len > MAX_HOST_NAME_LEN) return TLS_PARSE_ERROR;
    if (len > iter.length) return TLS_PARSE_INCOMPLETE;
    memset(name->host_name, 0, MAX_HOST_NAME_LEN + 1);
    memcpy(name->host_name, iter.data, len);
    // TODO: validate hostname
    iter = buffer_slice(iter, len);

    return iter.data - buffer.data;
}

int64_t uint16_parse(buffer_t buffer, uint16_t *i) {
    if (buffer.length < sizeof(uint16_t)) return TLS_PARSE_INCOMPLETE;
    *i = ntohs(*((uint16_t*)buffer.data));
    return 2;
}

int64_t server_name_list_parse(buffer_t buffer, server_name_list_t *lst) {
    buffer_t iter = buffer;

    size_t len;
    int64_t res = uint16_parse(buffer, (uint16_t*) &len);
    if (res < 0) return res;
    iter = buffer_slice(iter, res);

    if (len < iter.length) return TLS_PARSE_INCOMPLETE;
    
    for (size_t i = 0; i < MAX_SERVER_NAME_LIST_LEN; i++) {
        if (len == 0) break;
        int64_t len2 = server_name_parse((buffer_t){len, iter.data}, &lst->server_name_list[i]);
        if (len2 < 0) return TLS_PARSE_ERROR;
        lst->server_name_list_len += 1;
        iter = buffer_slice(iter, len2);

        len -= len2;
    } 

    return iter.data - buffer.data;
}

int64_t supported_group_list_parse(buffer_t buffer, supported_group_list_t *lst) {
    
    buffer_t iter = buffer;

    /* parse 16-bit vector length */
    if (iter.length < 2) return TLS_PARSE_INCOMPLETE;
    uint16_t len = ntohs(*((uint16_t*) iter.data));
    iter = buffer_slice(iter, 2);

    if (len / 2 > MAX_SUPPORTED_GROUPS_LEN) return TLS_PARSE_ERROR;
    if (len > iter.length) return TLS_PARSE_INCOMPLETE;
    lst->supported_groups_len = len / 2;
    for (size_t i = 0; i < lst->supported_groups_len; i++) {
        uint16_t g = ntohs(*((uint16_t*) iter.data));
        lst->supported_groups[i] = g;
        iter = buffer_slice(iter, 2);
    }

    return iter.data - buffer.data;
}

int64_t signature_scheme_list_parse(buffer_t buffer, signature_scheme_list_t *lst) {
     buffer_t iter = buffer;

    /* parse 16-bit vector length */
    if (iter.length < 2) return TLS_PARSE_INCOMPLETE;
    uint16_t len = ntohs(*((uint16_t*) iter.data));
    iter = buffer_slice(iter, 2);

    if (len / 2 > MAX_SIGNATURE_SCHEMES_LEN) return TLS_PARSE_ERROR;
    if (len > iter.length) return TLS_PARSE_INCOMPLETE;
    lst->signature_schemes_len = len / 2;
    for (size_t i = 0; i < lst->signature_schemes_len; i++) {
        uint16_t g = ntohs(*((uint16_t*) iter.data));
        lst->signature_schemes[i] = g;
        iter = buffer_slice(iter, 2);
    }

    return iter.data - buffer.data;
}

int64_t ec_point_format_list_parse(buffer_t buffer, ec_point_format_list_t *lst) {
    buffer_t iter = buffer;

    /* parse 8-bit vector length */
    if (iter.length < 1) return TLS_PARSE_INCOMPLETE;
    uint8_t len = iter.data[0];
    iter = buffer_slice(iter, 1);

    if (len > EC_POINT_FORMATS_MAX) return TLS_PARSE_ERROR;
    if (len > iter.length) return TLS_PARSE_INCOMPLETE;
    lst->ec_point_formats_len = len;
    for (size_t i = 0; i < lst->ec_point_formats_len; i++) {
        lst->ec_point_formats[i] = iter.data[i];
    }
    iter = buffer_slice(iter, len);

    return iter.data - buffer.data;
}

int64_t client_supported_version_parse(buffer_t buffer, client_supported_version_t *v) {
    /* parse 8-bit vector length */
    buffer_t iter = buffer;
    if (iter.length < 1) return TLS_PARSE_INCOMPLETE;
    uint8_t len = iter.data[0];
    iter = buffer_slice(iter, 1);

    if (len % sizeof(uint16_t) != 0) return TLS_PARSE_ERROR;
    if (len / sizeof(uint16_t) > MAX_SUPPORTED_VERSIONS_LEN) return TLS_PARSE_ERROR;
    if (len > iter.length) return TLS_PARSE_INCOMPLETE;
    v->supported_versions_len = len / sizeof(uint16_t);
    for (size_t i = 0; i < v->supported_versions_len; i++) {
        v->supported_versions[i] = htons(*((uint16_t*)iter.data));
        iter = buffer_slice(iter, sizeof(uint16_t));
    }

    return iter.data - buffer.data;
}

int64_t key_share_entry_parse(buffer_t buffer, key_share_entry_t *e) {
    buffer_t iter = buffer;

    /* parse 16-bit group */
    if (iter.length < 2) return TLS_PARSE_INCOMPLETE;
    uint16_t group = ntohs(*((uint16_t*) iter.data));
    iter = buffer_slice(iter, 2);
    e->group = group;

    /* parse 16-bit len */
    if (iter.length < 2) return TLS_PARSE_INCOMPLETE;
    uint16_t len = ntohs(*((uint16_t*) iter.data));
    iter = buffer_slice(iter, 2);

    switch (e->group) {
    case X25519:
        if (len != 32) return TLS_PARSE_ERROR;
        if (iter.length < len) return TLS_PARSE_INCOMPLETE;
        memcpy(e->x25519, iter.data, 32);
        iter = buffer_slice(iter, 32);
        break;
    default:
        if (iter.length < len) return TLS_PARSE_INCOMPLETE;
        iter = buffer_slice(iter, len);
        break;
    };

    return iter.data - buffer.data;
}

int64_t client_key_share_parse(buffer_t buffer, client_key_share_t *s) {
    buffer_t iter = buffer;

    /* parse 16-bit len */
    if (iter.length < 2) return TLS_PARSE_INCOMPLETE;
    uint16_t len = ntohs(*((uint16_t*) iter.data));
    iter = buffer_slice(iter, 2);
    s->client_shares_len = 0;

    if (len > iter.length) return TLS_PARSE_INCOMPLETE;
    for (size_t i = 0; i < MAX_CLIENT_SHARES_LEN; i++) {
        if (len == 0) break;
        int64_t len2 = key_share_entry_parse((buffer_t){len, iter.data}, &s->client_shares[i]);
        if (len2 < 0) return TLS_PARSE_ERROR;
        iter = buffer_slice(iter, len2);
        len -= len;
        s->client_shares_len += 1;
    }
    if (len != 0) return TLS_PARSE_ERROR;

    return iter.data - buffer.data;
}

int64_t extension_parse(buffer_t buffer, handshake_type_t msg_type, extension_t *ext) {
    /* parse 16-bit extension type */
    buffer_t iter = buffer;
    if (iter.length < sizeof(uint16_t)) return TLS_PARSE_INCOMPLETE;
    ext->extension_type = htons(*((uint16_t*)iter.data));
    iter = buffer_slice(iter, sizeof(uint16_t));

    /* parse 16-bit extension length */
    if (iter.length < sizeof(uint16_t)) return TLS_PARSE_INCOMPLETE;
    size_t len = htons(*((uint16_t*)iter.data));
    if (len > buffer.length) return TLS_PARSE_INCOMPLETE;
    ext->extension_data_len = len;
    iter = buffer_slice(iter, sizeof(uint16_t));

    size_t len2 = len;
    switch (ext->extension_type) {
    case SERVER_NAME:
        len2 = server_name_list_parse((buffer_t){len, iter.data}, &ext->server_name_list);
        break;
    case EC_POINT_FORMATS:
        len2 = ec_point_format_list_parse((buffer_t){len, iter.data}, &ext->ec_format_list);
        break;
    case SUPPORTED_GROUPS:
        len2 = supported_group_list_parse((buffer_t){len, iter.data}, &ext->supported_group_list);
        break;
    case SIGNATURE_ALGORITHMS:
        len2 = signature_scheme_list_parse((buffer_t){len, iter.data}, &ext->signature_scheme_list);
        break;
    case SUPPORTED_VERSION:
        switch (msg_type) {
            case CLIENT_HELLO:
                len2 = client_supported_version_parse((buffer_t){len, iter.data}, &ext->client_supported_version);
                break;
            case SERVER_HELLO:
                printf("info: skipping extension %s\n", extension_type_str(ext->extension_type));
                break;
            default:
                assert(0 && "unexpected");
                break;
        }
        break;
    case KEY_SHARE:
        switch (msg_type) {
            case CLIENT_HELLO:
                len2 = client_key_share_parse((buffer_t){len, iter.data}, &ext->client_key_share);
                break;
            case SERVER_HELLO:
                len2 = key_share_entry_parse((buffer_t){len, iter.data}, &ext->server_key_share.server_share);
                break;
        }
        break;
    default:
        printf("info: skipping extension %s\n", extension_type_str(ext->extension_type));
    }
    if (len2 != len) return TLS_PARSE_ERROR;
    iter = buffer_slice(iter, len);

    return iter.data - buffer.data;
}

int64_t server_hello_parse(buffer_t buffer, server_hello_t *hello) {
    buffer_t iter = buffer;

    /* parse 16-bit version */
    if (iter.length < sizeof(uint16_t)) return TLS_PARSE_INCOMPLETE;
    hello->legacy_version = ntohs(*((uint16_t*)iter.data));
    iter = buffer_slice(iter, sizeof(uint16_t));

    /* parse 32-byte random */
    if (iter.length < 32) return TLS_PARSE_INCOMPLETE;
    memcpy(hello->random, iter.data, 32);
    iter = buffer_slice(iter, 32);
  
    /* parse legacy_session_id vector */
    if (iter.length < 1) return TLS_PARSE_INCOMPLETE;
    size_t v_len = *((uint8_t*)iter.data);
    iter = buffer_slice(iter, 1);
    if (v_len > MAX_LEGACY_SESSION_ID_LEN) return TLS_PARSE_ERROR;
    if (v_len > iter.length) return TLS_PARSE_INCOMPLETE;
    hello->legacy_session_id_echo_len = v_len;
    memcpy(hello->legacy_session_id_echo, iter.data, v_len);
    iter = buffer_slice(iter, v_len);

    /* parse cipher_suite */
    if (iter.length < sizeof(uint16_t)) return TLS_PARSE_INCOMPLETE;
    hello->cipher_suite = ntohs(*((uint16_t*)iter.data));
    iter = buffer_slice(iter, sizeof(uint16_t));

    /* parse legacy_compression_methods vector */
    if (iter.length < 1) return TLS_PARSE_INCOMPLETE;
    hello->legacy_compression_method = iter.data[0];
    iter = buffer_slice(iter,1);

    /* parse extensions vector */
    if (iter.length < sizeof(uint16_t)) return TLS_PARSE_INCOMPLETE;
    v_len = ntohs(*((uint16_t*)iter.data));
    iter = buffer_slice(iter, sizeof(uint16_t));
    if (v_len > iter.length) return TLS_PARSE_INCOMPLETE;
    hello->extensions_len = 0;
    for (size_t i = 0; i < MAX_EXTENSIONS_LEN; i++) {
        if (v_len == 0) break;
        int64_t len2 = extension_parse((buffer_t){v_len, iter.data}, SERVER_HELLO, &hello->extensions[hello->extensions_len]);
        if (len2 < 0) return TLS_PARSE_ERROR;
        v_len -= len2;
        iter = buffer_slice(iter, len2);
        hello->extensions_len += 1;
    }

    return iter.data - buffer.data;
}

int64_t client_hello_parse(buffer_t buffer, client_hello_t *res) {
    buffer_t iter = buffer;
    
    /* parse 16-bit version */
    if (iter.length < 2) return TLS_PARSE_INCOMPLETE;
    res->legacy_version = *((uint16_t*)iter.data);
    iter = buffer_slice(iter, 2);

    /* parse 32-byte random */
    if (iter.length < 32) return TLS_PARSE_INCOMPLETE;
    memcpy(res->random, iter.data, 32);
    iter = buffer_slice(iter, 32);
  
    /* parse legacy_session_id vector */
    if (iter.length < 1) return TLS_PARSE_INCOMPLETE;
    size_t v_len = *((uint8_t*)iter.data);
    iter = buffer_slice(iter, 1);
    if (v_len > MAX_LEGACY_SESSION_ID_LEN) return TLS_PARSE_ERROR;
    if (v_len > iter.length) return TLS_PARSE_INCOMPLETE;
    res->legacy_session_id_len = v_len;
    memcpy(res->legacy_session_id, iter.data, v_len);
    iter = buffer_slice(iter, v_len);

    /* parse cipher_suites vector */
    if (iter.length < 2) return TLS_PARSE_INCOMPLETE;
    v_len = ntohs(*((uint16_t*)iter.data));
    iter = buffer_slice(iter, 2);
    if (v_len % 2 != 0) return TLS_PARSE_ERROR;
    if (v_len / 2 > MAX_CIPHER_SUITES_LEN) return TLS_PARSE_ERROR;
    if (v_len > iter.length) return TLS_PARSE_INCOMPLETE;
    res->cipher_suites_len = v_len / 2;
    for (size_t i = 0; i < res->cipher_suites_len; i++) {
        res->cipher_suites[i] = ntohs(*((uint16_t*)iter.data));
        iter = buffer_slice(iter, 2);
    }

    /* parse legacy_compression_methods vector */
    if (iter.length < 1) return TLS_PARSE_INCOMPLETE;
    v_len = iter.data[0];
    iter = buffer_slice(iter, 1);
    if (v_len > MAX_LEGACY_COMPRESSION_METHODS_LEN) return TLS_PARSE_ERROR;
    if (v_len > iter.length) return TLS_PARSE_INCOMPLETE;
    res->legacy_compression_methods_len = v_len;
    memcpy(res->legacy_compression_methods, iter.data, v_len);
    iter = buffer_slice(iter, v_len);

    /* parse extensions vector */
    if (iter.length < sizeof(uint16_t)) return TLS_PARSE_INCOMPLETE;
    v_len = ntohs(*((uint16_t*)iter.data));
    iter = buffer_slice(iter, sizeof(uint16_t));
    if (v_len > iter.length) return TLS_PARSE_INCOMPLETE;
    res->extensions_len = 0;
    for (size_t i = 0; i < MAX_EXTENSIONS_LEN; i++) {
        if (v_len == 0) break;
        int64_t len2 = extension_parse((buffer_t){v_len, iter.data}, CLIENT_HELLO, &res->extensions[res->extensions_len]);
        if (len2 < 0) return TLS_PARSE_ERROR;
        v_len -= len2;
        iter = buffer_slice(iter, len2);
        res->extensions_len += 1;
    }

    return iter.data - buffer.data;
}

void client_supported_version_write(dyn_buf_t *buf, client_supported_version_t *v) {
    uint8_t len = sizeof(uint16_t) * v->supported_versions_len;
    dyn_buf_write(buf, &len, 1);
    for (size_t i = 0; i < v->supported_versions_len; i++) {
        uint16_t version = htons(v->supported_versions[i]);
        dyn_buf_write(buf, &version, sizeof(uint16_t));
    }
}

void signature_scheme_list_write(dyn_buf_t *buf, signature_scheme_list_t *lst) {
    uint16_t len = htons(sizeof(uint16_t) * lst->signature_schemes_len);
    dyn_buf_write(buf, &len, 2);
    for (size_t i = 0; i < lst->signature_schemes_len; i++) {
        uint16_t s = htons(lst->signature_schemes[i]);
        dyn_buf_write(buf, &s, sizeof(uint16_t));
    }
}

void key_share_entry_write(dyn_buf_t *buf, key_share_entry_t *e) {
    uint16_t group = htons(e->group);
    dyn_buf_write(buf, &group, 2);
    uint16_t len;
    switch (e->group) {
    case X25519:
        len = htons(32);
        dyn_buf_write(buf, &len, 2);
        dyn_buf_write(buf, e->x25519, 32);
        break;
    default:
        assert(0 && "not implemented");
    }
}

void client_key_share_write(dyn_buf_t *buf, client_key_share_t *k) {
    uint16_t *client_key_share_len = buf->data + buf->length;
    dyn_buf_write(buf, &(uint16_t){0}, sizeof(uint16_t));
    size_t client_key_share_start = buf->length;
    for (size_t i = 0; i < k->client_shares_len; i++) {
        key_share_entry_t *e = &k->client_shares[i];
        key_share_entry_write(buf, e);
    }
    size_t client_key_share_end = buf->length;
    *client_key_share_len = htons(client_key_share_end - client_key_share_start);
}

void supported_group_list_write(dyn_buf_t *buf, supported_group_list_t *lst) {
    uint16_t *supported_group_list_len = buf->data + buf->length;
    dyn_buf_write(buf, &(uint16_t){0}, sizeof(uint16_t));
    size_t supported_group_list_start = buf->length;
    for (size_t i = 0; i < lst->supported_groups_len; i++) {
        uint16_t group = htons(lst->supported_groups[i]);
        dyn_buf_write(buf, &group, sizeof(uint16_t));
    }
    size_t supported_group_list_end = buf->length;
    *supported_group_list_len = htons(supported_group_list_end - supported_group_list_start);
}

void ec_point_format_list_write(dyn_buf_t *buf, ec_point_format_list_t *lst) {
    dyn_buf_write(buf, &lst->ec_point_formats_len, 1);
    for (size_t i = 0; i < lst->ec_point_formats_len; i++) {
        uint8_t format = lst->ec_point_formats[i];
        dyn_buf_write(buf, &format, 1);
    }
}

void extension_write(dyn_buf_t *buf, handshake_type_t msg_type, extension_t *ext) {
    uint16_t extension_type = htons(ext->extension_type);
    dyn_buf_write(buf, &extension_type, sizeof(uint16_t));

    uint16_t *extension_len = buf->data + buf->length;
    dyn_buf_write(buf, &(uint16_t){0}, sizeof(uint16_t));
    size_t extension_start = buf->length;
    switch (ext->extension_type) {
    case SUPPORTED_VERSION:
        client_supported_version_write(buf, &ext->client_supported_version);
        break;
    case SIGNATURE_ALGORITHMS:
        signature_scheme_list_write(buf, &ext->signature_scheme_list);
        break;
    case KEY_SHARE:
        if (msg_type == CLIENT_HELLO) {
            client_key_share_write(buf, &ext->client_key_share);
        } else if (msg_type == SERVER_HELLO) {
            key_share_entry_write(buf, &ext->server_key_share.server_share);
        } else {
            assert(0 && "not implemented");
        }
        break;
    case SUPPORTED_GROUPS:
        supported_group_list_write(buf, &ext->supported_group_list);
        break;
    case EC_POINT_FORMATS:
        ec_point_format_list_write(buf, &ext->ec_format_list);
        break;
    default:
        assert(0 && "not implemented");
    }
    size_t extension_end = buf->length;
    *extension_len = htons(extension_end - extension_start);
}

void client_hello_write(dyn_buf_t *buf, client_hello_t *client_hello) {
    dyn_buf_write(buf, &client_hello->legacy_version, sizeof(uint16_t));
    dyn_buf_write(buf, client_hello->random, 32);
    dyn_buf_write(buf, &client_hello->legacy_session_id_len, 1);
    dyn_buf_write(buf, client_hello->legacy_session_id, client_hello->legacy_session_id_len);
    
    /* write cipher_suites vector */
    uint16_t *cipher_suites_len = (uint16_t*) (buf->data + buf->length);
    dyn_buf_write(buf, &(uint16_t){0}, sizeof(uint16_t));
    size_t cipher_suites_start = buf->length;
    for (size_t i = 0; i < client_hello->cipher_suites_len; i++) {
        uint16_t cipher_suite = htons(client_hello->cipher_suites[i]);
        dyn_buf_write(buf, &cipher_suite, sizeof(uint16_t));
    }
    size_t cipher_suites_end = buf->length;
    *cipher_suites_len = htons(cipher_suites_end - cipher_suites_start);

    /* write legacy_compression_methods vector */
    dyn_buf_write(buf, &client_hello->legacy_compression_methods_len, 1);
    dyn_buf_write(buf, &client_hello->legacy_compression_methods, client_hello->legacy_compression_methods_len);

    /* write extensions vector */
    uint16_t *extensions_len = (uint16_t*) (buf->data + buf->length);
    dyn_buf_write(buf, &(uint16_t){0}, sizeof(uint16_t));
    size_t extensions_start = buf->length;
    for (size_t i = 0; i < client_hello->extensions_len; i++) {
        extension_t *ext = &client_hello->extensions[i];
        extension_write(buf, CLIENT_HELLO, ext);
    }
    size_t extensions_end = buf->length;
    *extensions_len = htons(extensions_end - extensions_start);

}

void server_hello_write(dyn_buf_t *buf, server_hello_t *server_hello) {
    dyn_buf_write(buf, &server_hello->legacy_version, sizeof(uint16_t));
    dyn_buf_write(buf, server_hello->random, 32);
    dyn_buf_write(buf, &server_hello->legacy_session_id_echo_len, 1);
    dyn_buf_write(buf, server_hello->legacy_session_id_echo, server_hello->legacy_session_id_echo_len);
    
    /* write cipher_suite  */
    uint16_t cipher_suite = htons(server_hello->cipher_suite);
    dyn_buf_write(buf, &cipher_suite, sizeof(uint16_t));

    /* write legacy_compression_method */
    dyn_buf_write(buf, &server_hello->legacy_compression_method, 1);

    /* write extensions vector */
    uint16_t *extensions_len = (uint16_t*) (buf->data + buf->length);
    dyn_buf_write(buf, &(uint16_t){0}, sizeof(uint16_t));
    size_t extensions_start = buf->length;
    for (size_t i = 0; i < server_hello->extensions_len; i++) {
        extension_t *ext = &server_hello->extensions[i];
        extension_write(buf, SERVER_HELLO, ext);
    }
    size_t extensions_end = buf->length;
    *extensions_len = htons(extensions_end - extensions_start);
}
