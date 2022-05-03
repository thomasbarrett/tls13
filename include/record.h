#ifndef TLS13_RECORD_H
#define TLS13_RECORD_H

#include <buffer.h>

typedef enum {
    CONTENT_TYPE_INVALID = 0,
    CONTENT_TYPE_CHANGE_CIPHER_CPEC = 20,
    CONTENT_TYPE_ALERT = 21,
    CONTENT_TYPE_HANDSHAKE = 22,
    CONTENT_TYPE_APPLICATION_DATA = 23,
    CONTENT_TYPE_HEARTBEAT = 24,
} content_type_t;

typedef enum {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305
} cipher_suite_t;

typedef enum {
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    CERTIFICATE_REQUEST = 13,
    CERTIFICATE_VERIFY = 15,
    FINISHED = 20,
    KEY_UPDATE = 24,
    MESSAGE_HASH = 254,
} handshake_type_t;

typedef struct {
    uint8_t type;
    uint16_t legacy_record_version;
    uint16_t length;
    uint8_t *fragment;
} tls_plaintext_t;

#define MAX_LEGACY_SESSION_ID_LEN 32
#define MAX_CIPHER_SUITES_LEN 8
#define MAX_LEGACY_COMPRESSION_METHODS_LEN 4
#define MAX_EXTENSIONS_LEN 16

typedef enum {
    SERVER_NAME = 0,                                /* RFC 6066 */
    MAX_FRAGMENT_LENGTH = 1,                        /* RFC 6066 */
    STATUS_REQUESTS = 5,                            /* RFC 6066 */
    SUPPORTED_GROUPS = 10,                          /* RFC 8422, 7919 */
    EC_POINT_FORMATS = 11,                          /* RFC8422 */
    SIGNATURE_ALGORITHMS = 13,                      /* RFC 8446 */
    USE_SRTP = 14,                                  /* RFC 5764 */
    HEARTBEAT = 15,                                 /* RFC 6520 */
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,    /* RFC 7301 */
    SIGNED_CERTIFICATE_TIMESTAMP = 18,              /* RFC 6962 */
    CLIENT_CERTIFICATE_TYPE = 19,                   /* RFC 7250 */
    SERVER_CERTIFICATE_TYPE = 20,                   /* RFC 7250 */
    PADDING = 21,                                   /* RFC 7685 */
    ENCRYPT_THEN_MAC = 22,                          /* RFC7366 */
    EXTENDED_MASTER_SECRET = 23,                    /* RFC7627 */
    SESSION_TICKET = 35,                            /* RFC 5077, 8447 */
    PRE_SHARED_KEY = 41,                            /* RFC 8446 */
    EARLY_DATA = 42,                                /* RFC 8446 */
    SUPPORTED_VERSION = 43,                         /* RFC 8446 */
    COOKIE = 44,                                    /* RFC 8446 */
    PSK_KEY_EXCHANGE_MODES = 45,                    /* RFC 8446 */
    CERTIFICATE_AUTHORITIES = 47,                   /* RFC 8446 */
    OID_FILTERS = 48,                               /* RFC 8446 */
    POST_HANDSHAKE_AUTH = 49,                       /* RFC 8446 */
    SIGNATURE_ALGORITHMS_CERT = 50,                 /* RFC 8446 */
    KEY_SHARE = 51                                  /* RFC 8446 */
} extension_type_t;

typedef enum {
    HOSTNAME = 0,
} name_type_t;

#define MAX_HOST_NAME_LEN 63
#define MAX_SERVER_NAME_LIST_LEN 1

typedef struct {
    name_type_t name_type;
    char host_name[MAX_HOST_NAME_LEN + 1];
} server_name_t;

typedef struct {
    size_t server_name_list_len;
    server_name_t server_name_list[1];
} server_name_list_t;

typedef enum {
    EC_POINT_FORMAT_UNCOMPRESSED = 0,
} ec_point_format_t;

#define EC_POINT_FORMATS_MAX 4

typedef struct {
    size_t ec_point_formats_len;
    ec_point_format_t ec_point_formats[EC_POINT_FORMATS_MAX];
} ec_point_format_list_t;

typedef enum {
    SECP256R1 = 23,
    SECP284R1 = 24,
    SECP521R1 = 25,
    X25519 = 29,
    X448 = 30,
} supported_group_t;

#define MAX_SUPPORTED_GROUPS_LEN 8
typedef struct {
    size_t supported_groups_len;
    uint16_t supported_groups[MAX_SUPPORTED_GROUPS_LEN];
} supported_group_list_t;

typedef enum {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RSA_PKCS1_SHA256 = 0x0401, 
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,

    /* ECDSA algorithms */
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RSA_PSS_RSAE_SHA256 = 0x0804, 
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PSS_RSAE_SHA512 = 0x0806,

    /* EdDSA algorithms */
    ED25519 = 0x0807,
    ED448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RSA_PSS_PSS_SHA256 = 0x0809,
    RSA_PSS_PSS_SHA384 = 0x080A,
    RSA_PSS_PSS_SHA512 = 0x080B,

    /* Legacy algorithms */
    RSA_PKCS1_SHA1 = 0x0201,
    ECDSA_SHA1 = 0x0203,
} signature_scheme_t;

#define MAX_SIGNATURE_SCHEMES_LEN 16
typedef struct {
    size_t signature_schemes_len;
    signature_scheme_t signature_schemes[MAX_SIGNATURE_SCHEMES_LEN];
} signature_scheme_list_t;

typedef enum {
    TLS_10 = 0x0301,
    TLS_12 = 0x0303,
    TLS_13 = 0x0304
} protocol_version_t;

#define MAX_SUPPORTED_VERSIONS_LEN 4
typedef struct {
    size_t supported_versions_len;
    protocol_version_t supported_versions[MAX_SUPPORTED_VERSIONS_LEN];
} client_supported_version_t;

typedef struct {
    protocol_version_t selected_version;
} server_supported_version_t;

#define MAX_CLIENT_SHARES_LEN 4

typedef struct {
    supported_group_t group;
    union {
        uint8_t x25519[32];
    };
} key_share_entry_t;

typedef struct {
    size_t client_shares_len;
    key_share_entry_t client_shares[MAX_CLIENT_SHARES_LEN];
} client_key_share_t;

typedef struct {
    key_share_entry_t server_share;
} server_key_share_t;

typedef struct {
    uint16_t extension_type;
    size_t extension_data_len;
    union {
        server_name_list_t server_name_list;
        ec_point_format_list_t ec_format_list;
        supported_group_list_t supported_group_list;
        signature_scheme_list_t signature_scheme_list;
        client_supported_version_t client_supported_version;
        client_key_share_t client_key_share;
        server_key_share_t server_key_share;
    };
} extension_t;

typedef struct {
    uint16_t legacy_version;
    uint8_t random[32];
    size_t legacy_session_id_len;
    uint8_t legacy_session_id[MAX_LEGACY_SESSION_ID_LEN];
    size_t cipher_suites_len;
    cipher_suite_t cipher_suites[MAX_CIPHER_SUITES_LEN];
    size_t legacy_compression_methods_len;
    uint8_t legacy_compression_methods[MAX_LEGACY_COMPRESSION_METHODS_LEN];
    size_t extensions_len;
    extension_t extensions[MAX_EXTENSIONS_LEN]; 
} client_hello_t;

typedef struct {
    uint16_t legacy_version;
    uint8_t random[32];
    size_t legacy_session_id_echo_len;
    uint8_t legacy_session_id_echo[MAX_LEGACY_SESSION_ID_LEN];
    cipher_suite_t cipher_suite;
    uint8_t legacy_compression_method;
    size_t extensions_len;
    extension_t extensions[MAX_EXTENSIONS_LEN]; 
} server_hello_t;

typedef struct {
    handshake_type_t msg_type;
    uint32_t length; 
    union {
        client_hello_t client_hello;
        server_hello_t server_hello;
    };
} handshake_message_t;

#define TLS_PARSE_INCOMPLETE -1
#define TLS_PARSE_ERROR -2

/**
 * Return a string representation of the content-type or NULL if
 * the content-type is unknown.
 * 
 * @param t the content_type
 * @return the string representation of t
 */
const char* content_type_str(content_type_t t);

/**
 * Return a string representation of the cipher-suite or NULL if
 * the cipher-suite is unknown.
 * 
 * @param t the content_type
 * @return the string representation of t
 */
const char* cipher_suite_str(cipher_suite_t t);

/**
 * @brief Return a string representation of the extension type or
 *        NULL if the extension type is unknown.
 * 
 * @param t the extension type
 * @return a string representation of the extension type. 
 */
const char* extension_type_str(extension_type_t t);

/**
 * @brief Return a string representation of the EC point format or
 *        NULL if the EC point format is unknown.
 * 
 * @param f the format
 * @return a string representation of the format 
 */
const char* ec_point_format_str(ec_point_format_t f);

/**
 * @brief Return a string representation of the group or NULL if the group
 *        is unknown.
 * 
 * @param g the group
 * @return a string representation of the group
 */
const char* supported_group_str(supported_group_t g);

/**
 * @brief Return a string representation of the signature scheme or NULL if the
 *        scheme is unknown.
 * 
 * @param s the signature scheme
 * @return a string representation of the signature scheme
 */
const char* signature_scheme_str(signature_scheme_t s);

/**
 * @brief Return a string representation of the signature scheme or NULL if the
 *        scheme is unknown.
 * 
 * @param v the protocol version
 * @return a string representation of the protocol version
 */
const char *protocol_version_str(protocol_version_t v);

/**
 * @brief Parse an ec_point_format_list_t from the buffer and return the number
 *        of bytes consumed.
 * 
 * @param buffer the buffer to parse.
 * @param lst the parse result
 * @return TLS_PARSE_INCOMPLETE if the record cannot be parsed because
 *         the input is incomplete and TLS_PARSE_ERROR if the record
 *         cannot be parsed because the input is incorrect. 
 */
int64_t ec_point_format_list_parse(buffer_t buffer, ec_point_format_list_t *lst);

/**
 * @brief Parse a supported_group_list_t from the buffer and return the number
 *        of bytes consumed.
 * 
 * @param buffer the buffer to parse.
 * @param lst the parse result
 * @return TLS_PARSE_INCOMPLETE if the record cannot be parsed because
 *         the input is incomplete and TLS_PARSE_ERROR if the record
 *         cannot be parsed because the input is incorrect. 
 */
int64_t supported_group_list_parse(buffer_t buffer, supported_group_list_t *lst);

/**
 * @brief Parse a signature_scheme_list_t from the buffer and return the number
 *        of bytes consumed.
 * 
 * @param buffer the buffer to parse.
 * @param lst the parse result
 * @return TLS_PARSE_INCOMPLETE if the record cannot be parsed because
 *         the input is incomplete and TLS_PARSE_ERROR if the record
 *         cannot be parsed because the input is incorrect. 
 */
int64_t signature_scheme_list_parse(buffer_t buffer, signature_scheme_list_t *lst);

/**
 * @brief Parse a client supported_version_t extensino from the buffer and return the
 *        number of bytes consumed.
 * 
 * @param buffer the buffer to parse
 * @param v the parse result
 * @return TLS_PARSE_INCOMPLETE if the record cannot be parsed because
 *         the input is incomplete and TLS_PARSE_ERROR if the record
 *         cannot be parsed because the input is incorrect.  
 */
int64_t client_supported_version_parse(buffer_t buffer, client_supported_version_t *v);

int64_t key_share_entry_parse(buffer_t buffer, key_share_entry_t *e);

int64_t client_key_share_parse(buffer_t buffer, client_key_share_t *s);

/**
 * @brief Parse a TLS 1.3 plaintext record from the buffer and return the number
 *        of bytes consumed.
 * 
 * @param buffer the buffer to parse.
 * @param res the result.
 * @return TLS_PARSE_INCOMPLETE if the record cannot be parsed because
 *         the input is incomplete and TLS_PARSE_ERROR if the record
 *         cannot be parsed because the input is incorrect. 
 */
int64_t tls_plaintext_parse(buffer_t buffer, tls_plaintext_t *res);

void tls_plaintext_write(dyn_buf_t *buf, tls_plaintext_t *msg);

/**
 * @brief Parse a TLS 1.3 handshake message from the buffer and return the number
 *        of bytes consumed.
 * 
 * @param buffer the buffer to parse.
 * @param res the result.
 * @return TLS_PARSE_INCOMPLETE if the record cannot be parsed because
 *         the input is incomplete and TLS_PARSE_ERROR if the record
 *         cannot be parsed because the input is incorrect.  
 */
int64_t handshake_message_parse(buffer_t buffer, handshake_message_t *res);

void handshake_message_write(dyn_buf_t *buf, handshake_message_t *res);

/**
 * @brief Parse a TLS 1.3 client hello message from the buffer and return the number
 *        of bytes consumed.
 * 
 * @param buffer the buffer to parse.
 * @param res the result.
 * @return TLS_PARSE_INCOMPLETE if the record cannot be parsed because
 *         the input is incomplete and TLS_PARSE_ERROR if the record
 *         cannot be parsed because the input is incorrect. 
 */
int64_t client_hello_parse(buffer_t buffer, client_hello_t *res);

int64_t server_hello_parse(buffer_t buffer, server_hello_t *res);

void client_hello_write(dyn_buf_t *buf, client_hello_t *client_hello);

void server_hello_write(dyn_buf_t *buf, server_hello_t *server_hello);

#endif /* TLS13_RECORD */
