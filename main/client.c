#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define MAX 80
#define PORT 8080
#define SA struct sockaddr
#include <sha256.h>

#include <record.h>
#include <hmac.h>
#include <x25519.h>
#include <hkdf.h>
#include <chacha20_poly1305.h>
#include <key_schedule.h>

handshake_keys_t handshake_keys;

void generate_random(buffer_t buf) {
    FILE *rnd = fopen("/dev/urandom", "r");
    assert(rnd != NULL);
    size_t n_read = fread(buf.data, buf.length, 1, rnd);
    assert(n_read == 1);
}

uint32_t swap_uint32(uint32_t val) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}


void bytes_to_uint(uint8_t *bytes, uint_t *n) {
    for (int i = 0; i < N; i++) {
        n[i] = ntohl(swap_uint32(*(uint_t*)(bytes + i * sizeof(uint_t))));
    }
}

void uint_to_bytes(uint_t *n, uint8_t *bytes) {
    for (int i = 0; i < N; i++) {
        *(uint_t*)(bytes + i * sizeof(uint_t)) = swap_uint32(htonl(n[i]));
    }
}

void func(int sockfd) {

    handshake_message_t handshake_message;
    handshake_message.msg_type = CLIENT_HELLO;
    client_hello_t *client_hello = &handshake_message.client_hello;
    client_hello->legacy_version = 0x0303;
    generate_random((buffer_t){32, client_hello->random});
    client_hello->legacy_session_id_len = 32;
    generate_random((buffer_t){32, client_hello->legacy_session_id});
    client_hello->cipher_suites_len = 1;
    client_hello->cipher_suites[0] = TLS_CHACHA20_POLY1305_SHA256;
    client_hello->legacy_compression_methods_len = 1;
    client_hello->legacy_compression_methods[0] = 0;
    client_hello->extensions_len = 0;

    /* append EC_POINT_FORMATS extension to the message */
    {
    extension_t *ext = &client_hello->extensions[client_hello->extensions_len];
    ext->extension_type = EC_POINT_FORMATS;
    ext->ec_format_list.ec_point_formats_len = 1;
    ext->ec_format_list.ec_point_formats[0] = EC_POINT_FORMAT_UNCOMPRESSED;
    client_hello->extensions_len += 1;
    }

    /* append SUPPORTED_VERSION extension to the message */
    {
    extension_t *ext = &client_hello->extensions[client_hello->extensions_len];
    ext->extension_type = SUPPORTED_VERSION;
    ext->client_supported_version.supported_versions_len = 1;
    ext->client_supported_version.supported_versions[0] = TLS_13;
    client_hello->extensions_len += 1;
    }

    /* append SIGNATURE_ALGORITHMS extension to the message */
    {
    extension_t *ext = &client_hello->extensions[client_hello->extensions_len];
    ext->extension_type = SIGNATURE_ALGORITHMS;
    ext->signature_scheme_list.signature_schemes_len = 1;
    ext->signature_scheme_list.signature_schemes[0] = ECDSA_SECP256R1_SHA256;
    client_hello->extensions_len += 1;
    }

     /* append SUPPORTED_GROUPS extension to the message */
    {
    extension_t *ext = &client_hello->extensions[client_hello->extensions_len];
    ext->extension_type = SUPPORTED_GROUPS;
    ext->supported_group_list.supported_groups_len = 2;
    ext->supported_group_list.supported_groups[0] = X25519;
    ext->supported_group_list.supported_groups[1] = SECP256R1;
    client_hello->extensions_len += 1;
    }

    /* append KEY_SHARE extension to the message */
    uint32_t sk[8] = {0};
    {
    extension_t *ext = &client_hello->extensions[client_hello->extensions_len];
    ext->extension_type = KEY_SHARE;
    ext->client_key_share.client_shares_len = 1;
    key_share_entry_t *entry = &ext->client_key_share.client_shares[0];
    entry->group = X25519;
    // x25519 base element
    x25519_element_t base = {0};
    base.x[0] = 9;
    base.z[0] = 1;
    uint8_t sk_bytes[32];
    generate_random((buffer_t){32, sk_bytes});
    x25519_clamp(sk_bytes);
    bytes_to_uint(sk_bytes, sk);
    uint_t pk[2 * N] = {0};
    x25519_scalar_mult(sk, &base, pk);
    uint8_t pk_bytes[32] = {0};
    uint_to_bytes(pk, pk_bytes);
    memcpy(entry->x25519, pk_bytes, 32);
    client_hello->extensions_len += 1;
    }

    dyn_buf_t buf = dyn_buf_create(1024);
    handshake_message_write(&buf, &handshake_message);
    
    tls_plaintext_t record;
    record.type = CONTENT_TYPE_HANDSHAKE;
    record.legacy_record_version = TLS_10;
    record.length = buf.length;
    record.fragment = buf.data;

    dyn_buf_t buff = dyn_buf_create(buf.length + 7);
    tls_plaintext_write(&buff, &record);
    write(sockfd, buff.data, buff.length);
    printf("message of length %zu sent\n", buff.length);
    
    printf("\n>>> %s [%zu] ", content_type_str(record.type), buff.length);
    uint8_t hash0[32];
    sha256(buf.data, buf.length, hash0);
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", hash0[i]);
    }
    printf("\n");

    uint8_t read_buff[1024] = {0};
    size_t n_read = read(sockfd, read_buff, sizeof(read_buff));
    buffer_t buffer = {n_read, read_buff};

    tls_plaintext_t record1 = {0};
    n_read = tls_plaintext_parse(buffer, &record1);
    assert(n_read > 0);
    printf("<<< %s [%zu] ", content_type_str(record1.type), n_read);
    uint8_t hash[32];
    sha256(record1.fragment, record1.length, hash);
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    handshake_message_t msg = {0};
    size_t n_read2 = handshake_message_parse((buffer_t){record1.length, record1.fragment}, &msg);
    assert(n_read2 == record1.length);
    assert(msg.msg_type == SERVER_HELLO);

    server_hello_t server_hello = msg.server_hello;
    printf("    version: %s\n", protocol_version_str(server_hello.legacy_version));
    printf("    random: 0x");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", server_hello.random[i]);
    }
    printf("\n");
    printf("    session_id: ");
    for (size_t i = 0; i < server_hello.legacy_session_id_echo_len; i++) {
        printf("%02x", server_hello.legacy_session_id_echo[i]);
    }
    printf("\n");
    printf("    cipher_suite: %s\n", cipher_suite_str(server_hello.cipher_suite));
    printf("    legacy_compression_method: %d\n", server_hello.legacy_compression_method);
    printf("    extensions:\n");
    x25519_element_t peer_pk = {0};
    peer_pk.z[0] = 1;
    for (size_t i = 0; i < server_hello.extensions_len; i++) {
        extension_t *ext = &server_hello.extensions[i];
        printf("    - %-20s [%03zu bytes]\n", extension_type_str(ext->extension_type), ext->extension_data_len);
        switch (ext->extension_type) {
        case SERVER_NAME:
            for (size_t i = 0; i < ext->server_name_list.server_name_list_len; i++) {
                server_name_t *server_name = &ext->server_name_list.server_name_list[i];
                printf("  - %s\n", server_name->host_name);
            }
            break;
        case EC_POINT_FORMATS:  
            for (size_t i = 0; i < ext->ec_format_list.ec_point_formats_len; i++) {
                ec_point_format_t format = ext->ec_format_list.ec_point_formats[i];
                printf("  - %d: %s\n", format, ec_point_format_str(format));
            }
            break;
        case SUPPORTED_GROUPS:
            for (size_t i = 0; i < ext->supported_group_list.supported_groups_len; i++) {
                supported_group_t g = ext->supported_group_list.supported_groups[i];
                printf("  - %d: %s\n", g, supported_group_str(g));
            }
            break;
        case SIGNATURE_ALGORITHMS:
            for (size_t i = 0; i < ext->signature_scheme_list.signature_schemes_len; i++) {
                signature_scheme_t s = ext->signature_scheme_list.signature_schemes[i];
                printf("  - %d: %s\n", s, signature_scheme_str(s));
            }
            break;
        case SUPPORTED_VERSION:
            for (size_t i = 0; i < ext->client_supported_version.supported_versions_len; i++) {
                protocol_version_t v = ext->client_supported_version.supported_versions[i];
                printf("  - %04x: %s\n", v, protocol_version_str(v));
            }
            break;
        case KEY_SHARE:{
            key_share_entry_t *e = &ext->server_key_share.server_share;
            printf("      - %s: ", supported_group_str(e->group));
            switch (e->group) {
            case X25519:
                bytes_to_uint(e->x25519, peer_pk.x);
                for (size_t i = 0; i < 32; i++) {
                    printf("%02x", e->x25519[i]);
                }
                printf("\n");
                break;
            default:
                printf("NOT IMPLEMENTED\n");
            }
        }
        }
    }

   printf("\n-------- HANDSHAKE KEYS --------\n");
  
    // Compute shared_secret

    uint_t shared_secret[16] = {0};
    x25519_scalar_mult(sk, &peer_pk, shared_secret);
    uint8_t shared_secret_bytes[32] = {0};
    uint_to_bytes(shared_secret, shared_secret_bytes);
    printf("shared_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", shared_secret_bytes[i]);
    }
    printf("\n");

    uint8_t hello_hash[32];
    dyn_buf_t hello = dyn_buf_create(buf.length + record1.length);
    dyn_buf_write(&hello, buf.data, buf.length);
    dyn_buf_write(&hello, record1.fragment, record1.length);
    sha256(hello.data, hello.length, hello_hash);

    /*
     * 
     *
     */
    compute_handshake_keys(hello_hash, shared_secret_bytes, &handshake_keys);

    printf("\n--------------------------------\n");
    
    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record2 = {0};
    n_read = tls_plaintext_parse(buffer, &record2);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record2.type), n_read);

    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record3 = {0};
    n_read = tls_ciphertext_parse(buffer, &handshake_keys.server_traffic, &record3);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record3.type), n_read);
    dyn_buf_write(&hello, record3.fragment, record3.length);

    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record4 = {0};
    n_read = tls_ciphertext_parse(buffer, &handshake_keys.server_traffic, &record4);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record4.type), n_read);
    dyn_buf_write(&hello, record4.fragment, record4.length);

    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record5 = {0};
    n_read = tls_ciphertext_parse(buffer, &handshake_keys.server_traffic, &record4);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record5.type), n_read);
    dyn_buf_write(&hello, record5.fragment, record5.length);
    
    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record6 = {0};
    n_read = tls_ciphertext_parse(buffer, &handshake_keys.server_traffic, &record4);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record6.type), n_read);
    dyn_buf_write(&hello, record6.fragment, record6.length);
    sha256(hello.data, hello.length, hello_hash);

    buffer = buffer_slice(buffer, n_read);
    assert(buffer.length == 0);

    tls_plaintext_t record7;
    record7.type = CONTENT_TYPE_CHANGE_CIPHER_CPEC;
    record7.legacy_record_version = TLS_12;
    record7.length = 1;
    record7.fragment = &(uint8_t){1};

    buff = dyn_buf_create(6);
    tls_plaintext_write(&buff, &record7);
    write(sockfd, buff.data, buff.length);
    printf("\n>>> %s [%zu] \n", content_type_str(record7.type), buff.length);

    uint8_t finished_key[32];
    hkdf_expand_label(
        (buffer_t){32, handshake_keys.client_traffic.secret}, 
        "finished",
        (buffer_t){0, NULL},
        (buffer_t){32, finished_key}
    );

    handshake_message_t finished_msg = {0};
    finished_msg.msg_type = FINISHED;
    hmac_sha256_sign(hello_hash, 32, finished_key, 32, finished_msg.finished.verify_data);

    dyn_buf_t finished_msg_buf = dyn_buf_create(32);
    handshake_message_write(&finished_msg_buf, &finished_msg);
    dyn_buf_write(&finished_msg_buf, &(uint8_t){CONTENT_TYPE_HANDSHAKE}, 1);
    
    uint8_t tag[16];
    tls_plaintext_t record8 = {0};
    record8.type = CONTENT_TYPE_APPLICATION_DATA;
    record8.legacy_record_version = TLS_12;
    record8.length = finished_msg_buf.length + 16;
    record8.fragment = finished_msg_buf.data;
    dyn_buf_t header = dyn_buf_create(512);
    tls_plaintext_write_header(&header, &record8);
    chacha20_poly1305(
        (buffer_t) {5, header.data},
        handshake_keys.client_traffic.key,
        handshake_keys.client_traffic.iv + 4,
        handshake_keys.client_traffic.iv,
        (buffer_t) {record8.length - 16, record8.fragment},
        (buffer_t) {record8.length - 16, record8.fragment},
        tag
    );

    dyn_buf_write(&header, record8.fragment, record8.length - 16);
    dyn_buf_write(&header, tag, 16);
    write(sockfd, header.data, header.length);


    printf("\n>>> %s [%zu] ", content_type_str(record8.type), header.length);
    printf("\n");

    printf("\n-------- APPLICATION KEYS --------\n");
        uint8_t zero[32] = {0};
   
    printf("\n");
    uint8_t empty_hash[32];
    sha256(NULL, 0, empty_hash);
    printf("empty_hash: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", empty_hash[i]);
    }
    printf("\n");

    uint8_t derived_secret[32];
    hkdf_expand_label(
        (buffer_t){32, handshake_keys.handshake_secret}, 
        "derived",
        (buffer_t){32, empty_hash},
        (buffer_t){32, derived_secret}
    );
    printf("derived_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", derived_secret[i]);
    }
    printf("\n");

    uint8_t master_secret[32];
    hmac_sha256_sign(zero, 32, derived_secret, 32, master_secret);
    printf("master_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", master_secret[i]);
    }
    printf("\n");

    uint8_t client_secret[32];
    hkdf_expand_label(
        (buffer_t){32, master_secret}, 
        "c ap traffic",
        (buffer_t){32, hello_hash},
        (buffer_t){32, client_secret}
    );
    printf("client_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", client_secret[i]);
    }
    printf("\n");

    uint8_t server_secret[32];
    hkdf_expand_label(
        (buffer_t){32, master_secret}, 
        "s ap traffic",
        (buffer_t){32, hello_hash},
        (buffer_t){32, server_secret}
    );
    printf("server_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", server_secret[i]);
    }
    printf("\n");

    uint8_t client_handshake_key[32];
    hkdf_expand_label(
        (buffer_t){32, client_secret}, 
        "key",
        (buffer_t){0, NULL},
        (buffer_t){32, client_handshake_key}
    );
    printf("client_handshake_key: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", client_handshake_key[i]);
    }
    printf("\n");

    uint8_t server_handshake_key[32];
    hkdf_expand_label(
        (buffer_t){32, server_secret}, 
        "key",
        (buffer_t){0, NULL},
        (buffer_t){32, server_handshake_key}
    );
    printf("server_handshake_key: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", server_handshake_key[i]);
    }
    printf("\n");


    uint8_t client_handshake_iv[12];
    hkdf_expand_label(
        (buffer_t){32, client_secret}, 
        "iv",
        (buffer_t){0, NULL},
        (buffer_t){12, client_handshake_iv}
    );
    printf("client_handshake_iv: ");
    for (size_t i = 0; i < 12; i++) {
        printf("%02x", client_handshake_iv[i]);
    }
    printf("\n");

    uint8_t server_handshake_iv[12];
    hkdf_expand_label(
        (buffer_t){32, server_secret}, 
        "iv",
        (buffer_t){0, NULL},
        (buffer_t){12, server_handshake_iv}
    );
    printf("server_handshake_iv: ");
    for (size_t i = 0; i < 12; i++) {
        printf("%02x", server_handshake_iv[i]);
    }
    printf("\n");
    printf("\n--------------------------------\n");

    dyn_buf_t msg_buf = dyn_buf_create(32);
    dyn_buf_write(&msg_buf, "hello world!", strlen("hello world!") + 1);
    dyn_buf_write(&msg_buf, &(uint8_t){CONTENT_TYPE_APPLICATION_DATA}, 1);

    tls_plaintext_t record9 = {0};
    record9.type = CONTENT_TYPE_APPLICATION_DATA;
    record9.legacy_record_version = TLS_12;
    record9.length = msg_buf.length + 16;
    record9.fragment = msg_buf.data;
    header = dyn_buf_create(512);
    tls_plaintext_write_header(&header, &record9);
    chacha20_poly1305(
        (buffer_t) {5, header.data},
        client_handshake_key,
        client_handshake_iv + 4,
        client_handshake_iv,
        (buffer_t) {record9.length - 16, record9.fragment},
        (buffer_t) {record9.length - 16, record9.fragment},
        tag
    );

    dyn_buf_write(&header, record9.fragment, record9.length - 16);
    dyn_buf_write(&header, tag, 16);
    write(sockfd, header.data, header.length);

    printf("\n>>> %s [%zu] ", content_type_str(record9.type), header.length);
    printf("\n");
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr;
   
       x25519_init();

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
   
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);
   
    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");
   
    // function for chat
    func(sockfd);
   
    // close the socket
    close(sockfd);
}
