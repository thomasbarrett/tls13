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

#include <record.h>

void generate_random(buffer_t buf) {
    FILE *rnd = fopen("/dev/urandom", "r");
    assert(rnd != NULL);
    size_t n_read = fread(buf.data, buf.length, 1, rnd);
    assert(n_read == 1);
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
    {
    extension_t *ext = &client_hello->extensions[client_hello->extensions_len];
    ext->extension_type = KEY_SHARE;
    ext->client_key_share.client_shares_len = 1;
    key_share_entry_t *entry = &ext->client_key_share.client_shares[0];
    entry->group = X25519;
    uint8_t pk[32] = {
        0x64, 0xa7, 0xf5, 0x89, 0x7e, 0x94, 0x23, 0x63,
        0x59, 0xe7, 0xa6, 0x39, 0xfc, 0x87, 0x12, 0x41,
        0x0e, 0x6b, 0x5f, 0x04, 0x0e, 0x90, 0xa9, 0x32,
        0x23, 0x8f, 0xd0, 0xd8, 0x1a, 0xfc, 0x69, 0x3e
    };
    memcpy(entry->x25519, pk, 32);
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
    
    uint8_t read_buff[1024] = {0};
    size_t n_read = read(sockfd, read_buff, sizeof(read_buff));
    buffer_t buffer = {n_read, read_buff};

    tls_plaintext_t record1 = {0};
    n_read = tls_plaintext_parse(buffer, &record1);
    assert(n_read > 0);
    printf("<<< %s [%zu] \n", content_type_str(record1.type), n_read);

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
        case KEY_SHARE:
            for (size_t i = 0; i < ext->client_key_share.client_shares_len; i++) {
                key_share_entry_t *e = &ext->client_key_share.client_shares[i];
                printf("  - %s: ", supported_group_str(e->group));
                switch (e->group) {
                case X25519:
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
    

    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record2 = {0};
    n_read = tls_plaintext_parse(buffer, &record2);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record2.type), n_read);

    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record3 = {0};
    n_read = tls_plaintext_parse(buffer, &record3);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record3.type), n_read);

    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record4 = {0};
    n_read = tls_plaintext_parse(buffer, &record4);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record4.type), n_read);

    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record5 = {0};
    n_read = tls_plaintext_parse(buffer, &record5);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record5.type), n_read);

    buffer = buffer_slice(buffer, n_read);
    tls_plaintext_t record6 = {0};
    n_read = tls_plaintext_parse(buffer, &record6);
    printf("<<< %-20s [%03zu bytes] \n", content_type_str(record6.type), n_read);

    buffer = buffer_slice(buffer, n_read);
    assert(buffer.length == 0);
}
   
int main() {
    int sockfd;
    struct sockaddr_in servaddr;
   
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
