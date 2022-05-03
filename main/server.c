#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include<unistd.h>
#include <sys/types.h>
#include <sha256.h>

#define BUFFER_SIZE 1024
#define PORT 8080
#define SA struct sockaddr
   
#include <record.h>
#include <assert.h>
#include <hmac.h>

void generate_random(buffer_t buf) {
    FILE *rnd = fopen("/dev/urandom", "r");
    assert(rnd != NULL);
    size_t n_read = fread(buf.data, buf.length, 1, rnd);
    assert(n_read == 1);
}

void send_server_hello(client_hello_t *client_msg, int fd) {
    handshake_message_t handshake_message;
    handshake_message.msg_type = SERVER_HELLO;
    server_hello_t *server_hello = &handshake_message.server_hello;
    server_hello->legacy_version = 0x0303;
    generate_random((buffer_t){32, server_hello->random});
    server_hello->legacy_session_id_echo_len = client_msg->legacy_session_id_len;
    memcpy(server_hello->legacy_session_id_echo, client_msg->legacy_session_id, client_msg->legacy_session_id_len);
    server_hello->legacy_compression_method = 0;
    server_hello->cipher_suite = TLS_CHACHA20_POLY1305_SHA256;
    server_hello->extensions_len = 0;

    dyn_buf_t buf = dyn_buf_create(1024);
    handshake_message_write(&buf, &handshake_message);
    
    tls_plaintext_t record;
    record.type = CONTENT_TYPE_HANDSHAKE;
    record.legacy_record_version = TLS_10;
    record.length = buf.length;
    record.fragment = buf.data;

    dyn_buf_t buff = dyn_buf_create(buf.length + 7);
    tls_plaintext_write(&buff, &record);
    write(fd, buff.data, buff.length);
    
    printf("\n>>> HANDSHAKE [%zu] ", buff.length);
    uint8_t hash[32];
    sha256(buf.data, buf.length, hash);
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Function designed for chat between client and server.
void func(int fd) {
    uint8_t data[BUFFER_SIZE];
    size_t n_read = read(fd, data, BUFFER_SIZE);
    tls_plaintext_t record = {0};
    n_read = tls_plaintext_parse((buffer_t){n_read, data}, &record);
    assert(n_read > 0);

    printf("<<< %s [%zu] ", content_type_str(record.type), n_read);
    uint8_t hash[32];
    sha256(record.fragment, record.length, hash);
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    handshake_message_t msg = {0};
    n_read = handshake_message_parse((buffer_t){record.length, record.fragment}, &msg);
    assert(msg.msg_type == CLIENT_HELLO);

    client_hello_t client_hello = msg.client_hello;
    printf("legacy_version: %04x\n", client_hello.legacy_version);
    printf("random (32): ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", client_hello.random[i]);
    }
    printf("\n");
    printf("session_id (%zu): ", client_hello.legacy_session_id_len);
    for (size_t i = 0; i < client_hello.legacy_session_id_len; i++) {
        printf("%02x", client_hello.legacy_session_id[i]);
    }
    printf("\n");
    printf("cipher_suites (%zu): \n", client_hello.cipher_suites_len);
    for (size_t i = 0; i < client_hello.cipher_suites_len; i++) {
        uint16_t cipher_suite = client_hello.cipher_suites[i];
        printf("%zu: %04x: %s\n", i, cipher_suite, cipher_suite_str(cipher_suite));
    }
    printf("compression_methods (%zu): \n", client_hello.legacy_compression_methods_len);
    for (size_t i = 0; i < client_hello.legacy_compression_methods_len; i++) {
        printf("%zu: %d \n", i, client_hello.legacy_compression_methods[i]);
    }
    printf("extensions (%zu): \n", client_hello.extensions_len);
    for (size_t i = 0; i < client_hello.extensions_len; i++) {
        extension_t *ext = &client_hello.extensions[i];
        printf("%zu: %d: %s %zu\n", i, ext->extension_type, extension_type_str(ext->extension_type), ext->extension_data_len);
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

    send_server_hello(&client_hello, fd);

    printf("\n-------- HANDSHAKE KEYS --------\n");
    uint8_t early_secret[32];
    hmac_sha256_sign(NULL, 0, NULL, 0, early_secret);
    printf("early_secret: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", early_secret[i]);
    }
    printf("\n");
    uint8_t empty_hash[32];
    sha256(NULL, 0, empty_hash);
    printf("empty_hash: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", empty_hash[i]);
    }
    printf("\n");

    printf("\n--------------------------------\n");

}

// Driver function
int main()
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;
   
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
   
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
   
    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");
   
    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening..\n");
    len = sizeof(cli);
   
    // Accept the data packet from client and verification
    connfd = accept(sockfd, (SA*)&cli, (socklen_t*) &len);
    if (connfd < 0) {
        printf("server accept failed...\n");
        exit(0);
    }
    else
        printf("server accept the client...\n");
   
    // Function for chatting between client and server
    func(connfd);
   
    // After chatting close the socket
    close(sockfd);
}
