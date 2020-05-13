#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>

#define BAD_SOCK_FD -1
#define BAD_ADDRESS -2
#define CONN_ERR -3


struct sokettoClientFunctionTable {
    ssize_t (*send)(skClient *self, void *buf, size_t len);
};

const struct sokettoClientFunctionTable ft = (struct sokettoClientFunctionTable) {
    .send = sokettoSend,
};

typedef struct sokettoClientConnection {
    uint16_t sock_fd;
    struct sokettoClientFunctionTable *ft;
} skClient;

typedef struct sokettoDataPacket {
    uint32_t packet_size;
    uint8_t packet_id;
    uint8_t data[];
} skPacket;

skClient *skClientConnect(uint16_t port, char *address, int8_t *err) {
    uint16_t sock_fd;
    struct sockaddr_in sock_address;
    if (sock_fd = socket(AF_INET, SOCK_STREAM, 0) < 0) {
        if (err) *err = BAD_SOCK_FD;
        return NULL;
    }
    sock_address.sin_family = AF_INET;
    sock_address.sin_port = htons(port);
    if (inet_pton(AF_INET, address, &sock_address.sin_addr) <= 0) {
        if (err) *err = BAD_ADDRESS;
        return NULL;
    }
    if (connect(sock_fd, (struct sockaddr *) &sock_address, sizeof(sock_address) < 0)) {
        if (err) *err = CONN_ERR;
        return NULL;
    }
    skClient *sk_client = malloc(sizeof(skClient));
    *sk_client = (skClient) {
        .sock_fd = sock_fd,
        .ft = &ft,
    };
    return sk_client;
}

ssize_t sokettoSend(skClient *self, void *buf, size_t len) {
    size_t packet_size = sizeof(skPacket) + len;
    skPacket *packet = malloc(packet_size);
    packet->packet_size = (uint32_t) len;
    memcpy(packet->data, buf, len);
    return send(self->sock_fd, (void *) packet, packet_size, 0);
}