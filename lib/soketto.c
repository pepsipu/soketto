#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>

#define BAD_SOCK_FD -1
#define BAD_ADDRESS -2
#define CONN_ERR -3

enum PacketTypes
{
    DataPacket = 0,
    ClosePacket,
};

typedef struct sokettoClientConnection
{
    int sock_fd;
    pthread_t thread;
    struct sokettoClientFunctionTable *ft;
    void (*recvCallback)(void *data, ssize_t data_amount);
} skClient;

typedef struct sokettoPacketHeader
{
    uint32_t packet_size;
    uint8_t packet_id;
    uint8_t data[];
} skPacket;

ssize_t sokettoSend(skClient *self, void *buf, size_t len)
{
    skPacket packet;
    packet.packet_size = (uint32_t)len;
    packet.packet_id = DataPacket;
    return send(self->sock_fd, (void *)&packet, sizeof(skPacket), 0) + send(self->sock_fd, buf, len, 0);
}

int sokettoClose(skClient *self)
{
    skPacket packet;
    packet.packet_size = 0;
    packet.packet_id = ClosePacket;
    if (send(self->sock_fd, &packet, sizeof(skPacket), 0) < 0)
    {
        return -1;
    }
    return close(self->sock_fd);
}

void *sokettoRecvThread(skClient *self)
{
    skPacket header;
    for (;;)
    {
        if (self->recvCallback)
        {
            memset(&header, 0, sizeof(skPacket));
            if (recv(self->sock_fd, &header, sizeof(skPacket), 0) != sizeof(skPacket))
                continue;
            void *data_chunk = malloc(header.packet_size);
            ssize_t data_size = recv(self->sock_fd, data_chunk, header.packet_size, 0);
            if (self->recvCallback)
                self->recvCallback(data_chunk, data_size);
            free(data_chunk);
        }
    }
}

struct sokettoClientFunctionTable
{
    ssize_t (*send)(skClient *self, void *buf, size_t len);
};

struct sokettoClientFunctionTable ft = (struct sokettoClientFunctionTable){
    .send = sokettoSend,
};

skClient *skClientConnect(char *address, uint16_t port, int8_t *err)
{
    int sock_fd;
    struct sockaddr_in sock_address;
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        if (err)
            *err = BAD_SOCK_FD;
        return NULL;
    }
    sock_address.sin_family = AF_INET;
    sock_address.sin_port = htons(port);
    if (inet_pton(AF_INET, address, &sock_address.sin_addr) <= 0)
    {
        if (err)
            *err = BAD_ADDRESS;
        return NULL;
    }
    if (connect(sock_fd, (struct sockaddr *)&sock_address, sizeof(sock_address)) != 0)
    {
        if (err)
            *err = CONN_ERR;
        return NULL;
    }
    skClient *sk_client = malloc(sizeof(skClient));
    *sk_client = (skClient){
        .sock_fd = sock_fd,
        .ft = &ft,
        .thread = 0,
    };
    pthread_create(&sk_client->thread, NULL, sokettoRecvThread, sk_client);
    return sk_client;
}