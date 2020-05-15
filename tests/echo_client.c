#include "../lib/soketto.c"

void recvCallback(void *_data, ssize_t size)
{
    char *data = (char *)_data;
    data[size - 1] = '\0';
    printf("data moment: %s", data);
}

int main()
{
    int8_t err;
    skClient *sock = skClientConnect("127.0.0.1", 2222, &err);
    if (!sock)
    {
        return -1;
    }
    sock->ft->send(sock, "owo", 3);
    sock->recvCallback = recvCallback;
    for (;;);
}