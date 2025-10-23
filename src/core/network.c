#include "network.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#define PORT 3333

int nw_get_socket()
{
    return socket(AF_INET, SOCK_STREAM, 0);
}

struct sockaddr_in nw_get_address()
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(PORT);

    return address;
}

int nw_set_socket_reuse(int socket)
{
    int opt = 1;

#ifdef _WIN32
    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
                   sizeof(opt))) {
#else
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
#endif
        return 1;
    }

#ifdef _WIN32
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, (const char *)&opt, sizeof(opt))) {
#else
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
#endif
        return 2;
    }

    return 0;
}

ssize_t nw_send_packet(int socket, const Packet *packet)
{
    const Header *header = &packet->header;
    const void *payload = packet->payload;

    size_t header_length = sizeof(header->length) + sizeof(header->type);
    size_t total_length = header->length + header_length;

    uint8_t *buffer = malloc(total_length);
    if (!buffer) {
        return -1;
    }

    uint16_t net_len = htons(header->length);  // convert to network order
    memcpy(buffer, &net_len, sizeof(net_len)); // copy payload length into message
    buffer[2] = header->type;                  // copy message type

    // todo: avoid copy the data again
    memcpy(buffer + header_length, payload, header->length); // copy message payload

    size_t bytes_sent = 0;
    while (bytes_sent < total_length) {
        ssize_t n = send(socket, buffer + bytes_sent, total_length - bytes_sent, 0);
        if (n <= 0) {
            free(buffer);
            return -1; // error while sending the message
        }
        bytes_sent += n;
    }

    free(buffer);
    return bytes_sent;
}

ssize_t nw_receive_packet(int socket, Packet *packet)
{
    Header header;
    if (recv(socket, (void *)&header, 3, MSG_WAITALL) != 3) {
        LOG_ERROR("RECEIVE ERROR");
        return -1;
    }
    header.length = ntohs(header.length);

    uint8_t *payload = malloc(header.length);
    if (!payload) {
        return -1;
    }

    if (recv(socket, payload, header.length, MSG_WAITALL) != header.length) {
        free(payload);
        return -1;
    }

    packet->header = header;
    packet->payload = payload;

    return header.length + sizeof(header);
}
