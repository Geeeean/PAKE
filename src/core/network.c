#include "network.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

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
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
                   sizeof(opt))) {
#else
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
#endif
        return 1;
    }

#ifndef _WIN32
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        return 2;
    }
#endif

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
    size_t total = 0;
    size_t header_size = 3;
    uint8_t *hdr_ptr = (uint8_t *)&header;

    // Receive header
    while (total < header_size) {
        int n = recv(socket, hdr_ptr + total, header_size - total, 0);
        if (n <= 0) {
            LOG_ERROR("RECEIVE ERROR (header)");
            return -1;
        }
        total += n;
    }

    header.length = ntohs(header.length);

    uint8_t *payload = malloc(header.length);
    if (!payload) return -1;

    // Receive payload
    total = 0;
    while (total < header.length) {
        int n = recv(socket, payload + total, header.length - total, 0);
        if (n <= 0) {
            free(payload);
            LOG_ERROR("RECEIVE ERROR (payload)");
            return -1;
        }
        total += n;
    }

    packet->header = header;
    packet->payload = payload;
    return header.length + sizeof(header);
}
