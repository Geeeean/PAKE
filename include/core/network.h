#ifndef NETWORK_H
#define NETWORK_H

#include "protocol.h"
#include "sodium.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

typedef enum {
    TCP,
    UNIX,
} SocketType;

int nw_get_socket(SocketType socket_type);
int nw_get_address(SocketType socket_type, struct sockaddr *address,
                   const char *server_id);
int nw_set_socket_reuse(int socket_fd);

ssize_t nw_send_packet(int socket, const Packet *packet);
ssize_t nw_receive_packet(int socket, Packet *packet);

#endif
