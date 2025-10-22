#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#else

#include <netinet/in.h>
#include <sys/socket.h>
#endif

typedef struct {
    int socket;
} Connection;

void handle_connection(const Connection connection);

#endif
