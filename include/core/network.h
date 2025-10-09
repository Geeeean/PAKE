#ifndef NETWORK_H
#define NETWORK_H

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#else

#include <netinet/in.h>
#include <sys/socket.h>

#endif

int nw_get_socket();
struct sockaddr_in nw_get_address();
int nw_set_socket_reuse(int socket_fd);

#endif
