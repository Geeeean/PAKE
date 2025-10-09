#include "network.h"

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

int nw_set_socket_reuse(int socket_fd)
{
    int opt = 1;

#ifdef _WIN32
    if (setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
                   sizeof(opt))) {
#else
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
#endif
        return 1;
    }

#ifdef _WIN32
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&opt,
                   sizeof(opt))) {
#else
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
#endif
        return 2;
    }

    return 0;
}
