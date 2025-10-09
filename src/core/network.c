#include "network.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#define PORT 3333

int get_socket()
{
    return socket(AF_INET, SOCK_STREAM, 0);
}

struct sockaddr_in get_address()
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(PORT);

    return address;
}

int set_socket_reuse(int socket_fd)
{
    int opt = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        return 1;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        return 2;
    }

    return 0;
}
