#include "network.h"

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#else

#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

#endif

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main()
{
    int result = 0;
    int listen_socket_fd = get_socket();

    /*** SOCKET ***/
    if (listen_socket_fd < 0) {
        fprintf(stderr, "Error while creating the socket: %s\n", strerror(errno));
        result = 1;
        goto cleanup;
    }

    /*** OPTIONS ***/
    int opt = 1;
#ifdef _WIN32
    if (setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
                   sizeof(opt)) < 0) {
#else
    if (setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
#endif
        fprintf(stderr, "Error while setting socket options\n");
        result = 1;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address = get_address();

    /*** BINDING ***/
    if (bind(listen_socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        result = 3;
        fprintf(stderr, "Error while binding socket to addr: %s\n", strerror(errno));
        goto cleanup;
    }

    if (listen(listen_socket_fd, 3) < 0) {
        result = 4;
        fprintf(stderr, "Error while setting socket for listening: %s\n",
                strerror(errno));
        goto cleanup;
    }

    /*** MAIN LOOP ***/
    struct sockaddr client_address;
    socklen_t socklen = sizeof(client_address);
    int new_socket =
        accept(listen_socket_fd, (struct sockaddr *)&client_address, &socklen);

    if (new_socket < 0) {
        goto cleanup;
    }

    char buffer[1024];
    ssize_t valread = read(new_socket, buffer, sizeof(buffer) - 1);

    printf("%s\n", buffer);

    char *hello = "Helloooooooooo!";

    send(new_socket, hello, strlen(hello), 0);
    printf("Hello message sent\n");

cleanup:
    close(listen_socket_fd);
    return result;
}
