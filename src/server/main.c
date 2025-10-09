#include "network.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main()
{
    int result = 0;
    int listen_socket_fd = nw_get_socket();

    /*** SOCKET ***/
    if (listen_socket_fd < 0) {
        fprintf(stderr, "Error while creating the socket\n");
        result = 1;
        goto cleanup;
    }

    /*** OPTIONS ***/
    int opt = 1;
    if (nw_set_socket_reuse(listen_socket_fd)) {
        fprintf(stderr, "Error while setting socket options\n");
        result = 1;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address = nw_get_address();

    /*** BINDING ***/
    if (bind(listen_socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        result = 3;
        fprintf(stderr, "Error while binding socket to addr\n");
        goto cleanup;
    }

    if (listen(listen_socket_fd, 3) < 0) {
        result = 4;
        fprintf(stderr, "Error while setting socket for listening");
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
