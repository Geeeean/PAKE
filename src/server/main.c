#include "log.h"
#include "network.h"
#include "server/client_handler.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int result = 0;
    int listen_socket_fd = nw_get_socket();

    if (argc != 2) {
        LOG_ERROR("Server requires an id");
        result = 1;
        goto cleanup;
    }

    /*** SOCKET ***/
    if (listen_socket_fd < 0) {
        LOG_ERROR("Error while creating the socket");
        result = 1;
        goto cleanup;
    }

    /*** OPTIONS ***/
    int opt = 1;
    if (nw_set_socket_reuse(listen_socket_fd)) {
        LOG_ERROR("Error while setting socket options");
        result = 2;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address = nw_get_address();

    /*** BINDING ***/
    if (bind(listen_socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        LOG_ERROR("Error while binding socket to addr");
        result = 3;
        goto cleanup;
    }

    if (listen(listen_socket_fd, 3) < 0) {
        LOG_ERROR("Error while setting socket for listening");
        result = 4;
        goto cleanup;
    }

    /*** MAIN LOOP ***/
    while (1) {
        struct sockaddr client_address;
        socklen_t socklen = sizeof(client_address);
        int new_socket =
            accept(listen_socket_fd, (struct sockaddr *)&client_address, &socklen);

        if (new_socket < 0) {
            goto cleanup;
        }

        const Connection connection = {.socket = new_socket, .server_id = argv[1]};
        handle_connection(connection);
    }

cleanup:
    close(listen_socket_fd);
    return result;
}
