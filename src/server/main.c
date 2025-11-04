#include "log.h"
#include "network.h"
#include "server/server.h"
#include "server/storage.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    LOG_INFO("Server init...");

    /*** Windows OS setup ***/
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            LOG_ERROR("WSAStartup failed");
            return 1;
        }
    #endif

    int result = 0;
    int listen_socket_fd = nw_get_socket();

    if (argc != 2) {
        LOG_ERROR("Server requires an id");
        result = 1;
        goto cleanup;
    }

    /*** SOCKET ***/
    if (listen_socket_fd < 0) {
        LOG_ERROR("While creating the socket");
        result = 1;
        goto cleanup;
    }
    LOG_INFO("Socket created successfully");

    /*** OPTIONS ***/
    int opt = 1;
    if (nw_set_socket_reuse(listen_socket_fd)) {
        LOG_ERROR("While setting socket options");
        result = 2;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address = nw_get_address();

    /*** BINDING ***/
    if (bind(listen_socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        LOG_ERROR("While binding socket to addr");
        result = 3;
        goto cleanup;
    }

    if (listen(listen_socket_fd, 3) < 0) {
        LOG_ERROR("While setting socket for listening");
        result = 4;
        goto cleanup;
    }

    /*** STORAGE ***/
    if (storage_init(argv[1])) {
        LOG_ERROR("While initializing storage");
        result = 5;
        goto cleanup;
    }
    LOG_INFO("Storage initialized");

    /*** MAIN LOOP ***/
    LOG_INFO("Server waiting for connections...");
    server_loop(argv[1], listen_socket_fd);

cleanup:
    #ifdef _WIN32
        WSACleanup();
    #endif
    close(listen_socket_fd);
    return result;
}
