#include "client/client.h"
#include "log.h"
#include "network.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
/*** Windows OS setup ***/
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed");
        return 1;
    }
#endif

    if (sodium_init() == -1) {
        LOG_ERROR("Unable to initialize sodium, aborting...");
        return EXIT_FAILURE;
    }

    if (argc != 3) {
        LOG_ERROR("Client requires an id and a password, aborting...");
        return EXIT_FAILURE;
    }

    int result = EXIT_SUCCESS;
    int socket = nw_get_socket(TCP);

    /*** SOCKET ***/
    if (socket < 0) {
        LOG_ERROR("While getting the socket, aborting...");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address;
    nw_get_address(TCP, (struct sockaddr *)&address, argv[1]);
    if (connect(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        LOG_ERROR("Connection failed, aborting...");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    Client *client = client_init(argv[1], argv[2], socket);
    result = client_run(client); 
    if (result) {
        goto cleanup;
    }

    unsigned char *k = client_get_k(client);

    // for testing purposes only
    char hex[65];
    for (size_t i = 0; i < client_get_k_size(client); i++) {
        sprintf(hex + (i * 2), "%02x", k[i]);
    }
    hex[64] = '\0';

    LOG_INFO("Computed session key k (client):");
    LOG_INFO("%s", hex);

cleanup:
#ifdef _WIN32
    WSACleanup();
#endif
    client_close(&client);
    return result;
}
