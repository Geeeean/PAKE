#include "client/client.h"
#include "log.h"
#include "network.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (sodium_init() == -1) {
        LOG_ERROR("Unable to initialize sodium");
        return EXIT_FAILURE;
    }

    if (argc != 3) {
        LOG_ERROR("Client requires an id and a password");
        return EXIT_FAILURE;
    }

    int result = EXIT_SUCCESS;
    int socket = nw_get_socket();

    /*** SOCKET ***/
    if (socket < 0) {
        LOG_ERROR("While getting the socket");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address = nw_get_address();
    if (connect(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        LOG_ERROR("Connection failed");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    Client *client = client_init(argv[1], argv[2], socket);

    /*** CLIENT HELLO ***/
    if (client_send_hello_packet(client)) {
        LOG_ERROR("While sending HELLO packet");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    LOG_INFO("Hello packet sent");

    switch (client_receive_hello_packet(client)) {
    case RR_SUCCESS:
        LOG_INFO("HELLO packet received");
        break;
    case RR_TYPE_ERROR:
        LOG_ERROR("Expected HELLO packet, aborting...");
        result = EXIT_FAILURE;
        goto cleanup;
        break;
    default:
        LOG_ERROR("While receiving HELLO packet, aborting...");
        result = EXIT_FAILURE;
        goto cleanup;
        break;
    }

    /*** CLIENT PAKE ***/
    client_compute_group_elements(client);
    client_compute_phi(client);
    client_compute_c(client);

    // Sends phi0 and c to the server
    if (client_send_setup_packet(client)) {
        LOG_ERROR("While sending SETUP packet");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    LOG_INFO("SETUP packet sent");

    client_compute_alpha(client);
    client_compute_u(client);

    // Sends u to the server
    if (client_send_u_packet(client)) {
        LOG_ERROR("While sending U packet");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    LOG_INFO("U packet sent");

    // Receiving v
    unsigned char v[crypto_core_ristretto255_BYTES];

    switch (client_receive_v_packet(client)) {
    case RR_SUCCESS:
        LOG_INFO("V packet received");
        break;
    case RR_TYPE_ERROR:
        LOG_ERROR("Expected V packet, aborting...");
        result = EXIT_FAILURE;
        goto cleanup;
        break;
    default:
        LOG_ERROR("While receiving V packet, aborting...");
        result = EXIT_FAILURE;
        goto cleanup;
        break;
    }

    client_compute_w_d(client);
    client_compute_k(client);

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
    close(socket);
    return result;
}
