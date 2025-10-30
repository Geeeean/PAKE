#include "server/client_handler.h"
#include "log.h"
#include "network.h"
#include "protocol.h"
#include "server/server.h"
#include "server/storage.h"
#include "utils.h"

#include "sodium.h"

#include <ctype.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void *handle_client(void *args)
{
    const Connection *connection = (const Connection *)args;
    Server *server = server_init(connection->server_id, connection->socket);

    switch (server_receive_hello_packet(server)) {
    case RR_SUCCESS:
        LOG_INFO("HELLO packet received");
        break;
    case RR_TYPE_ERROR:
        LOG_ERROR("Expected HELLO packet, aborting...");
        goto cleanup;
    default:
        LOG_ERROR("While receiving HELLO packet, aborting...");
        goto cleanup;
    }

    /*** SERVER HELLO ***/
    if (server_send_hello_packet(server)) {
        LOG_ERROR("While sending HELLO packet, aborting...");
        goto cleanup;
    }

    LOG_INFO("HELLO packet sent");

    switch (server_receive_setup_packet(server)) {
    case RR_SUCCESS:
        LOG_INFO("SETUP packet received");
        break;
    case RR_TYPE_ERROR:
        LOG_ERROR("Expected SETUP packet, aborting...");
        goto cleanup;
    default:
        LOG_ERROR("While receiving SETUP packet, aborting...");
        goto cleanup;
    }

    switch (server_verify_secret(server)) {
    case VR_SUCCESS:
        LOG_INFO("Secret verified correctly");
        break;
    case VR_NOT_FOUND:
        LOG_INFO("Secret not found, storing...");
        if (server_store_secret(server)) {
            LOG_ERROR("While storing secret, aborting...");
            goto cleanup;
        }
        LOG_INFO("Secret stored");
        break;
    case VR_NOT_VALID:
        if (server_send_close_packet(server)) {
            LOG_ERROR("While sending CLOSE packet, aborting...");
            goto cleanup;
        }
        LOG_ERROR("CLOSE packet sent");
        LOG_INFO("Secret is not valid, aborting...");
        goto cleanup;
    default:
        if (server_send_close_packet(server)) {
            LOG_ERROR("While sending CLOSE packet, aborting...");
            goto cleanup;
        }
        LOG_ERROR("CLOSE packet sent");
        LOG_ERROR("While verifying secret, aborting...");
        goto cleanup;
    }

    if (server_compute_group_elements(server)) {
        LOG_ERROR("While computing group elements, aborting...");
        goto cleanup;
    }

    switch (server_receive_u_packet(server)) {
    case RR_SUCCESS:
        LOG_INFO("U packet received");
        break;
    case RR_TYPE_ERROR:
        LOG_ERROR("Expected U packet, aborting...");
        goto cleanup;
    default:
        LOG_ERROR("While receiving U packet, aborting...");
        goto cleanup;
    }

    server_compute_beta(server);

    if (server_compute_g_beta(server)) {
        LOG_ERROR("While computing g_beta, aborting...");
        goto cleanup;
    }

    if (server_compute_b_phi0(server)) {
        LOG_ERROR("While computing b_phi0, aborting...");
        goto cleanup;
    }

    if (server_compute_v(server)) {
        LOG_ERROR("While computing v, aborting...");
        goto cleanup;
    }

    // Send v to C
    if (server_send_v_packet(server)) {
        LOG_ERROR("While sending V packet, aborting...");
        goto cleanup;
    }

    if (server_compute_a_phi0(server)) {
        LOG_ERROR("While computing a_phi0, aborting...");
        goto cleanup;
    }

    if (server_compute_u_a_phi0(server)) {
        LOG_ERROR("While computing u_a_phi0, aborting...");
        goto cleanup;
    }

    if (server_compute_w(server)) {
        LOG_ERROR("While computing w, aborting...");
        goto cleanup;
    }

    if (server_compute_d(server)) {
        LOG_ERROR("While computing d, aborting...");
        goto cleanup;
    }

    // Compute session key k
    if (server_compute_k(server)) {
        LOG_ERROR("Error computing k, aborting...");
    } else {
        unsigned char *k = server_get_k(server);

        // for testing purposes only
        char hex[65];
        for (size_t i = 0; i < server_get_k_size(server); i++) {
            sprintf(hex + (i * 2), "%02x", k[i]);
        }
        hex[64] = '\0';

        LOG_INFO("Computed session key k (client):");
        LOG_INFO("%s", hex);
    }

    // zero sensitive memory and free resources
    // sodium_memzero(beta, sizeof(beta));
    // sodium_memzero(g_beta, sizeof(g_beta));
    // sodium_memzero(b_phi0, sizeof(b_phi0));
    // sodium_memzero(a_phi0, sizeof(a_phi0));
    // sodium_memzero(u_a_phi0, sizeof(u_a_phi0));
    // free(phi0);
    // free(c);

cleanup:
    // TODO: free server
    return NULL;
}

void handle_connection(const Connection connection)
{
#ifdef _WIN32
    // On Windows, create a thread with CreateThread
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)handle_client,
                                 (LPVOID)&connection, 0, NULL);
    if (thread) {
        CloseHandle(thread);
    } else {
        LOG_ERROR("Failed to create thread on Windows");
    }
#else
    // On Linux / macOS
    pthread_t thread;
    pthread_create(&thread, NULL, handle_client, (void *)&connection);
    pthread_detach(thread);
#endif
}
