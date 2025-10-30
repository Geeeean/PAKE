#include "server/client_handler.h"
#include "log.h"
#include "network.h"
#include "protocol.h"
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
    int socket = connection->socket;
    char *server_id = connection->server_id;

    Packet client_hello_packet;
    if (nw_receive_packet(socket, &client_hello_packet) < 0) {
        LOG_ERROR("While receiving client hello packet, aborting...");
        goto cleanup;
    }
    if (client_hello_packet.header.type != MSG_HELLO) {
        LOG_ERROR("First packet received is not a client hello, aborting...");
        goto cleanup;
    }
    char *client_id = client_hello_packet.payload;
    LOG_INFO("Client handshake: %s", client_id);

    Packet hello_packet = pt_initialize_packet(MSG_HELLO);
    hello_packet.payload =
        pt_build_hello_payload((const char *)server_id, &hello_packet.header.length);
    if (nw_send_packet(socket, &hello_packet) < 0) {
        LOG_ERROR("While sending hello packet");
        goto cleanup;
    }
    pt_free_packet_payload(&hello_packet);

    Packet setup_packet;
    if (nw_receive_packet(socket, &setup_packet) < 0) {
        LOG_ERROR("While receiving client setup packet, aborting...");
        goto cleanup;
    }

    if (setup_packet.header.type != MSG_SETUP) {
        LOG_ERROR("Expected SETUP packet, aborting...");
        pt_free_packet_payload(&setup_packet);
        goto cleanup;
    }

    unsigned char *phi0 = NULL;
    unsigned char *c = NULL;
    uint16_t phi0_len = 0;
    uint16_t c_len = 0;

    if (pt_parse_setup_packet(&setup_packet, &phi0, &phi0_len, &c, &c_len) != 0) {
        LOG_ERROR("While parsing setup packet");
        pt_free_packet_payload(&setup_packet);
        goto cleanup;
    }
    pt_free_packet_payload(&setup_packet); // payload copied, free the packet payload

    if (phi0_len != crypto_core_ristretto255_SCALARBYTES) {
        LOG_ERROR("phi0 length mismatch: expected %d, got %d",
                  crypto_core_ristretto255_SCALARBYTES, phi0_len);
        free(phi0);
        free(c);
        goto cleanup;
    }

    switch (storage_verify_secret(client_id, phi0, phi0_len, c, c_len)) {
    case VR_SUCCESS:
        LOG_INFO("Secret verified correctly");
        break;
    case VR_NOT_FOUND:
        LOG_INFO("Secret not found, storing...");
        if (storage_store_secret(client_id, phi0, phi0_len, c, c_len)) {
            LOG_ERROR("While storing secret");
            goto cleanup;
        }
        LOG_INFO("Secret stored");
        break;
    case VR_NOT_VALID:
        LOG_INFO("Secret is not valid, aborting...");
        goto cleanup;
    default:
        LOG_ERROR("While verifying secret");
        goto cleanup;
    }

    // Generate fixed group elements a and b
    unsigned char a[crypto_core_ristretto255_BYTES];
    unsigned char b[crypto_core_ristretto255_BYTES];
    if (generate_a_b_group_elements(a, b) != 0) {
        LOG_ERROR("Error generating a,b");
        free(phi0);
        free(c);
        goto cleanup;
    }

    // Receiving u
    Packet u_packet;
    if (nw_receive_packet(socket, &u_packet) < 0) {
        LOG_ERROR("While receiving u packet");
        free(phi0);
        free(c);
        goto cleanup;
    }

    if (u_packet.header.type != MSG_U ||
        u_packet.header.length != crypto_core_ristretto255_BYTES) {
        LOG_ERROR("u packet invalid");
        pt_free_packet_payload(&u_packet);
        free(phi0);
        free(c);
        goto cleanup;
    }

    unsigned char u[crypto_core_ristretto255_BYTES];
    memcpy(u, u_packet.payload, crypto_core_ristretto255_BYTES);
    pt_free_packet_payload(&u_packet);

    // S samples β ← Zp uniformly at random, computes v = gβ bφ0
    unsigned char beta[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(beta);

    unsigned char g_beta[crypto_core_ristretto255_BYTES];
    unsigned char b_phi0[crypto_core_ristretto255_BYTES];
    unsigned char v[crypto_core_ristretto255_BYTES];

    crypto_scalarmult_ristretto255_base(g_beta, beta);

    if (crypto_scalarmult_ristretto255(b_phi0, phi0, b) != 0) {
        LOG_ERROR("Error computing b^{phi0}");
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
        goto cleanup;
    }

    crypto_core_ristretto255_add(v, g_beta, b_phi0);

    // Send v to C
    Packet v_packet = pt_initialize_packet(MSG_V);
    v_packet.payload = pt_build_v_payload(v, sizeof(v), &v_packet.header.length);
    if (nw_send_packet(socket, &v_packet) < 0) {
        LOG_ERROR("While sending v packet");
        pt_free_packet_payload(&v_packet);
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
        goto cleanup;
    }
    pt_free_packet_payload(&v_packet);

    // Compute w and d
    // w = (u / a^{phi0})^{beta}
    // d = c^{beta}
    unsigned char a_phi0[crypto_core_ristretto255_BYTES];
    unsigned char u_a_phi0[crypto_core_ristretto255_BYTES];
    unsigned char w[crypto_core_ristretto255_BYTES];
    unsigned char d[crypto_core_ristretto255_BYTES];

    if (crypto_scalarmult_ristretto255(a_phi0, phi0, a) != 0) {
        LOG_ERROR("Error computing a^{phi0}");
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
        goto cleanup;
    }

    crypto_core_ristretto255_sub(u_a_phi0, u, a_phi0);

    if (crypto_scalarmult_ristretto255(w, beta, u_a_phi0) != 0) {
        LOG_ERROR("Error computing w");
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
        sodium_memzero(a_phi0, sizeof(a_phi0));
        goto cleanup;
    }

    if (crypto_scalarmult_ristretto255(d, beta, c) != 0) {
        LOG_ERROR("Error computing d");
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
        sodium_memzero(a_phi0, sizeof(a_phi0));
        sodium_memzero(u_a_phi0, sizeof(u_a_phi0));
        goto cleanup;
    }

    // Compute session key k
    // k = H′(φ0 ‖ idC ‖ idS ‖ u ‖ v ‖ w ‖ d)
    unsigned char k[32];

    if (H_prime(phi0, phi0_len, (const unsigned char *)client_id, strlen(client_id),
                (const unsigned char *)server_id, strlen(server_id), u, sizeof(u), v,
                sizeof(v), w, sizeof(w), d, sizeof(d), k) != 0) {
        LOG_ERROR("Error computing H'");
    } else {
        // for testing purposes only
        char hex[65];
        for (size_t i = 0; i < sizeof(k); i++) {
            sprintf(hex + (i * 2), "%02x", k[i]);
        }
        hex[64] = '\0';

        LOG_INFO("Computed session key k (server):");
        LOG_INFO("%s", hex);
    }

    // zero sensitive memory and free resources
    sodium_memzero(beta, sizeof(beta));
    sodium_memzero(g_beta, sizeof(g_beta));
    sodium_memzero(b_phi0, sizeof(b_phi0));
    sodium_memzero(a_phi0, sizeof(a_phi0));
    sodium_memzero(u_a_phi0, sizeof(u_a_phi0));
    free(phi0);
    free(c);

cleanup:
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
