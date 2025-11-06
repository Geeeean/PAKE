#include "server/server.h"
#include "log.h"
#include "network.h"
#include "protocol.h"
#include "server/server.h"
#include "server/storage.h"
#include "utils.h"

#include "sodium.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

struct Server {
    char *client_id;
    char *server_id;
    int socket;

    // TODO: Our way of getting the public and fixed group elements a,b
    // Maybe we can find a better way
    unsigned char a[crypto_core_ristretto255_BYTES];
    unsigned char b[crypto_core_ristretto255_BYTES];

    unsigned char phi0[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    unsigned char u[crypto_core_ristretto255_BYTES];
    unsigned char beta[crypto_core_ristretto255_SCALARBYTES];
    unsigned char g_beta[crypto_core_ristretto255_BYTES];
    unsigned char b_phi0[crypto_core_ristretto255_BYTES];
    unsigned char v[crypto_core_ristretto255_BYTES];
    unsigned char a_phi0[crypto_core_ristretto255_BYTES];
    unsigned char u_a_phi0[crypto_core_ristretto255_BYTES];
    unsigned char w[crypto_core_ristretto255_BYTES];
    unsigned char d[crypto_core_ristretto255_BYTES];
    unsigned char k[32];
};

typedef struct {
    int socket;
    const char *server_id;
} Connection;

Server *server_init(const char *server_id, int socket)
{
    Server *server = NULL;

    if (!server_id) {
        goto cleanup;
    }

    if (socket < 0) {
        goto cleanup;
    }

    server = malloc(sizeof(Server));
    if (!server) {
        goto cleanup;
    }

    server->server_id = strdup(server_id);
    if (!server->server_id) {
        goto cleanup;
    }

    server->socket = socket;

    return server;

cleanup:
    if (server) {
        free((unsigned char *)server->server_id);
    }
    free(server);

    return NULL;
}

int server_send_hello_packet(Server *server)
{
    int result = SUCCESS;

    Packet packet = pt_initialize_packet(MSG_HELLO);
    packet.payload = pt_build_hello_payload(server->server_id, &packet.header.length);

    if (nw_send_packet(server->socket, &packet) < 0) {
        result = FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&packet);

    return result;
}

int server_send_close_packet(Server *server)
{
    int result = SUCCESS;

    Packet packet = pt_initialize_packet(MSG_CLOSE);

    if (nw_send_packet(server->socket, &packet) < 0) {
        result = FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&packet);

    return result;
}

int server_send_v_packet(Server *server)
{
    int result = SUCCESS;

    Packet packet = pt_initialize_packet(MSG_V);
    packet.payload =
        pt_build_v_payload(server->v, sizeof(server->v), &packet.header.length);

    if (nw_send_packet(server->socket, &packet) < 0) {
        result = FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&packet);

    return result;
}

ReceiveResult server_receive_close_packet(Server *server)
{
    Packet packet;

    if (nw_receive_packet(server->socket, &packet) < 0) {
        return RR_FAILURE;
    }

    if (packet.header.type != MSG_CLOSE) {
        return RR_TYPE_ERROR;
    }

    return RR_SUCCESS;
}

ReceiveResult server_receive_hello_packet(Server *server)
{
    Packet packet;

    if (nw_receive_packet(server->socket, &packet) < 0) {
        return RR_FAILURE;
    }

    if (packet.header.type != MSG_HELLO) {
        return RR_TYPE_ERROR;
    }

    server->client_id = strdup(packet.payload);

    return RR_SUCCESS;
}

ReceiveResult server_receive_setup_packet(Server *server)
{
    ReceiveResult result = RR_SUCCESS;

    unsigned char *phi0 = NULL;
    unsigned char *c = NULL;
    uint16_t phi0_len = 0;
    uint16_t c_len = 0;

    Packet packet;
    if (nw_receive_packet(server->socket, &packet) < 0) {
        return RR_FAILURE;
    }

    if (packet.header.type != MSG_SETUP) {
        result = RR_TYPE_ERROR;
        goto cleanup;
    }

    if (pt_parse_setup_packet(&packet, &phi0, &phi0_len, &c, &c_len) != 0) {
        result = RR_TYPE_ERROR;
        goto cleanup;
    }

    // TODO: is this necessary?
    if (phi0_len != crypto_core_ristretto255_SCALARBYTES ||
        c_len != crypto_core_ristretto255_BYTES) {
        result = RR_TYPE_ERROR;
        goto cleanup;
    }

    memcpy(server->phi0, phi0, crypto_core_ristretto255_SCALARBYTES);
    memcpy(server->c, c, crypto_core_ristretto255_BYTES);

cleanup:
    pt_free_packet_payload(&packet);
    free(phi0);
    free(c);

    return result;
}

ReceiveResult server_receive_u_packet(Server *server)
{
    Packet packet;

    if (nw_receive_packet(server->socket, &packet) < 0) {
        return RR_FAILURE;
    }

    if (packet.header.type != MSG_U ||
        packet.header.length != crypto_core_ristretto255_BYTES) {
        return RR_TYPE_ERROR;
    }

    memcpy(server->u, packet.payload, crypto_core_ristretto255_BYTES);
    pt_free_packet_payload(&packet);

    return RR_SUCCESS;
}

VerifyResult server_verify_secret(Server *server)
{
    return storage_verify_secret(server->client_id, server->phi0, sizeof(server->phi0),
                                 server->c, sizeof(server->c));
}

int server_store_secret(Server *server)
{
    return storage_store_secret(server->client_id, server->phi0, sizeof(server->phi0),
                                server->c, sizeof(server->c));
}

int server_compute_group_elements(Server *server)
{
    return generate_a_b_group_elements(server->a, server->b);
}

void server_compute_beta(Server *server)
{
    crypto_core_ristretto255_scalar_random(server->beta);
}

int server_compute_g_beta(Server *server)
{
    return crypto_scalarmult_ristretto255_base(server->g_beta, server->beta);
}

int server_compute_b_phi0(Server *server)
{
    return crypto_scalarmult_ristretto255(server->b_phi0, server->phi0, server->b);
}

int server_compute_v(Server *server)
{
    return crypto_core_ristretto255_add(server->v, server->g_beta, server->b_phi0);
}

int server_compute_a_phi0(Server *server)
{
    return crypto_scalarmult_ristretto255(server->a_phi0, server->phi0, server->a);
}

int server_compute_u_a_phi0(Server *server)
{
    return crypto_core_ristretto255_sub(server->u_a_phi0, server->u, server->a_phi0);
}

int server_compute_w(Server *server)
{
    return crypto_scalarmult_ristretto255(server->w, server->beta, server->u_a_phi0);
}

int server_compute_d(Server *server)
{
    return crypto_scalarmult_ristretto255(server->d, server->beta, server->c);
}

int server_compute_k(Server *server)
{
    if (!server) {
        return FAILURE;
    }

    return H_prime(server->phi0, sizeof(server->phi0),
                   (const unsigned char *)server->client_id, strlen(server->client_id),
                   (const unsigned char *)server->server_id, strlen(server->server_id),
                   server->u, sizeof(server->u), server->v, sizeof(server->v), server->w,
                   sizeof(server->w), server->d, sizeof(server->d), server->k);
}

unsigned char *server_get_k(Server *server)
{
    return server->k;
}

uint64_t server_get_k_size(Server *server)
{
    return sizeof(server->k);
}

void server_close(Server **server)
{
    if (server) {
        if (*server) {
            free((*server)->server_id);
            free((*server)->client_id);
            close((*server)->socket);
            free(*server);
            *server = NULL;
        }
    }
}

static void *handle_client(void *args)
{
    Connection *connection = (Connection *)args;
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
    server_close(&server);
    return NULL;
}

static void server_handle_connection(Connection *connection)
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
    pthread_create(&thread, NULL, handle_client, (void *)connection);
    pthread_detach(thread);
#endif
}

static int server_handle_helper(const char *server_id, int listen_socket)
{
    struct sockaddr client_address;
    socklen_t socklen = sizeof(client_address);
    int new_socket = accept(listen_socket, (struct sockaddr *)&client_address, &socklen);

    if (new_socket < 0) {
        return FAILURE;
    }

    Connection *connection = malloc(sizeof(Connection));
    connection->socket = new_socket;
    connection->server_id = server_id;

    server_handle_connection(connection);

    return SUCCESS;
}

int server_loop(const char *server_id, int listen_socket, int max)
{
    int result = EXIT_SUCCESS;

    if (max > 0) {
        while (1) {
            if (server_handle_helper(server_id, listen_socket)) {
                result = EXIT_FAILURE;
                goto cleanup;
            }
        }
    } else {
        for (int i = 0; i < max; i++) {
            if (server_handle_helper(server_id, listen_socket)) {
                result = EXIT_FAILURE;
                goto cleanup;
            }
        }
    }

cleanup:;
    // todo
    // exit threads
    // server delete
    return result;
}
