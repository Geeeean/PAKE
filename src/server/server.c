#include "server/server.h"
#include "network.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

struct Server {
    const char *client_id;
    const char *server_id;
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

Server *server_init(const char *server_id, int socket)
{
    Server *server = NULL;

    if (!server_id || socket < 0) {
        goto cleanup;
    }

    server = malloc(sizeof(Server));
    if (!server) {
        goto cleanup;
    }

    server->server_id = (const char *)strdup(server_id);
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
    int result = EXIT_SUCCESS;

    Packet packet = pt_initialize_packet(MSG_HELLO);
    packet.payload = pt_build_hello_payload(server->server_id, &packet.header.length);

    if (nw_send_packet(server->socket, &packet) < 0) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&packet);

    return result;
}

int server_send_close_packet(Server *server)
{
    int result = EXIT_SUCCESS;

    Packet packet = pt_initialize_packet(MSG_CLOSE);

    if (nw_send_packet(server->socket, &packet) < 0) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&packet);

    return result;
}

int server_send_v_packet(Server *server)
{
    int result = EXIT_SUCCESS;

    Packet packet = pt_initialize_packet(MSG_V);
    packet.payload =
        pt_build_v_payload(server->v, sizeof(server->v), &packet.header.length);

    if (nw_send_packet(server->socket, &packet) < 0) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&packet);

    return result;
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
        return EXIT_FAILURE;
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
