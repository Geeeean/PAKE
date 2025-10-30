#include "client/client.h"
#include "network.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

struct Client {
    const char *client_id;
    const char *server_id;
    const char *password;
    int socket;

    // TODO: Our way of getting the public and fixed group elements a,b
    // Maybe we can find a better way
    unsigned char a[crypto_core_ristretto255_BYTES];
    unsigned char b[crypto_core_ristretto255_BYTES];

    // (phi0, phi1) <- H(pi||client_id||server_id)
    unsigned char phi0[crypto_core_ristretto255_SCALARBYTES];
    unsigned char phi1[crypto_core_ristretto255_SCALARBYTES];

    // c <- g^(phi0)
    unsigned char c[crypto_core_ristretto255_BYTES];

    // alpha <- Z_p
    unsigned char alpha[crypto_core_ristretto255_SCALARBYTES];

    // u <- g^(alpha)a^(phi0)
    unsigned char u[crypto_core_ristretto255_BYTES];

    unsigned char v[crypto_core_ristretto255_BYTES];

    // w <- (v/b^(phi0))^(alpha)
    unsigned char w[crypto_core_ristretto255_BYTES];

    // d <- (v/b^(phi0))^(phi1)
    unsigned char d[crypto_core_ristretto255_BYTES];

    // k <- H'(phi0||client_id||server_id||u||v||w||d)
    unsigned char k[32];
};

Client *client_init(const char *client_id, const char *password, int socket)
{
    Client *client = NULL;

    if (!client_id || !password || socket < 0) {
        goto cleanup;
    }

    client = malloc(sizeof(Client));
    if (!client) {
        goto cleanup;
    }

    client->client_id = (const char *)strdup(client_id);
    if (!client->client_id) {
        goto cleanup;
    }

    client->password = (const char *)strdup(password);
    if (!client->password) {
        goto cleanup;
    }

    client->socket = socket;

    return client;

cleanup:
    if (client) {
        free((unsigned char *)client->password);
        free((unsigned char *)client->client_id);
    }
    free(client);

    return NULL;
}

int client_send_hello_packet(Client *client)
{
    int result = EXIT_SUCCESS;

    Packet hello_packet = pt_initialize_packet(MSG_HELLO);
    hello_packet.payload =
        pt_build_hello_payload(client->client_id, &hello_packet.header.length);

    if (nw_send_packet(client->socket, &hello_packet) < 0) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&hello_packet);

    return result;
}

int client_send_setup_packet(Client *client)
{
    int result = EXIT_SUCCESS;

    Packet setup_packet = pt_initialize_packet(MSG_SETUP);
    setup_packet.payload =
        pt_build_setup_payload(client->phi0, sizeof(client->phi0), client->c,
                               sizeof(client->c), &setup_packet.header.length);

    if (nw_send_packet(client->socket, &setup_packet) < 0) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&setup_packet);
    return result;
}

int client_send_u_packet(Client *client)
{
    int result = EXIT_SUCCESS;

    Packet u_packet = pt_initialize_packet(MSG_U);
    u_packet.payload =
        pt_build_u_payload(client->u, sizeof(client->u), &u_packet.header.length);

    if (nw_send_packet(client->socket, &u_packet) < 0) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    pt_free_packet_payload(&u_packet);
    return result;
}

ReceiveResult client_receive_hello_packet(Client *client)
{
    Packet packet;

    if (nw_receive_packet(client->socket, &packet) < 0) {
        return RR_FAILURE;
    }

    if (packet.header.type != MSG_HELLO) {
        return RR_TYPE_ERROR;
    }

    client->server_id = strdup(packet.payload);

    return RR_SUCCESS;
}

ReceiveResult client_receive_v_packet(Client *client)
{
    Packet packet;

    if (nw_receive_packet(client->socket, &packet) < 0) {
        return RR_FAILURE;
    }

    if (packet.header.type != MSG_V ||
        packet.header.length != crypto_core_ristretto255_BYTES) {
        return RR_TYPE_ERROR;
    }

    memcpy(client->v, packet.payload, crypto_core_ristretto255_BYTES);
    pt_free_packet_payload(&packet);

    return RR_SUCCESS;
}

void client_compute_group_elements(Client *client)
{
    generate_a_b_group_elements(client->a, client->b);
}

int client_compute_phi(Client *client)
{
    if (!client->password || !client->client_id || !client->server_id) {
        return EXIT_FAILURE;
    }

    H_function((const unsigned char *)client->password,
               (const unsigned char *)client->client_id,
               (const unsigned char *)client->server_id, client->phi0, client->phi1);

    return EXIT_SUCCESS;
}

void client_compute_c(Client *client)
{
    crypto_scalarmult_ristretto255_base(client->c, client->phi1);
}

void client_compute_alpha(Client *client)
{
    crypto_core_ristretto255_scalar_random(client->alpha);
}

void client_compute_u(Client *client)
{
    compute_u_value(client->alpha, client->a, client->phi0, client->u);
}

void client_compute_w_d(Client *client)
{
    compute_w_d_values_for_client(client->alpha, client->b, client->v, client->phi0,
                                  client->phi1, client->w, client->d);
}

void client_compute_k(Client *client)
{
    H_prime(client->phi0, sizeof(client->phi0), (const unsigned char *)client->client_id,
            strlen(client->client_id), (const unsigned char *)client->server_id,
            strlen(client->server_id), client->u, sizeof(client->u), client->v,
            sizeof(client->v), client->w, sizeof(client->w), client->d, sizeof(client->d),
            client->k);
}

unsigned char *client_get_k(Client *client)
{
    return client->k;
}

uint64_t client_get_k_size(Client *client)
{
    return sizeof(client->k);
}
