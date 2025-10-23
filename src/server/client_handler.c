#include "server/client_handler.h"
#include "log.h"
#include "network.h"
#include "protocol.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
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
        LOG_ERROR("aborting...");
        goto cleanup;
    }

    unsigned char *phi0 = NULL;
    unsigned char *c = NULL;

    pt_parse_setup_packet(&setup_packet, phi0, c);

    // TODO for Radu
    // https://learn.inside.dtu.dk/d2l/le/lessons/270908/topics/1066318
    // S samples β ← Zp uniformly at random, computes v = gβ bφ0 and
    // sends v to C.

    // at this point u should have:
    unsigned char v[crypto_core_ristretto255_BYTES] /* = SOMETHING */;

    Packet v_packet = pt_initialize_packet(MSG_V);
    v_packet.payload = pt_build_v_payload(v, sizeof(v), &v_packet.header.length);
    if (nw_send_packet(socket, &v_packet) < 0) {
        LOG_ERROR("While sending v packet");
        goto cleanup;
    }
    pt_free_packet_payload(&v_packet);

    // Receiving u
    unsigned char u[crypto_core_ristretto255_BYTES];

    Packet u_packet;
    if (nw_receive_packet(socket, &u_packet) < 0) {
        LOG_ERROR("While receiving u packet");
        goto cleanup;
    }

    if (u_packet.header.type != MSG_U ||
        u_packet.header.length != crypto_core_ristretto255_BYTES) {
        LOG_ERROR("u packet is not valid");
        goto cleanup;
    }

    memcpy(u, u_packet.payload, crypto_core_ristretto255_BYTES);
    pt_free_packet_payload(&v_packet);

    // TODO for Radu
    // S, upon obtaining u from C, computes
    // w = (u/aφ0 )β
    // d = cβ
    // k = H′(φ0 ‖ idC ‖ idS ‖ u ‖ v ‖ w ‖ d)

cleanup:
    return NULL;
}

void handle_connection(const Connection connection)
{
    pthread_t thread;
    pthread_create(&thread, NULL, handle_client, (void *)&connection);
}
