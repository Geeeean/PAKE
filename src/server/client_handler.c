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

    int length = ntohs(setup_packet.header.length);
    uint16_t phi0_len;
    memcpy(&phi0_len, setup_packet.payload, sizeof(phi0_len));

    phi0_len = ntohs(phi0_len);

    uint16_t c_len = length - sizeof(phi0_len) - phi0_len;

    unsigned char *phi0 = malloc(phi0_len);
    unsigned char *c = malloc(c_len);

    memcpy(phi0, setup_packet.payload + sizeof(phi0_len), phi0_len);
    memcpy(c, setup_packet.payload + sizeof(phi0_len) + phi0_len, c_len);

    // TODO: rest of the comunication

cleanup:
    return NULL;
}

void handle_connection(const Connection connection)
{
    pthread_t thread;
    pthread_create(&thread, NULL, handle_client, (void *)&connection);
}
