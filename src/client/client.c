#include "client/client.h"

#include <stdlib.h>
#include <string.h>

struct Client {
    const char *client_id;
    const char *password;
    int socket;
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

ReceiveResult client_receive_hello_packet(Client *client, Packet *packet)
{
    if (nw_receive_packet(client->socket, packet) < 0) {
        return RR_FAILURE;
    }

    if (packet->header.type != MSG_HELLO) {
        return RR_TYPE_ERROR;
    }

    return RR_SUCCESS;
}
