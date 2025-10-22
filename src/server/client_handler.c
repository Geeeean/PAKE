#include "server/client_handler.h"
#include "log.h"
#include "network.h"
#include "protocol.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void *handle_client(void *args)
{
    const Connection *connection = (const Connection *)args;
    int socket = connection->socket;

    Packet hello_packet;
    if (nw_receive_packet(socket, &hello_packet) < 0) {
        LOG_ERROR("While receiving client hello packet, aborting...");
        goto cleanup;
    }

    if (hello_packet.header.type != MSG_HELLO) {
        LOG_ERROR("First packet received is not a client hello, aborting...");
        goto cleanup;
    }

    LOG_INFO("Client hello payload: %s", (char *)hello_packet.payload);

    // TODO: rest of the comunication

cleanup:
    return NULL;
}

void handle_connection(const Connection connection)
{
    pthread_t thread;
    pthread_create(&thread, NULL, handle_client, (void *)&connection);
}
