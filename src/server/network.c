#include "server/network.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void *handle_client(void *args)
{
    const Connection *connection = (const Connection *)args;
    int socket = connection->socket;

    // printf("ACCEPTED CONNECTION WITH CLIENT: %d\n", socket);

    // char buffer[1024];
    // while (read(socket, buffer, sizeof(buffer)) > 0) {
    //     printf("READ FROM CLIENT %d: %s\n", socket, buffer);
    //     if (strcmp(buffer, "END") == 0) {
    //         break;
    //     }
    // }

    return NULL;
}

void sn_handle_connection(const Connection connection)
{
    pthread_t thread;
    pthread_create(&thread, NULL, handle_client, (void *)&connection);
}
