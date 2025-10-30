#ifndef CLIENT_H
#define CLIENT_H

#include "network.h"
#include "protocol.h"

typedef struct Client Client;

typedef enum {
    RR_SUCCESS,
    RR_FAILURE,
    RR_TYPE_ERROR,
} ReceiveResult;

Client *client_init(const char *client_id, const char *password, int socket);
int client_send_hello_packet(Client *client);
ReceiveResult client_receive_hello_packet(Client *client, Packet *packet);

#endif
