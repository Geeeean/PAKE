#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>

typedef struct Client Client;

typedef enum {
    RR_SUCCESS,
    RR_FAILURE,
    RR_TYPE_ERROR,
} ReceiveResult;

Client *client_init(const char *client_id, const char *password, int socket);

int client_send_hello_packet(Client *client);
int client_send_setup_packet(Client *client);
int client_send_u_packet(Client *client);

ReceiveResult client_receive_hello_packet(Client *client);
ReceiveResult client_receive_v_packet(Client *client);

int client_compute_group_elements(Client *client);
int client_compute_phi(Client *client);
int client_compute_c(Client *client);
void client_compute_alpha(Client *client);
int client_compute_u(Client *client);
int client_compute_w_d(Client *client);
int client_compute_k(Client *client);

unsigned char *client_get_k(Client *client);
uint64_t client_get_k_size(Client *client);

#endif
