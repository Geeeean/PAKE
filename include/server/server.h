#ifndef SERVER_H
#define SERVER_H

typedef struct Server Server;

#include "common.h"
#include "server/storage.h"

Server *server_init(const char *server_id, int socket);

int server_send_close_packet(Server *server);
int server_send_hello_packet(Server *server);
int server_send_v_packet(Server *server);

ReceiveResult server_receive_hello_packet(Server *server);
ReceiveResult server_receive_setup_packet(Server *server);
ReceiveResult server_receive_u_packet(Server *server);

VerifyResult server_verify_secret(Server *server);
int server_store_secret(Server *server);

int server_compute_group_elements(Server *server);
void server_compute_beta(Server *server);
int server_compute_g_beta(Server *server);
int server_compute_b_phi0(Server *server);
int server_compute_v(Server *server);
int server_compute_a_phi0(Server *server);
int server_compute_u_a_phi0(Server *server);
int server_compute_w(Server *server);
int server_compute_d(Server *server);
int server_compute_k(Server *server);

unsigned char *server_get_k(Server *server);
uint64_t server_get_k_size(Server *server);

void server_loop(const char *server_id, int listen_socket_fd);

#endif
