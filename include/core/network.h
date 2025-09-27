#ifndef NETWORK_H
#define NETWORK_H

int get_socket();
struct sockaddr_in get_address();
int set_socket_reuse(int socket_fd);

#endif
