#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>   // for size_t

int sum(const int a, const int b);
int H_function(const unsigned char *password, const unsigned char *id_client,
               const unsigned char *id_server, unsigned char *output0,
               unsigned char *output1);


int H_prime(const unsigned char* phi0, size_t phi0_len,
            const unsigned char* id_client, size_t id_client_len,
            const unsigned char* id_server, size_t id_server_len,
            const unsigned char* u, size_t u_len,
            const unsigned char* v, size_t v_len,
            const unsigned char* w, size_t w_len,
            const unsigned char* d, size_t d_len,
            unsigned char output[32]);

#endif
