#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>   // for size_t
#include <sodium.h>

int sum(const int a, const int b);

int generate_a_b_group_elements(unsigned char a[crypto_core_ristretto255_BYTES],
                                unsigned char b[crypto_core_ristretto255_BYTES]);

int H_function(const unsigned char* password, const unsigned char* id_client, 
                const unsigned char* id_server, unsigned char output0[crypto_core_ristretto255_BYTES], 
                unsigned char output1[crypto_core_ristretto255_BYTES]);


int H_prime(const unsigned char* phi0, size_t phi0_len,
            const unsigned char* id_client, size_t id_client_len,
            const unsigned char* id_server, size_t id_server_len,
            const unsigned char* u, size_t u_len,
            const unsigned char* v, size_t v_len,
            const unsigned char* w, size_t w_len,
            const unsigned char* d, size_t d_len,
            unsigned char output[32]);

int compute_u_value(const unsigned char alpha[crypto_core_ristretto255_SCALARBYTES],
                    const unsigned char a[crypto_core_ristretto255_BYTES],
                    const unsigned char phi0[crypto_core_ristretto255_SCALARBYTES], 
                    unsigned char u[crypto_core_ristretto255_BYTES]);

int compute_w_d_values_for_client(const unsigned char alpha[crypto_core_ristretto255_SCALARBYTES],
                          const unsigned char b[crypto_core_ristretto255_BYTES],
                          const unsigned char v[crypto_core_ristretto255_BYTES],
                          const unsigned char phi0[crypto_core_ristretto255_SCALARBYTES],
                          const unsigned char phi1[crypto_core_ristretto255_SCALARBYTES],
                          unsigned char w[crypto_core_ristretto255_BYTES],
                          unsigned char d[crypto_core_ristretto255_BYTES]);

#endif
