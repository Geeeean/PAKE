#include<unity.h>
#include<utils.h>
#include "log.h"
#include <stdio.h>
#include <string.h>

void spake_keys() {
    const unsigned char *password = "pass123";
    const unsigned char *client_id = "hej123";
    const unsigned char *server_id = "server123";
    /*** CLIENT PAKE ***/
    // TEMP: Our way of getting the public and fixed group elements a,b
    // Maybe you have a better way Gianluca
    unsigned char a[crypto_core_ristretto255_BYTES];
    unsigned char b[crypto_core_ristretto255_BYTES];
    generate_a_b_group_elements(a, b);

    // (phi0, phi1) <- H(pi||client_id||server_id)
    unsigned char phi0[crypto_core_ristretto255_SCALARBYTES];
    unsigned char phi1[crypto_core_ristretto255_SCALARBYTES];
    H_function(password, client_id, server_id, phi0, phi1);

    // c <- g^(phi0)
    unsigned char c[crypto_core_ristretto255_BYTES];
    crypto_scalarmult_ristretto255_base(c, phi1);

    // alpha <- Z_p
    unsigned char alpha[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(alpha);
    // u = g^(alpha)a^(phi0)
    unsigned char u[crypto_core_ristretto255_BYTES];
    compute_u_value(alpha, a, phi0, u);

        unsigned char beta[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(beta);

    unsigned char g_beta[crypto_core_ristretto255_BYTES];
    unsigned char b_phi0[crypto_core_ristretto255_BYTES];
    unsigned char v[crypto_core_ristretto255_BYTES];

    crypto_scalarmult_ristretto255_base(g_beta, beta);

    if (crypto_scalarmult_ristretto255(b_phi0, phi0, b) != 0) {
        LOG_ERROR("Error computing b^{phi0}");
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
    }

    crypto_core_ristretto255_add(v, g_beta, b_phi0);

    unsigned char w[crypto_core_ristretto255_BYTES];
    unsigned char d[crypto_core_ristretto255_BYTES];
    compute_w_d_values_for_client(alpha, b, v, phi0, phi1, w, d);

    // k = H'(phi0||client_id||server_id||u||v||w||d)
    unsigned char k_1[32];
    H_prime(phi0, sizeof(phi0), client_id, strlen((const char *)client_id), server_id,
            strlen((const char *)server_id), u, sizeof(u), v, sizeof(v), w, sizeof(w), d,
            sizeof(d), k_1);
    
    unsigned char a_phi0[crypto_core_ristretto255_BYTES];
    unsigned char u_a_phi0[crypto_core_ristretto255_BYTES];

    if (crypto_scalarmult_ristretto255(a_phi0, phi0, a) != 0) {
        LOG_ERROR("Error computing a^{phi0}");
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
    }

    crypto_core_ristretto255_sub(u_a_phi0, u, a_phi0);

    if (crypto_scalarmult_ristretto255(w, beta, u_a_phi0) != 0) {
        LOG_ERROR("Error computing w");
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
        sodium_memzero(a_phi0, sizeof(a_phi0));
    }

    if (crypto_scalarmult_ristretto255(d, beta, c) != 0) {
        LOG_ERROR("Error computing d");
        free(phi0);
        free(c);
        sodium_memzero(beta, sizeof(beta));
        sodium_memzero(a_phi0, sizeof(a_phi0));
        sodium_memzero(u_a_phi0, sizeof(u_a_phi0));
    }

    // Compute session key k
    // k = H′(φ0 ‖ idC ‖ idS ‖ u ‖ v ‖ w ‖ d)
    unsigned char k_2[32];

    if (H_prime(phi0, sizeof(phi0),
                (const unsigned char *)client_id, strlen(client_id),
                (const unsigned char *)server_id, strlen(server_id),
                u, sizeof(u),
                v, sizeof(v),
                w, sizeof(w),
                d, sizeof(d),
                k_2) != 0) {
        LOG_ERROR("Error computing H'");
    } else {
        LOG_INFO("Computed session key k (client):");
        // for testing purposes only
        char hex_1[65];
        for (size_t i = 0; i < sizeof(k_1); i++) {
            sprintf(hex_1 + (i * 2), "%02x", k_1[i]);
        }
        hex_1[64] = '\0';
        LOG_INFO("%s", hex_1);
        LOG_INFO("Computed session key k (server):");
        // for testing purposes only
        char hex_2[65];
        for (size_t i = 0; i < sizeof(k_2); i++) {
            sprintf(hex_2 + (i * 2), "%02x", k_2[i]);
        }
        hex_2[64] = '\0';
        LOG_INFO("%s", hex_2);
    }
}

void setUp(void) { sodium_init(); }

void tearDown(void) {}

void simple_protocol_correct(void) {
    unsigned char key_client[32];
    unsigned char key_server[32];
    spake_keys();
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(simple_protocol_correct);
    return UNITY_END();
}