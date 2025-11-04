#include "log.h"
#include <stdio.h>
#include <string.h>
#include <unity.h>
#include <utils.h>

void setUp(void)
{
    int result = sodium_init();
    if (result < 0) {
        LOG_ERROR("While sodiume init, aborting...");
        exit(EXIT_FAILURE);
    }
}

void tearDown(void) {}

int run_setup(const unsigned char *password, const unsigned char *client_id,
              const unsigned char *server_id, unsigned char phi0[32], unsigned char c[32])
{
    unsigned char a[crypto_core_ristretto255_BYTES];
    unsigned char b[crypto_core_ristretto255_BYTES];
    generate_a_b_group_elements(a, b);

    // (phi0, phi1) <- H(pi||client_id||server_id)
    unsigned char phi1[crypto_core_ristretto255_SCALARBYTES];
    H_function(password, client_id, server_id, phi0, phi1);

    // c <- g^(phi0)
    crypto_scalarmult_ristretto255_base(c, phi1);
    sodium_memzero(phi1, sizeof(phi1));
    return 0;
}

int run_key_exchange(const unsigned char *password, const unsigned char *client_id,
                     const unsigned char *server_id, unsigned char phi0_s[32],
                     unsigned char c[32], unsigned char key_client[32],
                     unsigned char key_server[32])
{
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

    // alpha <- Z_p
    unsigned char alpha[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(alpha);
    // u <- g^(alpha)a^(phi0)
    unsigned char u[crypto_core_ristretto255_BYTES];
    compute_u_value(alpha, a, phi0, u);

    unsigned char beta[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(beta);

    unsigned char g_beta[crypto_core_ristretto255_BYTES];
    unsigned char b_phi0[crypto_core_ristretto255_BYTES];
    unsigned char v[crypto_core_ristretto255_BYTES];

    crypto_scalarmult_ristretto255_base(g_beta, beta);

    if (crypto_scalarmult_ristretto255(b_phi0, phi0_s, b) != 0) {
        LOG_ERROR("Error computing b^{phi0}");
        return -1;
    }

    crypto_core_ristretto255_add(v, g_beta, b_phi0);

    unsigned char w[crypto_core_ristretto255_BYTES];
    unsigned char d[crypto_core_ristretto255_BYTES];
    compute_w_d_values_for_client(alpha, b, v, phi0, phi1, w, d);

    // k = H'(phi0||client_id||server_id||u||v||w||d)
    H_prime(phi0, sizeof(phi0), client_id, strlen((const char *)client_id), server_id,
            strlen((const char *)server_id), u, sizeof(u), v, sizeof(v), w, sizeof(w), d,
            sizeof(d), key_client);

    unsigned char a_phi0[crypto_core_ristretto255_BYTES];
    unsigned char u_a_phi0[crypto_core_ristretto255_BYTES];

    if (crypto_scalarmult_ristretto255(a_phi0, phi0_s, a) != 0) {
        LOG_ERROR("Error computing a^{phi0}");
        return -1;
    }

    crypto_core_ristretto255_sub(u_a_phi0, u, a_phi0);

    if (crypto_scalarmult_ristretto255(w, beta, u_a_phi0) != 0) {
        LOG_ERROR("Error computing w");
        return -1;
    }

    if (crypto_scalarmult_ristretto255(d, beta, c) != 0) {
        LOG_ERROR("Error computing d");
        return -1;
    }

    // Compute session key k
    // k = H′(φ0 ‖ idC ‖ idS ‖ u ‖ v ‖ w ‖ d)
    if (H_prime(phi0_s, crypto_core_ristretto255_SCALARBYTES,
                (const unsigned char *)client_id, strlen((char *)client_id),
                (const unsigned char *)server_id, strlen((char *)server_id), u, sizeof(u),
                v, sizeof(v), w, sizeof(w), d, sizeof(d), key_server) != 0) {
        LOG_ERROR("Error computing H'");
        return -1;
    }
    return 0;
}

void test_a_and_b_generators(void)
{
    unsigned char a_1[crypto_core_ristretto255_BYTES];
    unsigned char b_1[crypto_core_ristretto255_BYTES];
    generate_a_b_group_elements(a_1, b_1);
    TEST_ASSERT_TRUE(crypto_core_ristretto255_is_valid_point(a_1) == 1);
    TEST_ASSERT_TRUE(crypto_core_ristretto255_is_valid_point(b_1) == 1);

    unsigned char a_2[crypto_core_ristretto255_BYTES];
    unsigned char b_2[crypto_core_ristretto255_BYTES];
    generate_a_b_group_elements(a_2, b_2);
    TEST_ASSERT_TRUE(memcmp(a_1, a_2, 32) == 0);
    TEST_ASSERT_TRUE(memcmp(b_1, b_2, 32) == 0);
}

void simple_protocol_correct(void)
{
    unsigned char key_client[32];
    unsigned char key_server[32];
    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    run_setup((unsigned char *)"password123", (unsigned char *)"name",
              (unsigned char *)"server", phi0_s, c);
    run_key_exchange((unsigned char *)"password123", (unsigned char *)"name",
                     (unsigned char *)"server", phi0_s, c, key_client, key_server);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(key_client, key_server, 32);
}

void logic_protocol_doesnt_produce_same_keys_with_same_credentials(void)
{
    unsigned char key_client_1[32];
    unsigned char key_server_1[32];

    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    run_setup((unsigned char *)"password123", (unsigned char *)"name",
              (unsigned char *)"server", phi0_s, c);

    run_key_exchange((unsigned char *)"password123", (unsigned char *)"name",
                     (unsigned char *)"server", phi0_s, c, key_client_1, key_server_1);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(key_client_1, key_server_1, 32);
    unsigned char key_client_2[32];
    unsigned char key_server_2[32];
    run_key_exchange((unsigned char *)"password123", (unsigned char *)"name",
                     (unsigned char *)"server", phi0_s, c, key_client_2, key_server_2);
    TEST_ASSERT_TRUE(memcmp(key_client_1, key_client_2, 32) != 0);
    TEST_ASSERT_TRUE(memcmp(key_server_1, key_server_2, 32) != 0);
}

void wrong_password_used(void)
{
    unsigned char key_client[32];
    unsigned char key_server[32];
    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    run_setup((unsigned char *)"password123", (unsigned char *)"name",
              (unsigned char *)"server", phi0_s, c);
    run_key_exchange((unsigned char *)"password1234", (unsigned char *)"name",
                     (unsigned char *)"server", phi0_s, c, key_client, key_server);
    TEST_ASSERT_TRUE(memcmp(key_client, key_server, 32) != 0);
}

void wrong_id_used(void)
{
    unsigned char key_client[32];
    unsigned char key_server[32];
    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    run_setup((unsigned char *)"password123", (unsigned char *)"name",
              (unsigned char *)"server", phi0_s, c);
    run_key_exchange((unsigned char *)"password1234", (unsigned char *)"name123",
                     (unsigned char *)"server", phi0_s, c, key_client, key_server);
    TEST_ASSERT_TRUE(memcmp(key_client, key_server, 32) != 0);
}

void wrong_server_used(void)
{
    unsigned char key_client[32];
    unsigned char key_server[32];
    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    run_setup((unsigned char *)"password123", (unsigned char *)"name",
              (unsigned char *)"server", phi0_s, c);
    run_key_exchange((unsigned char *)"password1234", (unsigned char *)"name",
                     (unsigned char *)"server123", phi0_s, c, key_client, key_server);
    TEST_ASSERT_TRUE(memcmp(key_client, key_server, 32) != 0);
}

void name_and_server_switched_around(void)
{
    unsigned char key_client[32];
    unsigned char key_server[32];
    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    run_setup((unsigned char *)"password123", (unsigned char *)"name",
              (unsigned char *)"server", phi0_s, c);
    run_key_exchange((unsigned char *)"password1234", (unsigned char *)"server",
                     (unsigned char *)"name", phi0_s, c, key_client, key_server);
    TEST_ASSERT_TRUE(memcmp(key_client, key_server, 32) != 0);
}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_a_and_b_generators);
    RUN_TEST(simple_protocol_correct);
    RUN_TEST(logic_protocol_doesnt_produce_same_keys_with_same_credentials);
    RUN_TEST(wrong_password_used);
    RUN_TEST(wrong_id_used);
    RUN_TEST(wrong_server_used);
    RUN_TEST(name_and_server_switched_around);
    return UNITY_END();
}
