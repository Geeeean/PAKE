#include "client/client.h"
#include "log.h"
#include "network.h"
#include "server/server.h"
#include "server/storage.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <unity.h>
#include <utils.h>

#define STORAGE_PATH "./test_storage"

void setUp(void)
{
    int result = sodium_init();
    if (result < 0) {
        LOG_ERROR("While sodiume init, aborting...");
        exit(FAILURE);
    }
    system("rm -rf " STORAGE_PATH);
    mkdir(STORAGE_PATH, 0755);
    setenv("STORAGE_PATH", STORAGE_PATH, 1);
}

void tearDown(void)
{
    system("rm -rf " STORAGE_PATH);
}

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

void logic_test_a_and_b_generators(void)
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

void logic_simple_protocol_correct(void)
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

void logic_wrong_password_used(void)
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

void logic_wrong_id_used(void)
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

void logic_wrong_server_used(void)
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

void logic_name_and_server_switched_around(void)
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

void storage_init_success(void)
{
    int result = storage_init("server123");
    TEST_ASSERT_EQUAL_INT(SUCCESS, result);
}

void storage_store_and_verify_secret(void)
{
    storage_init("server123");
    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    run_setup((unsigned char *)"password123", (unsigned char *)"name",
              (unsigned char *)"server123", phi0_s, c);
    int result =
        storage_store_secret((char *)"name", phi0_s, sizeof(phi0_s), c, sizeof(c));
    TEST_ASSERT_EQUAL_INT(SUCCESS, result);

    VerifyResult verify_result =
        storage_verify_secret("name", phi0_s, sizeof(phi0_s), c, sizeof(c));
    TEST_ASSERT_EQUAL_INT(VR_SUCCESS, verify_result);
}

void storage_verify_secret_not_found(void)
{
    storage_init("server123");
    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_random(phi0_s);
    unsigned char c[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_random(c);
    VerifyResult verify_result =
        storage_verify_secret("jens", phi0_s, sizeof(phi0_s), c, sizeof(c));
    TEST_ASSERT_EQUAL_INT(VR_NOT_FOUND, verify_result);
}

void storage_store_and_verify_secret_wrong_credentials(void)
{
    storage_init("server123");
    unsigned char phi0_s[crypto_core_ristretto255_SCALARBYTES];
    unsigned char c[crypto_core_ristretto255_BYTES];
    run_setup((unsigned char *)"password123", (unsigned char *)"name",
              (unsigned char *)"server123", phi0_s, c);
    int result =
        storage_store_secret((char *)"name", phi0_s, sizeof(phi0_s), c, sizeof(c));
    TEST_ASSERT_EQUAL_INT(SUCCESS, result);

    unsigned char phi0_wrong[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_random(phi0_wrong);
    unsigned char c_wrong[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_random(c_wrong);

    VerifyResult verify_result = storage_verify_secret(
        "name", phi0_wrong, sizeof(phi0_wrong), c_wrong, sizeof(c_wrong));
    TEST_ASSERT_EQUAL_INT(VR_NOT_VALID, verify_result);
}

void integration_init(void)
{
    char *server_id = "server_test";
    char *client_id = "client_test";
    char *client_password = "password_test";

    /*** SERVER SOCKET CONFIG ***/
    int listen_socket = nw_get_socket(UNIX);
    TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(SUCCESS, listen_socket, "listen socket get");

    struct sockaddr_un server_address;
    nw_get_address(UNIX, (struct sockaddr *)&server_address, server_id);

    TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(
        0,
        bind(listen_socket, (struct sockaddr *)&server_address, sizeof(server_address)),
        "bind");

    TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(SUCCESS, listen(listen_socket, 3), "listen");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, storage_init(server_id), "storage init");

    /*** CLIENT SOCKET CONFIG ***/
    int client_socket = nw_get_socket(UNIX);
    TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(SUCCESS, client_socket,
                                             "client socket get fail");
    TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(SUCCESS,
                                             connect(client_socket,
                                                     (struct sockaddr *)&server_address,
                                                     sizeof(server_address)),
                                             "client socket connect");

    /*** SERVER CONNECTION ACCEPT ***/
    struct sockaddr client_address;
    socklen_t socklen = sizeof(client_address);
    int new_socket = accept(listen_socket, (struct sockaddr *)&client_address, &socklen);
    TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(SUCCESS, new_socket, "accept");

    Client *client = client_init(client_id, client_password, client_socket);
    TEST_ASSERT_TRUE_MESSAGE(client, "client init");

    Server *server = server_init(server_id, new_socket);
    TEST_ASSERT_TRUE_MESSAGE(server, "server init");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, storage_deinit(), "storage deinit");
}

int socket_setup(struct sockaddr_un *server_address, char *server_id, int *listen_socket,
                 int *client_socket)
{
    close(*listen_socket);

    /*** SERVER SOCKET CONFIG ***/
    *listen_socket = nw_get_socket(UNIX);
    if (*listen_socket < 0) {
        return FAILURE;
    }

    nw_get_address(UNIX, (struct sockaddr *)server_address, server_id);
    if (bind(*listen_socket, (struct sockaddr *)server_address, sizeof(*server_address)) <
        0) {
        return FAILURE;
    }

    if (listen(*listen_socket, 3) < 0) {
        return FAILURE;
    }

    if (storage_init(server_id)) {
        return FAILURE;
    }

    /*** CLIENT SOCKET CONFIG ***/
    *client_socket = nw_get_socket(UNIX);
    if (*client_socket < 0) {
        return FAILURE;
    }

    return SUCCESS;
}

int socket_connect(struct sockaddr_un server_address, char *server_id, int *listen_socket,
                   int *client_socket, int *new_socket)
{
    if (connect(*client_socket, (struct sockaddr *)&server_address,
                sizeof(server_address)) < 0) {
        return 2;
    }

    /*** SERVER CONNECTION ACCEPT ***/
    struct sockaddr client_address;
    socklen_t socklen = sizeof(client_address);
    *new_socket = accept(*listen_socket, (struct sockaddr *)&client_address, &socklen);
    if (*new_socket < 0) {
        return FAILURE;
    }

    return SUCCESS;
}

void integration_hello_handshake(void)
{
    char *server_id = "server_test";
    char *client_id = "client_test";
    char *client_password = "password_test";

    struct sockaddr_un server_address;
    int listen_socket, client_socket, new_socket;
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        SUCCESS, socket_setup(&server_address, server_id, &listen_socket, &client_socket),
        "socket setup");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS,
                                  socket_connect(server_address, server_id,
                                                 &listen_socket, &client_socket,
                                                 &new_socket),
                                  "socket connect");

    Client *client = client_init(client_id, client_password, client_socket);
    TEST_ASSERT_TRUE_MESSAGE(client, "client init");

    Server *server = server_init(server_id, new_socket);
    TEST_ASSERT_TRUE_MESSAGE(server, "server init");

    /*** CLIENT HELLO SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, client_send_hello_packet(client), "client hello");

    /** SERVER HELLO RECEIVE + SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, server_receive_hello_packet(server),
                              "server hello receive");
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, server_send_hello_packet(server), "client hello");

    /*** CLIENT HELLO RECEIVE ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, client_receive_hello_packet(client),
                              "server hello receive");

    server_close(&server);
    TEST_ASSERT_TRUE_MESSAGE(!server, "server close");

    client_close(&client);
    TEST_ASSERT_TRUE_MESSAGE(!client, "client close");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, storage_deinit(), "storage deinit");
}

void integration_setup(void)
{
    char *server_id = "server_test";
    char *client_id = "client_test";
    char *client_password = "password_test";

    struct sockaddr_un server_address;
    int listen_socket, client_socket, new_socket;
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        SUCCESS, socket_setup(&server_address, server_id, &listen_socket, &client_socket),
        "socket setup");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS,
                                  socket_connect(server_address, server_id,
                                                 &listen_socket, &client_socket,
                                                 &new_socket),
                                  "socket connect");

    Client *client = client_init(client_id, client_password, client_socket);
    TEST_ASSERT_TRUE_MESSAGE(client, "client init");

    Server *server = server_init(server_id, new_socket);
    TEST_ASSERT_TRUE_MESSAGE(server, "server init");

    /*** CLIENT HELLO SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, client_send_hello_packet(client), "client hello");

    /** SERVER HELLO RECEIVE + SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, server_receive_hello_packet(server),
                              "server hello receive");
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, server_send_hello_packet(server), "client hello");

    /*** CLIENT HELLO RECEIVE ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, client_receive_hello_packet(client),
                              "server hello receive");

    /*** CLIENT PAKE ***/
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_group_elements(client),
                                  "client compute group elements");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_phi(client),
                                  "client compute phi");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_c(client), "client compute c");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_send_setup_packet(client),
                                  "client send setup packet");

    TEST_ASSERT_EQUAL_INT_MESSAGE(RR_SUCCESS, server_receive_setup_packet(server),
                                  "server receive setup packet");

    VerifyResult verify_result = server_verify_secret(server);
    TEST_ASSERT_TRUE_MESSAGE(verify_result == VR_NOT_FOUND, "secret");

    server_close(&server);
    TEST_ASSERT_TRUE_MESSAGE(!server, "server close");

    client_close(&client);
    TEST_ASSERT_TRUE_MESSAGE(!client, "client close");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, storage_deinit(), "storage deinit");
}

void integration_setup_wrong_password(void)
{
    char *server_id = "server_test";
    char *client_id = "client_test";
    char *client_password = "password_test";

    struct sockaddr_un server_address;
    int listen_socket, client_socket, new_socket;
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        SUCCESS, socket_setup(&server_address, server_id, &listen_socket, &client_socket),
        "socket setup");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS,
                                  socket_connect(server_address, server_id,
                                                 &listen_socket, &client_socket,
                                                 &new_socket),
                                  "socket connect");

    Client *client = client_init(client_id, client_password, client_socket);
    TEST_ASSERT_TRUE_MESSAGE(client, "client init");

    Server *server = server_init(server_id, new_socket);
    TEST_ASSERT_TRUE_MESSAGE(server, "server init");

    /*** CLIENT HELLO SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, client_send_hello_packet(client), "client hello");

    /** SERVER HELLO RECEIVE + SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, server_receive_hello_packet(server),
                              "server hello receive");
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, server_send_hello_packet(server), "client hello");

    /*** CLIENT HELLO RECEIVE ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, client_receive_hello_packet(client),
                              "server hello receive");

    /*** CLIENT PAKE ***/
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_group_elements(client),
                                  "client compute group elements");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_phi(client),
                                  "client compute phi");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_c(client), "client compute c");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_send_setup_packet(client),
                                  "client send setup packet");
    TEST_ASSERT_EQUAL_INT_MESSAGE(RR_SUCCESS, server_receive_setup_packet(server),
                                  "server receive setup packet");

    VerifyResult verify_result = server_verify_secret(server);
    TEST_ASSERT_TRUE_MESSAGE(verify_result == VR_NOT_FOUND, "secret");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, server_store_secret(server), "store secret");

    server_close(&server);
    TEST_ASSERT_TRUE_MESSAGE(!server, "server close");

    client_close(&client);
    TEST_ASSERT_TRUE_MESSAGE(!client, "client close");

    /*** SAME SERVER, SAME CLIENT, WRONG PASSWORD ***/
    char *client_wrong_password = "wrong_password_test";

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        SUCCESS, socket_setup(&server_address, server_id, &listen_socket, &client_socket),
        "socket setup");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS,
                                  socket_connect(server_address, server_id,
                                                 &listen_socket, &client_socket,
                                                 &new_socket),
                                  "socket connect 2");

    client = client_init(client_id, client_wrong_password, client_socket);
    TEST_ASSERT_TRUE_MESSAGE(client, "client init 2");

    server = server_init(server_id, new_socket);
    TEST_ASSERT_TRUE_MESSAGE(server, "server init 2");

    /*** CLIENT HELLO SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, client_send_hello_packet(client),
                              "client hello 2");

    /** SERVER HELLO RECEIVE + SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, server_receive_hello_packet(server),
                              "server hello receive 2");
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, server_send_hello_packet(server),
                              "client hello 2");

    /*** CLIENT HELLO RECEIVE ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, client_receive_hello_packet(client),
                              "server hello receive 2");

    /*** CLIENT PAKE ***/
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_group_elements(client),
                                  "client compute group elements 2");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_phi(client),
                                  "client compute phi 2");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_c(client),
                                  "client compute c 2");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_send_setup_packet(client),
                                  "client send setup packet 2");

    TEST_ASSERT_EQUAL_INT_MESSAGE(RR_SUCCESS, server_receive_setup_packet(server),
                                  "server receive setup packet 2");

    verify_result = server_verify_secret(server);
    TEST_ASSERT_TRUE_MESSAGE(verify_result == VR_NOT_VALID, "secret 2");

    server_close(&server);
    TEST_ASSERT_TRUE_MESSAGE(!server, "server close");

    client_close(&client);
    TEST_ASSERT_TRUE_MESSAGE(!client, "client close");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, storage_deinit(), "storage deinit");
}

void integration_setup_correct_password(void)
{
    char *server_id = "server_test";
    char *client_id = "client_test";
    char *client_password = "password_test";

    struct sockaddr_un server_address;
    int listen_socket, client_socket, new_socket;
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        SUCCESS, socket_setup(&server_address, server_id, &listen_socket, &client_socket),
        "socket setup");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS,
                                  socket_connect(server_address, server_id,
                                                 &listen_socket, &client_socket,
                                                 &new_socket),
                                  "socket connect");

    Client *client = client_init(client_id, client_password, client_socket);
    TEST_ASSERT_TRUE_MESSAGE(client, "client init");

    Server *server = server_init(server_id, new_socket);
    TEST_ASSERT_TRUE_MESSAGE(server, "server init");

    /*** CLIENT HELLO SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, client_send_hello_packet(client), "client hello");

    /** SERVER HELLO RECEIVE + SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, server_receive_hello_packet(server),
                              "server hello receive");
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, server_send_hello_packet(server), "client hello");

    /*** CLIENT HELLO RECEIVE ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, client_receive_hello_packet(client),
                              "server hello receive");

    /*** CLIENT PAKE ***/
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_group_elements(client),
                                  "client compute group elements");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_phi(client),
                                  "client compute phi");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_c(client), "client compute c");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_send_setup_packet(client),
                                  "client send setup packet");
    TEST_ASSERT_EQUAL_INT_MESSAGE(RR_SUCCESS, server_receive_setup_packet(server),
                                  "server receive setup packet");

    VerifyResult verify_result = server_verify_secret(server);
    TEST_ASSERT_TRUE_MESSAGE(verify_result == VR_NOT_FOUND, "secret");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, server_store_secret(server), "store secret");

    server_close(&server);
    TEST_ASSERT_TRUE_MESSAGE(!server, "server close");

    client_close(&client);
    TEST_ASSERT_TRUE_MESSAGE(!client, "client close");

    /*** SAME SERVER, SAME CLIENT, SAME PASSWORD ***/
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        SUCCESS, socket_setup(&server_address, server_id, &listen_socket, &client_socket),
        "socket setup");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS,
                                  socket_connect(server_address, server_id,
                                                 &listen_socket, &client_socket,
                                                 &new_socket),
                                  "socket connect 2");

    client = client_init(client_id, client_password, client_socket);
    TEST_ASSERT_TRUE_MESSAGE(client, "client init 2");

    server = server_init(server_id, new_socket);
    TEST_ASSERT_TRUE_MESSAGE(server, "server init 2");

    /*** CLIENT HELLO SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, client_send_hello_packet(client),
                              "client hello 2");

    /** SERVER HELLO RECEIVE + SEND ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, server_receive_hello_packet(server),
                              "server hello receive 2");
    TEST_ASSERT_EQUAL_MESSAGE(SUCCESS, server_send_hello_packet(server),
                              "client hello 2");

    /*** CLIENT HELLO RECEIVE ***/
    TEST_ASSERT_EQUAL_MESSAGE(RR_SUCCESS, client_receive_hello_packet(client),
                              "server hello receive 2");

    /*** CLIENT PAKE ***/
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_group_elements(client),
                                  "client compute group elements 2");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_phi(client),
                                  "client compute phi 2");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_compute_c(client),
                                  "client compute c 2");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, client_send_setup_packet(client),
                                  "client send setup packet 2");

    TEST_ASSERT_EQUAL_INT_MESSAGE(RR_SUCCESS, server_receive_setup_packet(server),
                                  "server receive setup packet 2");

    verify_result = server_verify_secret(server);
    TEST_ASSERT_TRUE_MESSAGE(verify_result == VR_SUCCESS, "secret 2");

    server_close(&server);
    TEST_ASSERT_TRUE_MESSAGE(!server, "server close");

    client_close(&client);
    TEST_ASSERT_TRUE_MESSAGE(!client, "client close");

    TEST_ASSERT_EQUAL_INT_MESSAGE(SUCCESS, storage_deinit(), "storage deinit");
}

int main()
{
    UNITY_BEGIN();
    // Util test
    RUN_TEST(logic_test_a_and_b_generators);

    // Protocol (business logic)
    RUN_TEST(logic_simple_protocol_correct);
    RUN_TEST(logic_protocol_doesnt_produce_same_keys_with_same_credentials);
    RUN_TEST(logic_wrong_password_used);
    RUN_TEST(logic_wrong_id_used);
    RUN_TEST(logic_wrong_server_used);
    RUN_TEST(logic_name_and_server_switched_around);

    // Storage
    RUN_TEST(storage_init_success);
    RUN_TEST(storage_store_and_verify_secret);
    RUN_TEST(storage_verify_secret_not_found);
    RUN_TEST(storage_store_and_verify_secret_wrong_credentials);

    // Integration
    RUN_TEST(integration_init);
    RUN_TEST(integration_hello_handshake);
    RUN_TEST(integration_setup);
    RUN_TEST(integration_setup_wrong_password);
    RUN_TEST(integration_setup_correct_password);

    return UNITY_END();
}
