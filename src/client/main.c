#include "log.h"
#include "network.h"
#include "protocol.h"
#include "utils.h"

#include "sodium.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (sodium_init() == -1) {
        LOG_ERROR("Unable to initialize sodium");
        return 1;
    }

    if (argc != 2) {
        LOG_ERROR("Client requires an id");
        return 2;
    }

    int result = 0;
    int socket = nw_get_socket();

    /*** SOCKET ***/
    if (socket < 0) {
        LOG_ERROR("While getting the socket");
        result = 3;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address = nw_get_address();
    if (connect(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        LOG_ERROR("Connection failed");
        result = 4;
        goto cleanup;
    }

    // TEMP: The client's password for this test and username
    // and the server's id
    const unsigned char *password = "pass123";
    const unsigned char *id_client = argv[1];
    const unsigned char *id_server = "dtu.dk";

    /*** CLIENT HELLO ***/
    Packet hello_packet = pt_initialize_packet(MSG_HELLO);
    hello_packet.payload =
        pt_build_hello_payload((const char *)id_client, &hello_packet.header.length);
    if (nw_send_packet(socket, &hello_packet) < 0) {
        LOG_ERROR("While sending hello packet");
        result = 5;
        goto cleanup;
    }
    pt_free_packet_payload(&hello_packet);

    /*** CLIENT PAKE ***/
    // TEMP: Our way of getting the public and fixed group elements a,b
    // Maybe you have a better way Gianluca
    unsigned char a[crypto_core_ristretto255_BYTES];
    unsigned char b[crypto_core_ristretto255_BYTES];
    generate_a_b_group_elements(a, b);

    // (phi0, phi1) <- H(pi||id_client||id_server)
    unsigned char phi0[crypto_core_ristretto255_SCALARBYTES];
    unsigned char phi1[crypto_core_ristretto255_SCALARBYTES];
    H_function(password, id_client, id_server, phi0, phi1);

    // c <- g^(phi0)
    unsigned char c[crypto_core_ristretto255_BYTES];
    crypto_scalarmult_ristretto255_base(c, phi1);

    // Sends phi0 and c to the server
    Packet setup_packet = pt_initialize_packet(MSG_SETUP);
    setup_packet.payload = pt_build_setup_payload(phi0, sizeof(phi0), c, sizeof(c),
                                                  &setup_packet.header.length);
    if (nw_send_packet(socket, &setup_packet) < 0) {
        LOG_ERROR("While sending setup packet");
        result = 6;
        goto cleanup;
    }
    pt_free_packet_payload(&setup_packet);

    // alpha <- Z_p
    unsigned char alpha[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(alpha);
    // u = g^(alpha)a^(phi0)
    unsigned char u[crypto_core_ristretto255_BYTES];
    compute_u_value(alpha, a, phi0, u);

    // Sends u to the server
    Packet u_packet = pt_initialize_packet(MSG_U);
    u_packet.payload = pt_build_u_payload(u, sizeof(u), &u_packet.header.length);
    if (nw_send_packet(socket, &u_packet) < 0) {
        LOG_ERROR("While sending u packet");
        result = 7;
        goto cleanup;
    }
    pt_free_packet_payload(&u_packet);

    // Receiving v
    unsigned char v[crypto_core_ristretto255_BYTES];

    Packet v_packet;
    if (nw_receive_packet(socket, &v_packet) < 0) {
        LOG_ERROR("While receiving v packet");
        result = 8;
        goto cleanup;
    }

    if (v_packet.header.type != MSG_V ||
        v_packet.header.length != crypto_core_ristretto255_BYTES) {
        LOG_ERROR("v packet is not valid");
        result = 9;
        goto cleanup;
    }

    memcpy(v, v_packet.payload, crypto_core_ristretto255_BYTES);
    pt_free_packet_payload(&v_packet);

    // w = (v/b^(phi0))^(alpha)
    // d = (v/b^(phi0))^(phi1)
    unsigned char w[crypto_core_ristretto255_BYTES];
    unsigned char d[crypto_core_ristretto255_BYTES];
    compute_w_d_values_for_client(alpha, b, v, phi0, phi1, w, d);

    // k = H'(phi0||id_client||id_server||u||v||w||d)
    unsigned char k[32];
    H_prime(phi0, sizeof(phi0), id_client, strlen((const char *)id_client), id_server,
            strlen((const char *)id_server), u, sizeof(u), v, sizeof(v), w, sizeof(w), d,
            sizeof(d), k);

cleanup:
    close(socket);
    return result;
}
