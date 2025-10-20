#include "log.h"
#include "network.h"
#include "utils.h"

#include "sodium.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main()
{
    if (sodium_init() == -1) {
        return 1;
    }

    int result = 0;
    int socket_fd = nw_get_socket();

    /*** SOCKET ***/
    if (socket_fd < 0) {
        fprintf(stderr, "Error while creating the socket\n");
        result = 1;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address = nw_get_address();

    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Connection Failed");
        return 1;
    }

    for (int i = 0; i < 3; i++) {
        char *msg;
        asprintf(&msg, "Message %d", i);

        LOG_INFO("Sending %s to server", msg);
        send(socket_fd, msg, strlen(msg) + 1, 0);

        // char buffer[1024] = {0};
        // read(socket_fd, buffer, sizeof(buffer));
        // printf("msg from server: %s\n", buffer);

        free(msg);

        sleep(3);
    }

    char *msg = "END";
    send(socket_fd, msg, strlen(msg) + 1, 0);
    LOG_INFO("Sending %s to server for finishing comunication", msg);

    /*** CLIENT PAKE ***/
    goto cleanup; // to be removed -------------------------------

    // TEMP: Our way of getting the public and fixed group elements a,b
    // Maybe you have a better way Gianluca
    unsigned char a[crypto_core_ristretto255_BYTES];
    unsigned char b[crypto_core_ristretto255_BYTES];
    generate_a_b_group_elements(a, b);

    // TEMP: The client's password for this test and username
    // and the server's id
    const unsigned char *password = "pass123";
    const unsigned char *id_client = "jakobkjellberg02";
    const unsigned char *id_server = "dtu.dk";

    // (phi0, phi1) <- H(pi||id_client||id_server)
    unsigned char phi0[crypto_core_ristretto255_SCALARBYTES];
    unsigned char phi1[crypto_core_ristretto255_SCALARBYTES];
    H_function(password, id_client, id_server, phi0, phi1);

    // c <- g^(phi0)
    unsigned char c[crypto_core_ristretto255_BYTES];
    crypto_scalarmult_ristretto255_base(c, phi1);

    // Sends phi0 and c to the server
    // SERVER STUFF GIANLUCA HELP
    send(socket_fd, phi0, sizeof(phi0), 0);
    send(socket_fd, c, sizeof(c), 0);

    // alpha <- Z_p
    unsigned char alpha[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(alpha);
    // u = g^(alpha)a^(phi0) 
    unsigned char u[crypto_core_ristretto255_BYTES];
    compute_u_value(alpha, a, phi0, u);

    // SERVER STUFF GIANLUCA HELP
    send(socket_fd, u, sizeof(u), 0);

    // Receiving v 
    unsigned char v[crypto_core_ristretto255_BYTES];
    // Need a way to recieve v value from server
    // Is this the correct way?
    // SERVER STUFF GIANLUCA HELP
    recv(socket_fd, v, sizeof(v), 0);

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
    close(socket_fd);
    return result;
}
