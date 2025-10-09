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

    char *msg = "Hello from client!";
    send(socket_fd, msg, strlen(msg), 0);

    char buffer[1024] = {0};
    read(socket_fd, buffer, sizeof(buffer) - 1);
    printf("msg from server: %s\n", buffer);

    const unsigned char *password = "pass123";
    const unsigned char *id_client = "jakobkjellberg02";
    const unsigned char *id_server = "dtu.dk";
    unsigned char phi0[crypto_core_ristretto255_SCALARBYTES];
    unsigned char phi1[crypto_core_ristretto255_SCALARBYTES];

    H_function(password, id_client, id_server, phi0, phi1);
    printf("phi0: ");
    for (size_t i = 0; i < sizeof(phi0); i++) {
        printf("%02x", phi0[i]);
    }
    printf("\n");
    printf("phi1: ");
    for (size_t i = 0; i < sizeof(phi1); i++) {
        printf("%02x", phi1[i]);
    }
    printf("\n");

    unsigned char k[32];
    unsigned char u[crypto_core_ristretto255_BYTES];
    unsigned char v[crypto_core_ristretto255_BYTES];
    unsigned char w[crypto_core_ristretto255_BYTES];
    unsigned char d[crypto_core_ristretto255_SCALARBYTES];

    H_prime(phi0, sizeof(phi0), id_client, strlen((const char *)id_client), id_server,
            strlen((const char *)id_server), u, sizeof(u), v, sizeof(v), w, sizeof(w), d,
            sizeof(d), k);

    printf("k (H'): ");
    for (size_t i = 0; i < sizeof(k); i++)
        printf("%02x", k[i]);
    printf("\n");

cleanup:
    close(socket_fd);
    return result;
}
