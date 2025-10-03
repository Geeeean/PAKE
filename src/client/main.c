#include <stdio.h>
#include "sodium.h"
#include "utils.h"

int main()
{
    printf("Hello from client\n");
    
    if (sodium_init() == -1) {
        return 1;
    }

    const unsigned char* password = "pass123";
    const unsigned char* id_client = "jakobkjellberg02";
    const unsigned char* id_server = "dtu.dk";
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
}
