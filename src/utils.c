#include "utils.h"
#include "sodium.h"
#include "string.h"

int sum(const int a, const int b)
{
    return a + b;
}

int setup_keys(char* password, char* id_client, char* id_server) {
    size_t total_length = strlen(password) + strlen(id_client) + strlen(id_server);
    unsigned char* buffer = malloc(total_length);

    // Ugly code, will maybe us strcat but idk
    memcpy(buffer, password, strlen(password));
    memcpy(buffer + strlen(password), id_client, strlen(id_client));
    memcpy(buffer + strlen(password) + strlen(id_client), id_server, strlen(id_server));
    
    unsigned char phi1[32];
    unsigned char phi2[32];
    H_function(buffer, total_length, phi1, phi2);
    return 0;
}

int H_function(unsigned char* input, size_t len, unsigned char output0[32], unsigned char output1[32]) {
    unsigned char hash[64];   
    crypto_hash_sha512(hash, input, len);
    
    // To do - Need converting part
    memcpy(output0, hash, 32);
    memcpy(output1, hash + 32, 32);
    return 0;
}

int H_prime_function(const input, const len, unsigned char out[32]) {
    unsigned char hash[64];
    crypto_hash_sha512(hash, input, len);
    memcpy(out, hash, 32);
    return 0;
}
