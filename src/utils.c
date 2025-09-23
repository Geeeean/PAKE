#include "utils.h"
#include "sodium.h"
#include "string.h"

int sum(const int a, const int b)
{
    return a + b;
}


int H_function(char* password, char* id_client, char* id_server, unsigned char output0[32], unsigned char output1[32]) {
    unsigned char hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);

    crypto_hash_sha512_update(&state, password, strlen(password));
    crypto_hash_sha512_update(&state, id_client, strlen(id_client));
    crypto_hash_sha512_update(&state, id_server, strlen(id_server));

    crypto_hash_sha512_final(&state, hash);
    
    // To do - Need converting part
    memcpy(output0, hash, 32);
    memcpy(output1, hash + 32, 32);
    return 0;
}

int H_prime_function(const input, const len, unsigned char out[32]) {
    unsigned char hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash, input, len);
    memcpy(out, hash, 32);
    return 0;
}
