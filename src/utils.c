#include "utils.h"
#include "sodium.h"
#include "string.h"

int sum(const int a, const int b)
{
    return a + b;
}


int H_function(const unsigned char* password, const unsigned char* id_client, 
                const unsigned char* id_server, unsigned char output0[32], 
                unsigned char output1[32]) {
    
    // https://libsodium.gitbook.io/doc/advanced/sha-2_hash_function
    unsigned char hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);

    crypto_hash_sha512_update(&state, password, strlen(password));
    crypto_hash_sha512_update(&state, id_client, strlen(id_client));
    crypto_hash_sha512_update(&state, id_server, strlen(id_server));

    crypto_hash_sha512_final(&state, hash);
    
    // https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto
    crypto_core_ristretto255_scalar_reduce(output0, hash);
    crypto_core_ristretto255_scalar_reduce(output1, hash + 32);

    // https://libsodium.gitbook.io/doc/memory_management (PARANOIA)
    sodium_memzero(hash, sizeof(hash));
    return 0;
}

// int H_prime_function(const input, const len, unsigned char out[32]) {
//     unsigned char hash[crypto_hash_sha512_BYTES];

//     crypto_hash_sha512(hash, input, len);
//     memcpy(out, hash, 32);

//     sodium_memzero(hash, sizeof(hash));
//     return 0;
// }
