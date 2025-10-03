#include "utils.h"
#include "sodium.h"
#include "string.h"

int sum(const int a, const int b)
{
    return a + b;
}


int H_function(const unsigned char* password, const unsigned char* id_client, 
                const unsigned char* id_server, unsigned char output0[crypto_core_ristretto255_BYTES], 
                unsigned char output1[crypto_core_ristretto255_BYTES]) {
    
    // https://libsodium.gitbook.io/doc/advanced/sha-2_hash_function
    unsigned char hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);

    crypto_hash_sha512_update(&state, password, strlen(password));
    crypto_hash_sha512_update(&state, id_client, strlen(id_client));
    crypto_hash_sha512_update(&state, id_server, strlen(id_server));

    crypto_hash_sha512_final(&state, hash);
    
    // 512 bits to two bitstrings of length 256 bits + padding
    unsigned char buffer0[crypto_hash_sha512_BYTES] = {0};
    memcpy(buffer0, hash, crypto_core_ristretto255_BYTES);
    unsigned char buffer1[crypto_hash_sha512_BYTES] = {0};
    memcpy(buffer0, hash + crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
    sodium_memzero(hash, sizeof(hash));

    // https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto
    // I have to check if this is the correct way
    crypto_core_ristretto255_scalar_reduce(output0, buffer0);
    sodium_memzero(buffer0, sizeof(buffer0));
    crypto_core_ristretto255_scalar_reduce(output1, buffer1);
    sodium_memzero(buffer1, sizeof(buffer1));

    return 0;
}

