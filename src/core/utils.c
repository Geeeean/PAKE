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
    memcpy(buffer1, hash + crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
    sodium_memzero(hash, sizeof(hash));

    // https://libsodium.net/api/LibSodium.CryptoRistretto.html#LibSodium_CryptoRistretto_ReduceScalar_System_ReadOnlySpan_System_Byte__System_Span_System_Byte__
    // I have to check if this is the correct way
    crypto_core_ristretto255_scalar_reduce(output0, buffer0);
    sodium_memzero(buffer0, sizeof(buffer0));
    crypto_core_ristretto255_scalar_reduce(output1, buffer1);
    sodium_memzero(buffer1, sizeof(buffer1));

    return 0;
}


int H_prime(const unsigned char* phi0, size_t phi0_len,
            const unsigned char* id_client, size_t id_client_len,
            const unsigned char* id_server, size_t id_server_len,
            const unsigned char* u, size_t u_len,
            const unsigned char* v, size_t v_len,
            const unsigned char* w, size_t w_len,
            const unsigned char* d, size_t d_len,
            unsigned char output[32])
{
    if (output == NULL) return -1;

    crypto_hash_sha512_state state;
    unsigned char hash[crypto_hash_sha512_BYTES];

    crypto_hash_sha512_init(&state);

    if (phi0 != NULL && phi0_len > 0)
        crypto_hash_sha512_update(&state, phi0, phi0_len);

    if (id_client != NULL && id_client_len > 0)
        crypto_hash_sha512_update(&state, id_client, id_client_len);

    if (id_server != NULL && id_server_len > 0)
        crypto_hash_sha512_update(&state, id_server, id_server_len);

    if (u != NULL && u_len > 0)
        crypto_hash_sha512_update(&state, u, u_len);

    if (v != NULL && v_len > 0)
        crypto_hash_sha512_update(&state, v, v_len);

    if (w != NULL && w_len > 0)
        crypto_hash_sha512_update(&state, w, w_len);

    if (d != NULL && d_len > 0)
        crypto_hash_sha512_update(&state, d, d_len);

    crypto_hash_sha512_final(&state, hash);

    memcpy(output, hash, 32);

    sodium_memzero(hash, sizeof(hash));
    return 0;
}

