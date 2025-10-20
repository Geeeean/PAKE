#include "utils.h"
#include "sodium.h"
#include "string.h"

// Maybe a better way to make group elements global and static but this should
// work for now
#define HASH_INPUT_A "pake_ristretto_a"
#define HASH_INPUT_B "pake_ristretto_b"

int sum(const int a, const int b)
{
    return a + b;
}

/***********************************************
 *  Generating static group elements a and b
 *  @param a   32 byte scalar
 *  @param b   32 byte scalar
 ***********************************************/
int generate_a_b_group_elements(unsigned char a[crypto_core_ristretto255_BYTES],
                                unsigned char b[crypto_core_ristretto255_BYTES]) {
    
    unsigned char buffer_a[crypto_hash_sha512_BYTES];
    unsigned char buffer_b[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(buffer_a, (const unsigned char*)HASH_INPUT_A, strlen(HASH_INPUT_A));
    crypto_hash_sha512(buffer_b, (const unsigned char*)HASH_INPUT_B, strlen(HASH_INPUT_B));

    // Right now the way is just to generate the group element from the output of
    // a hash function
    // Maybe there is a better way
    crypto_core_ristretto255_from_hash(a, buffer_a);
    crypto_core_ristretto255_from_hash(b, buffer_b);
    sodium_memzero(buffer_a, sizeof(buffer_a));
    sodium_memzero(buffer_b, sizeof(buffer_b));
    return 0;
}

/***********************************************
 *  PAKE Hash function for phi0 and phi1
 *  @param password   Pointer to password
 *  @param id_client  Pointer to the client's id
 *  @param id_server  Pointer to the Server's id
 *  @param output0    Output for phi0
 *  @param output1    Output for phi1
 ***********************************************/
int H_function(const unsigned char* password, const unsigned char* id_client, 
                const unsigned char* id_server, unsigned char output0[crypto_core_ristretto255_BYTES], 
                unsigned char output1[crypto_core_ristretto255_BYTES]) {
    
    if (!password || !id_client || !id_server) return -1;
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

/***********************************************
 *  Compute the u value for the client
 *  @param alpha   32 byte scalar
 *  @param a       Fixed group element a
 *  @param phi0    32 byte scalar from hash
 *  @param u       Output for group element
 ***********************************************/
int compute_u_value(const unsigned char alpha[crypto_core_ristretto255_SCALARBYTES],
                    const unsigned char a[crypto_core_ristretto255_BYTES],
                    const unsigned char phi0[crypto_core_ristretto255_SCALARBYTES], 
                    unsigned char u[crypto_core_ristretto255_BYTES]) {
    if (!alpha || !a || !phi0) return -1;

    unsigned char g_alpha[crypto_core_ristretto255_BYTES];
    crypto_scalarmult_ristretto255_base(g_alpha, alpha);

    unsigned char a_phi0[crypto_core_ristretto255_BYTES];

    // We have to check everytime for no warnings
    // to see if the first arg is the identity element
    if (crypto_scalarmult_ristretto255(a_phi0, phi0, a) != 0) return -1;
    crypto_core_ristretto255_add(u, g_alpha, a_phi0);
    sodium_memzero(g_alpha, sizeof(g_alpha));
    sodium_memzero(a_phi0, sizeof(a_phi0));
    return 0;
}

/***********************************************
 *  Compute w and d values for the client
 *  @param alpha   32 byte scalar
 *  @param b       Fixed group element b
 *  @param phi0    32 byte scalar from hash
 *  @param phi1    32 byte scalar from hash
 *  @param w       Output for group element
 *  @param d       Output for group element
 ***********************************************/
int compute_w_d_values_for_client(const unsigned char alpha[crypto_core_ristretto255_SCALARBYTES],
                          const unsigned char b[crypto_core_ristretto255_BYTES],
                          const unsigned char v[crypto_core_ristretto255_BYTES],
                          const unsigned char phi0[crypto_core_ristretto255_SCALARBYTES],
                          const unsigned char phi1[crypto_core_ristretto255_SCALARBYTES],
                          unsigned char w[crypto_core_ristretto255_BYTES],
                          unsigned char d[crypto_core_ristretto255_BYTES]) {
    if (!alpha || !b || !v || !phi0 || !phi1) return -1;
    
    unsigned char b_phi0[crypto_core_ristretto255_BYTES];
    if (crypto_scalarmult_ristretto255(b_phi0, phi0, b) != 0) {
        return -1;
    }
    unsigned char v_b_phi0[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_sub(v_b_phi0, v, b_phi0);

    if (crypto_scalarmult_ristretto255(w, alpha, v_b_phi0) != 0) return -1;
    if (crypto_scalarmult_ristretto255(d, phi1, v_b_phi0) != 0) return -1;
    sodium_memzero(b_phi0, sizeof(b_phi0));
    sodium_memzero(v_b_phi0, sizeof(v_b_phi0));
    return 0;
}

