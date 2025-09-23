#include "utils.h"
#include "sodium.h"

int sum(const int a, const int b)
{
    return a + b;
}

int H_function(const* input, const len, unsigned char phi0[32], unsigned char phi1[32]) {
    unsigned char hash[64];   
    crypto_hash_sha512(hash, input, len);

    // Need splitting

}

int H_prime_function(const input, const len, unsigned char out[32]) {
    unsigned char hash[64];
    crypto_hash_sha512(hash, input, len);
    memcpy(out, hash, 32);
    return 0;
}
