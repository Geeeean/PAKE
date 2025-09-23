#include "stdio.h"
#include "utils.h"
#include "sodium.h"

int main()
{
    int res = sum(1, 2);
    if (sodium_init < 0) {
        printf("INSTALL LIBSODIUM!");
    }
    return 0;
}
