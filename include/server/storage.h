#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>

typedef enum {
    VR_SUCCESS,
    VR_FAILURE,
    VR_NOT_FOUND,
    VR_NOT_VALID,
} VerifyResult;

int storage_init(const char *server_id);
int storage_deinit();
int storage_store_secret(const char *client_id, unsigned char *phi0,
                         uint16_t phi0_len_out, unsigned char *c, uint16_t c_len_out);
VerifyResult storage_verify_secret(const char *client_id, unsigned char *phi0,
                                   uint16_t phi0_len_out, unsigned char *c,
                                   uint16_t c_len_out);

#endif
