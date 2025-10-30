#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

typedef enum {
    MSG_HELLO, // exchanging id at the beginning of the comunication
               // [ length (2B) ][ type (1B) ] | [ id (lengthB) ]
               //
    MSG_SETUP, // During the setup phase, the client computes (φ0, φ1) ← H(π ‖ idC ‖ idS)
               //  where π is the password. It sets c ← gφ1 and then sends φ0, c to S
               // [ length (2B) ][ type (1B) ] | [ len1 (2B) ][ phi0 (len1B) ][ c ({length
               // - len1 - 2B}B) ]
               //
    MSG_U,     // C samples α ← Zp uniformly at random, computes u = gαaφ0 and
               //  sends u to S.
               // [ length (2B) ][ type (1B) ] | [ u (lengthB) ]
               //
    MSG_V,     // S samples β ← Zp uniformly at random, computes v = gβ bφ0 and
               //  sends v to C.
               // [ length (2B) ][ type (1B) ] | [ v (lengthB) ]
               //
    MSG_CLOSE, // for closing connection (in case of error)
} MessageType;

#pragma pack(push, 1)
typedef struct {
    uint16_t length;
    uint8_t type; // MessageType
} Header;
#pragma pack(pop)

typedef struct {
    Header header;
    void *payload;
} Packet;

// Header pt_build_header(MessageType msg_type);
Packet pt_initialize_packet(MessageType msg_type);
void pt_free_packet_payload(Packet *packet);

uint8_t *pt_build_hello_payload(const char *id, uint16_t *length);
uint8_t *pt_build_setup_payload(const unsigned char *phi0, const uint16_t phi0_len,
                                const unsigned char *c, const uint16_t c_len,
                                uint16_t *length);
uint8_t *pt_build_u_payload(const unsigned char *u, const uint16_t u_len,
                            uint16_t *length);
uint8_t *pt_build_v_payload(const unsigned char *v, const uint16_t v_len,
                            uint16_t *length);

int pt_parse_setup_packet(Packet *setup_packet, unsigned char **phi0,
                          uint16_t *phi0_len_out, unsigned char **c, uint16_t *c_len_out);

#endif
