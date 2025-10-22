#include "protocol.h"

#include <stdlib.h>
#include <string.h>

static Header pt_build_header(MessageType msg_type)
{
    return (Header){.type = msg_type, .length = 0};
}

Packet pt_initialize_packet(MessageType msg_type)
{
    return (Packet){.header = pt_build_header(msg_type), .payload = NULL};
}

void pt_free_packet_payload(Packet *packet)
{
    free(packet->payload);
}

uint8_t *pt_build_hello_payload(const char *id, uint16_t *length)
{
    *length = strlen(id);

    uint8_t *buffer = malloc(sizeof(*length));
    memcpy(buffer, id, *length);
    return buffer;
}

uint8_t *pt_build_setup_payload(const unsigned char *phi0, const uint16_t phi0_len,
                                const unsigned char *c, const uint16_t c_len,
                                uint16_t *length)
{
    *length = sizeof(phi0_len) + phi0_len + c_len;

    uint8_t *buffer = malloc(sizeof(*length));
    memcpy(buffer, &phi0_len, sizeof(phi0_len));
    memcpy(buffer + sizeof(phi0_len), phi0, phi0_len);
    memcpy(buffer + sizeof(phi0_len) + phi0_len, c, c_len);
    return buffer;
}

uint8_t *pt_build_u_payload(const unsigned char *u, const uint16_t u_len,
                            uint16_t *length)
{
    *length = u_len;

    uint8_t *buffer = malloc(sizeof(*length));
    memcpy(buffer, u, u_len);
    return buffer;
}
