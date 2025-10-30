#include "protocol.h"

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

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
    *length = strlen(id) + 1;

    uint8_t *buffer = malloc(*length);
    memcpy(buffer, id, *length);
    return buffer;
}

uint8_t *pt_build_setup_payload(const unsigned char *phi0, const uint16_t phi0_len,
                                const unsigned char *c, const uint16_t c_len,
                                uint16_t *length)
{
    *length = sizeof(phi0_len) + phi0_len + c_len;

    const uint16_t phi0_len_s = htons(phi0_len);

    uint8_t *buffer = malloc(*length);
    memcpy(buffer, &phi0_len_s, sizeof(phi0_len_s));
    memcpy(buffer + sizeof(phi0_len), phi0, phi0_len);
    memcpy(buffer + sizeof(phi0_len) + phi0_len, c, c_len);
    return buffer;
}

// those two can be merged
uint8_t *pt_build_u_payload(const unsigned char *u, const uint16_t u_len,
                            uint16_t *length)
{
    *length = u_len;

    uint8_t *buffer = malloc(*length);
    memcpy(buffer, u, u_len);
    return buffer;
}

uint8_t *pt_build_v_payload(const unsigned char *v, const uint16_t v_len,
                            uint16_t *length)
{
    *length = v_len;

    uint8_t *buffer = malloc(*length);
    memcpy(buffer, v, v_len);
    return buffer;
}

int pt_parse_setup_packet(Packet *setup_packet, unsigned char **phi0,
                          uint16_t *phi0_len_out, unsigned char **c, uint16_t *c_len_out)
{
    if (!setup_packet || !phi0 || !c || !phi0_len_out || !c_len_out)
        return 1;

    // header.length already in network order in packet header; convert to host order
    uint16_t length = setup_packet->header.length;

    if (length < sizeof(uint16_t))
        return 2; // not enough data

    uint16_t phi0_len_net;
    memcpy(&phi0_len_net, setup_packet->payload, sizeof(phi0_len_net));
    uint16_t phi0_len = ntohs(phi0_len_net);

    if (length < sizeof(phi0_len_net) + phi0_len)
        return 3; // malformed

    uint16_t c_len = length - sizeof(phi0_len_net) - phi0_len;

    *phi0 = malloc(phi0_len);
    if (!*phi0)
        return 4;
    memcpy(*phi0, setup_packet->payload + sizeof(phi0_len_net), phi0_len);

    *c = malloc(c_len);
    if (!*c) {
        free(*phi0);
        *phi0 = NULL;
        return 5;
    }
    memcpy(*c, setup_packet->payload + sizeof(phi0_len_net) + phi0_len, c_len);

    *phi0_len_out = phi0_len;
    *c_len_out = c_len;

    return 0;
}
