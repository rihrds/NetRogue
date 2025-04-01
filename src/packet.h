#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdlib.h>
#include "helper.h"

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    uint8_t dest_mac[MAC_LEN]; //same as recv
    uint8_t src_mac[MAC_LEN]; // same as transmit
    uint8_t bssid_mac[MAC_LEN];
    uint16_t SN;
} base_packet;

//mb rename to auth_fixed_params
typedef struct {
    uint16_t auth_algo;
    uint16_t SEQ;
    uint16_t status_code; 
} auth_part;

//mb rename to asso_fixed_params
typedef struct {
    uint16_t capabilities;
    uint16_t listen_interval;
} asso_part;

//
// The following structure can be used for any tagged parameter;
// The structure for all is mostly the same, but creating each may be challenging
//

typedef struct {
    uint8_t tag_num;
    uint8_t len;
    uint8_t *data;
} tagged_param;


uint8_t *create_auth_packet(base_packet *bp, auth_part *ap, size_t *packet_size);
uint8_t *create_asso_packet(base_packet *bp, asso_part *ap, char *ssid, size_t *packet_size);
uint8_t *create_probe_req(base_packet *bp, size_t *packet_size);

#endif