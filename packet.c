//idk wht to include
#include "packet.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

//dummy radiotap_header to be added to packets
//static for file scope. const bcs it won't change
static const uint8_t radiotap_header[] = {
    0x00, 0x00,  // Version & Pad
    0x08, 0x00,  // Length (8 bytes)
    0x00, 0x00, 0x00, 0x00  // Flags (no extra features)
};


// mb remove auth_part from parameters since its identical for all packets
uint8_t *create_auth_packet(base_packet *bp, auth_part *ap, size_t *packet_size)
{
    *packet_size = sizeof(radiotap_header) + sizeof(base_packet) + sizeof(auth_part);

    uint8_t *buffer = (uint8_t *) malloc(*packet_size);
    if (buffer == NULL)
    { //mb better to return NULL for better error handling
        printf("Error allocating buffer for authentication packet!\n");
        exit(3);
    }

    size_t offset = 0;

    memcpy(buffer, radiotap_header, sizeof(radiotap_header));
    offset += sizeof(radiotap_header);
    memcpy(buffer + offset, bp, sizeof(base_packet));
    offset += sizeof(base_packet);
    memcpy(buffer + offset, ap, sizeof(auth_part));

    return buffer;
}

// mb remove asso_part from parameters since it will prob be identical for all packets
// mb also replace base_packet with src and dest? But then also SN would need to be passed
uint8_t *create_asso_packet(base_packet *bp, asso_part *ap, char *ssid_name, size_t *packet_size)
{
    tagged_param ssid = {.tag_num = 0, .len = strlen(ssid_name), .data = (uint8_t *) ssid_name};

    uint8_t rates_data[] = {0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24};
    tagged_param rates = {.tag_num = 1, .len = sizeof(rates_data), .data = rates_data};

    uint8_t ext_rates_data[] = {0x30, 0x48, 0x60, 0x6c};
    tagged_param ext_rates = {.tag_num = 50, .len = sizeof(ext_rates_data), .data = ext_rates_data};

    uint8_t rsn_info[] = {0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x12, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xac, 0x06};
    tagged_param rsn = {.tag_num = 48, .len = sizeof(rsn_info), .data = rsn_info};

    uint8_t owe_info[] = {0x20, 0x13, 0x00, 0xf7, 0xe9, 0xf9, 0x93, 0xc5, 0x68, 0xe3, 0x3c, 0x14, 0xf1, 0x07, 0x29, 0x04, 0xf4, 0x14, 0xef, 0xd9, 0xbb, 0x8d, 0x7b, 0x90, 0x6c, 0x27, 0x2d, 0x1d, 0x45, 0xf1, 0xfc, 0x5a, 0xfb, 0xde, 0xab};
    tagged_param owe = {.tag_num = 255, .len = sizeof(owe_info), .data = owe_info};


    //TODO: make the tagged param more logical
    *packet_size = sizeof(radiotap_header) + sizeof(base_packet) + sizeof(asso_part) + 2 + ssid.len + 2 + rates.len + 2 + ext_rates.len + 2 + rsn.len + 2 + owe.len;

    uint8_t *buffer = (uint8_t *) malloc(*packet_size);
    if (buffer == NULL)
    { //mb better to return NULL for better error handling
        printf("Error allocating buffer for assocation packet!\n");
        exit(3);
    }

    size_t offset = 0;

    memcpy(buffer, radiotap_header, sizeof(radiotap_header));
    offset += sizeof(radiotap_header);
    memcpy(buffer + offset, bp, sizeof(base_packet));
    offset += sizeof(base_packet);
    memcpy(buffer + offset, ap, sizeof(asso_part));
    offset += sizeof(asso_part);


    memcpy(buffer + offset, (uint8_t []) {ssid.tag_num, ssid.len}, 2);
    offset += 2;
    memcpy(buffer + offset, ssid.data, ssid.len);
    offset += ssid.len;

    memcpy(buffer + offset, (uint8_t []) {rates.tag_num, rates.len}, 2);
    offset += 2;
    memcpy(buffer + offset, rates.data, rates.len);
    offset += rates.len;

    memcpy(buffer + offset, (uint8_t []) {ext_rates.tag_num, ext_rates.len}, 2);
    offset += 2;
    memcpy(buffer + offset, ext_rates.data, ext_rates.len);
    offset += ext_rates.len;

    memcpy(buffer + offset, (uint8_t []) {rsn.tag_num, rsn.len}, 2);
    offset += 2;
    memcpy(buffer + offset, rsn.data, rsn.len);
    offset += rsn.len;

    memcpy(buffer + offset, (uint8_t []) {owe.tag_num, owe.len}, 2);
    offset += 2;
    memcpy(buffer + offset, owe.data, owe.len);

    return buffer;
}

uint8_t *create_probe_req(base_packet *bp, size_t *packet_size)
{
    char *ssid_name = "MikroTik_OWE"; 
    tagged_param ssid = {.tag_num = 0, .len = strlen("MikroTik_OWE"), .data = (uint8_t *) ssid_name};

    uint8_t rates_data[] = {0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24};
    tagged_param rates = {.tag_num = 1, .len = sizeof(rates_data), .data = rates_data};

    uint8_t ext_rates_data[] = {0x30, 0x48, 0x60, 0x6c};
    tagged_param ext_rates = {.tag_num = 50, .len = sizeof(ext_rates_data), .data = ext_rates_data};

    uint8_t dsset_data[] = {0x06};
    tagged_param dsset = {.tag_num = 50, .len = sizeof(dsset_data), .data = dsset_data};

    uint8_t rsn_info[] = {0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x12, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xac, 0x06};
    tagged_param rsn = {.tag_num = 48, .len = sizeof(rsn_info), .data = rsn_info};

    uint8_t ext_cap_data[] = {0x04, 0x00, 0xca, 0x02, 0x01, 0x40, 0x40, 0xc0, 0x01, 0x21, 0x20};
    tagged_param ext_cap = {.tag_num = 127, .len = sizeof(ext_cap_data), .data = ext_cap_data};


    *packet_size = sizeof(radiotap_header) + sizeof(base_packet) + 2 + ssid.len + 2 + rates.len + 2 + ext_rates.len + 2 + dsset.len + 2 + rsn.len + 2 + ext_cap.len;

    uint8_t *buffer = (uint8_t *) malloc(*packet_size);
    if (buffer == NULL)
    { //mb better to return NULL for better error handling
        printf("Error allocating buffer for assocation packet!\n");
        exit(3);
    }

    size_t offset = 0;

    memcpy(buffer, radiotap_header, sizeof(radiotap_header));
    offset += sizeof(radiotap_header);
    memcpy(buffer + offset, bp, sizeof(base_packet));
    offset += sizeof(base_packet);

    //since ssid empty only describing params need to be copied
    memcpy(buffer + offset, (uint8_t []) {ssid.tag_num, ssid.len}, 2);
    offset += 2;
    memcpy(buffer + offset, ssid.data, ssid.len);
    offset += ssid.len;

    memcpy(buffer + offset, (uint8_t []) {rates.tag_num, rates.len}, 2);
    offset += 2;
    memcpy(buffer + offset, rates.data, rates.len);
    offset += rates.len;

    memcpy(buffer + offset, (uint8_t []) {ext_rates.tag_num, ext_rates.len}, 2);
    offset += 2;
    memcpy(buffer + offset, ext_rates.data, ext_rates.len);
    offset += ext_rates.len;

    memcpy(buffer + offset, (uint8_t []) {dsset.tag_num, dsset.len}, 2);
    offset += 2;
    memcpy(buffer + offset, dsset.data, dsset.len);
    offset += dsset.len;

    memcpy(buffer + offset, (uint8_t []) {rsn.tag_num, rsn.len}, 2);
    offset += 2;
    memcpy(buffer + offset, rsn.data, rsn.len);
    offset += rsn.len;

    memcpy(buffer + offset, (uint8_t []) {ext_cap.tag_num, ext_cap.len}, 2);
    offset += 2;
    memcpy(buffer + offset, ext_cap.data, ext_cap.len);
    offset += ext_cap.len;

    return buffer;
}
