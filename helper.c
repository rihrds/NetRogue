#include <stdio.h>
#include <stdlib.h>

#include "helper.h"

void get_mac_address(unsigned char *start, char *address_string)
{
    sprintf(address_string, "%02x:%02x:%02x:%02x:%02x:%02x", 
        start[0], start[1], start[2], start[3], start[4], start[5]);
}

uint8_t *mac_to_bytes(char mac_addr[STRING_MAC_LEN])
{
    uint8_t *mac_bytes = (uint8_t *) malloc(MAC_LEN);

    sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
        &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
        &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
    
    return mac_bytes;
}

void print_packet_contents(uint8_t *raw_packet, int packet_len)
{
    for (int i = 0; i < packet_len; i++)
        printf("%02x ", raw_packet[i]);
    printf("\n");
}

