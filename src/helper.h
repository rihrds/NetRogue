#ifndef HELPER_H
#define HELPER_H

#include <stdint.h>

#define STRING_MAC_LEN 18
#define MAC_LEN 6
#define BUFFER_SIZE 512


typedef struct {
    char *ssid;
    uint8_t mac[MAC_LEN];
} ap_info;

typedef struct {
    char *name;
    uint8_t *mac;
} intf_info;

void get_mac_address(unsigned char *start, char *address_string);
void print_packet_contents(uint8_t *raw_packet, int packet_len);
uint8_t *mac_to_bytes(char mac_addr[STRING_MAC_LEN]);

#endif