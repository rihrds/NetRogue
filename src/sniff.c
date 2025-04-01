#include "sniff.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "helper.h"


//***************************************************************************
// returns the length of the sniffed packet.
//
// arguments: 
//      raw_socket fd,
//      pointer to a uint8_t for place to store packet. If NULL then return packet is not stored,
//      filter -> a pointer to a function that returns true or false based on packet contents.
//      listen_limit -> how many packets to listen for before giving up. 0 means always listen
//
// Returns -1 if packet wasn't found. -2 or -3 for other errors
//
//***************************************************************************
int sniff(int raw_socket, uint8_t *packet_buffer, bool (*filter)(uint8_t *), int listen_limit)
{
    uint8_t *buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL)
    {
        printf("[-] Failed to allocate buffer\n");
        return -2;
    }

    for (int i = 0; listen_limit == 0 || i < listen_limit; i += (listen_limit == 0 ? 0 : 1))
    {
        memset(buffer, 0, BUFFER_SIZE);

        int packet_size = recv(raw_socket, buffer, BUFFER_SIZE, 0);
        if (packet_size < 0)
        {
            printf("[-] Error receiving the packet\n");
            return -3;
        }

        uint8_t *raw_packet = buffer + buffer[2]; //packet without radiotap

        if (filter(raw_packet))
        {
            if (packet_buffer != NULL)
                memcpy(packet_buffer, buffer, BUFFER_SIZE);
            free(buffer);
            return packet_size;
        }
    }

    free(buffer);
    return -1;
}