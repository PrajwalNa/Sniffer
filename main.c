/*
*   Main file for packet sniffer
*   This file contains the main function and the processPacket function
*   processPacket function processes the packet based on the protocol and filters set
*   Main function parses the command line options, creates a raw socket, binds it to the interface, and listens for packets
*   It also enables promiscuous mode if requested and disables it after listening
*   I really liked building this project, it was a great learning experience about networking and sockets and linux kernel
*
*   Author: Prajwal Nautiyal
*   Date: 11 May 2024
*   Version: 1.0
*
// Features
*   - The program is a packet sniffer that listens on a specified interface and prints the details of the packets received
*   - It can filter packets based on protocol (TCP, UDP, ICMP, ARP), source and destination IP addresses
*   - It can print the payload in ASCII and/or Hex
*   - It can run in verbose mode, where it prints the details of each packet after processing
*   - It can exclude the Ethernet header from the output
*   - It can run in promiscuous mode, where it captures all packets on the network
*   - It can capture a specified number of packets and then stop
*   - It writes the details of each packet to a log file

// Includes
*   - sys/socket.h: contains socket functions
*   - sys/ioctl.h: contains ioctl functions
*   - net/if.h: network interface functions
*   - stdlib.h: standard library
*   - unistd.h: POSIX syscalls
*   - signal.h: signal handling for SIGINT
*
*   - "modules.h": contains function prototypes and includes required for the functions
*   - included headers from modules.h
*       - stdio.h: standard input/output
*       - string.h: string functions
*       - netinet/in.h: contains structs like sockaddr_in, in_addr etc
*       - arpa/inet.h: converts ip address to string and vice versa (inet_ntoa)
*       - netinet/ip.h: IP header (struct iphdr)
*       - netinet/if_ether.h: Ethernet header for Linux systems (struct ethhdr)
*       - net/ethernet.h: Ethernet header for BSD systems (struct ether_header) also has INT32_MAX XD

*   - "modules.c": contains the functions to process the packet headers
*
*   - Global variables
*       - FILE* logFile: log file to write to
*       - char srcIP[16], destIP[16]: source and destination IP addresses to filter for
*       - char verbose = 0, noEth = 0, proto = 'X', ascii = 0, hex = 0, prom = 0: Filter flags
*       - struct sockaddr_in src, dest: source and destination IP addresses in packet
*       - int tcp = 0, udp = 0, icmp = 0, other = 0, otherEth = 0, arp = 0: counters for different protocols
*       // made global to be accessed in the signal handler
*       - int rawSocket: raw socket
*       - char* interface: interface to listen on
*
*/


#include <sys/socket.h> // contains socket functions
#include <sys/ioctl.h>  // contains ioctl functions
#include <net/if.h>     // network interface functions, like struct ifreq (setting flags, getting interface name etc)
#include <stdlib.h>     // standard library functions
#include <unistd.h>     // POSIX syscalls (close())
#include <signal.h>     // signal handling (SIGINT)

#include "modules.h"

// true -> 1, false -> 0 //

// Local Function prototype
int processPacket(unsigned char* buffer, int size);
void sigintHandler(int sig);

// Global variables
FILE* logFile; // log file to write to
char srcIP[16], destIP[16]; // source and destination IP addresses to filter for
char verbose = 0, noEth = 0, proto = 'X', ascii = 0, hex = 0, prom = 0; // flags
struct sockaddr_in src, dest;   // source and destination IP addresses in packet
int tcp = 0, udp = 0, icmp = 0, other = 0, otherEth = 0, arp = 0;   // counters for different protocols

// these were made global so that they can accessed in the signal handler
int rawSocket;          // raw socket, making it global so that it can be closed in the signal handler
char* interface = NULL; // interface to listen on
int n = INT32_MAX;              // default number of packets is infinite so set to max, this is funnily included with net/ethernet.h


int main(int argc, char* argv[]) {

    unsigned char buffer[65536];    // buffer for packet
    int dataSize;                   // num of butes received in recv
    int opt;                        // to check command line options
    long writePos;                  // position the file pointer last wrote to

    signal(SIGINT, sigintHandler);  // register signal handler for SIGINT (Ctrl+C)

    // Parse command line options
    while ((opt = getopt(argc, argv, "i:vep:n:s:d:axmh")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;

            case 'v':
                verbose = 1;
                break;

            case 'e':
                noEth = 1;
                break;

            case 'p':
                if (strcmp(optarg, "TCP") == 0) {
                    proto = 'T';
                }
                else if (strcmp(optarg, "UDP") == 0) {
                    proto = 'U';
                }
                else if (strcmp(optarg, "ICMP") == 0) {
                    proto = 'I';
                }
                else if (strcmp(optarg, "ARP") == 0) {
                    proto = 'A';
                }
                else {
                    fprintf(stderr, "Invalid protocol\n");
                    return 1;
                }
                break;

            case 'n':
                n = atoi(optarg);
                break;

            case 's':
                // 255.255.255.255 --> 15 characters
                strncpy(srcIP, optarg, 15);
                srcIP[15] = '\0'; // null terminator, since strncpy doesn't add it
                break;

            case 'd':
                // same as above
                strncpy(destIP, optarg, 15);
                destIP[15] = '\0';
                break;

            case 'a':
                ascii = 1;
                break;

            case 'x':
                hex = 1;
                break;

            case 'm':
                prom = 1;
                break;

            case 'h':
                // printing with ANSI escape codes for color
                fprintf(stdout, "Usage: %s -i interface [-p (TCP|UDP|ICMP|ARP)] [-n (Num of Packets)] [-s srcIP] [-d destIP] [-veax]\n", argv[0]);
                fprintf(stdout, "Options:\033[38;5;141m\n");
                fprintf(stdout, "\t-i:\033[0m Interface\033[38;5;141m\n");
                fprintf(stdout, "\t-v:\033[0m  Verbose\033[38;5;141m\n");
                fprintf(stdout, "\t-e:\033[0m  Exclude Ethernet header\033[38;5;141m\n");
                fprintf(stdout, "\t-p:\033[0m  Protocol (Default is watch for All)\033[38;5;141m\n");
                fprintf(stdout, "\t-n:\033[0m  Number of packets to capture (default is infinite)\033[38;5;141m\n");
                fprintf(stdout, "\t-s:\033[0m  Filter for Source IP address\033[38;5;141m");
                fprintf(stdout, "\t-d:\033[0m  Filter for Destination IP address\033[38;5;141m\n");
                fprintf(stdout, "\t-a:\033[0m  Print payload in ASCII\033[38;5;141m");
                fprintf(stdout, "\t-x:\033[0m  Print payload in Hex\n");
                fprintf(stdout, "\t\tIf you want both hex and ascii payload you can just combine both flags \033[38;5;141m[-ax]\n");
                fprintf(stdout, "\t-m:\033[0m  Enable promiscuous mode\033[38;5;141m\n");
                return 0;

            default:
                fprintf(stderr, "Usage help: %s -h\n", argv[0]);
        }
    }

    if (interface == NULL) {
        fprintf(stderr, "Interface is required\n");
        fprintf(stderr, "Usage help: %s -h\n", argv[0]);
        return 1;
    }

    printf("Interface: %s\n", interface);
    printf("Verbose: %d\n", verbose);
    printf("Exclude Ethernet: %d\n", noEth);
    printf("Filtering for Protocol: %c\n", proto);
    printf("Number of packets: %d\n", n);
    printf("Promiscuous mode: %d\n", prom);
    if (strlen(srcIP) > 0) {
        printf("Filtering for Source IP: %s\n", srcIP);
    }
    if (strlen(destIP) > 0) {
        printf("Filtering for Destination IP: %s\n", destIP);
    }
    printf("Payload - ASCII: %d, Hex: %d\n", ascii, hex);

    logFile = fopen("log.txt", "w+");
    char line[256];
    if (logFile == NULL) {
        perror("Failed to open log file");
        return 1;
    }

    // Create raw socket with AF_PACKET family, SOCK_RAW type, and ETH_P_ALL protocol
    // * AF_PACKET lets the application interface directly with the network card (layer 2)
    // * SOCK_RAW is used to create a raw socket, which provides application to provide custom headers
    // * ETH_P_ALL is a protocol value that tells the kernel to send all packets to the socket, regardless of the protocol
    // ** it sets the NIC in a SAP (Service Access Point) promiscuous mode, its not sending all packets on the network to the socket
    // ** it just sends all packets that the network stack didn't discard
    // * htons() [host to network short] converts the value to network byte order [big endian]
    rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // Check if socket creation was successful
    if (rawSocket < 0) {
        perror("Socket creation failed");
        close(rawSocket);
        return 1;
    }
    printf("\nSocket created\n");

    // Bind socket to interface
    // SO_BINDTODEVICE is used to bind the socket to a specific interface
    // the binding is done at the socket level (level 1), so all packets sent or received on this socket will be on the specified interface
    if (setsockopt(rawSocket, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) < 0) {
        perror("Bind to device failed");
        close(rawSocket);
        return 1;
    }

    // Enable promiscuous mode if requested
    // this will set the network card to be "physically" promiscuous, meaning it will send a copy of all packets on the network to the socket
    struct ifreq intf;
    if (prom == 1) {
        strncpy(intf.ifr_name, interface, IFNAMSIZ);    // copy the interface name to the ifreq struct, IFNAMSIZ is the max size of interface name
        if (ioctl(rawSocket, SIOCGIFFLAGS, &intf) == -1) {  // get the flags of the interface, if it fails, print error and exit
            perror("IOCTL failed to get interface flags!");
            close(rawSocket);
            fclose(logFile);
            exit(1);
        }
        intf.ifr_flags |= IFF_PROMISC;  // set the promiscuous flag by doing a bitwise OR operation (intf.ifr_flags = intf.ifr_flags | IFF_PROMISC;)
        if (ioctl(rawSocket, SIOCSIFFLAGS, &intf) == -1) {  // set the flags of the interface, if it fails, print error and exit
            perror("IOCTL failed to set promiscuous mode!");
            close(rawSocket);
            fclose(logFile);
            exit(1);
        }
        printf("Promiscuous mode enabled\n");
    }

    printf("Listening for packets...\n");
    printf("Press Ctrl+C to stop\n");
    printf("----------------------------------------------------\n");

    while (n > 0) {
        dataSize = recv(rawSocket, buffer, 65536, 0);
        printf("\rTCP: %d, UDP: %d, ICMP: %d, ARP: %d, Other IP: %d, Other Eth: %d%*s", tcp, udp, icmp, arp, other, otherEth, 10, "");
        fflush(stdout);

        if (dataSize < 0) {
            perror("Failed to receive data");
            close(rawSocket);
            fclose(logFile);
            exit(1);
        }
        writePos = ftell(logFile); // get the current position of the file pointer

        // if packets fails any filters, continue to the next packet
        if (processPacket(buffer, dataSize) == 1)
            continue;

        n--;
        // if verbosity is not set, update the counters on the same line, else print the details after each packet
        if (verbose != 1) {
            printf("\rTCP: %d, UDP: %d, ICMP: %d, ARP: %d, Other IP: %d, Other Eth: %d%*s", tcp, udp, icmp, arp, other, otherEth, 10, "");
            fflush(stdout);
        }
        else {
            printf("\nTCP: %d, UDP: %d, ICMP: %d, ARP: %d, Other IP: %d, Other Eth: %d", tcp, udp, icmp, arp, other, otherEth);
            fseek(logFile, writePos, SEEK_SET); // set the file pointer to the last write position
            while (fgets(line, sizeof(line), logFile)) {
                printf("%s", line);
            }
            printf("---------------------------------------------\n");
        }
    }

    // disable promiscuous mode if enabled
    if (prom == 1) {
        intf.ifr_flags &= ~IFF_PROMISC;
        if (ioctl(rawSocket, SIOCSIFFLAGS, &intf) == -1) {
            perror("IOCTL failed to disable promiscuous mode!");
            close(rawSocket);
            fclose(logFile);
            exit(1);
        }
        printf("\nPromiscuous mode disabled\n");
    }
    close(rawSocket);
    fclose(logFile);
    printf("\nFinished\n");
    printf("Socket closed\n");

    return 0;
}


int processPacket(unsigned char* buffer, int size) {
    // get the IP header part of this packet using declaration of IP header in netinet/ip.h, struct ethhdr is defined in netinet/if_ether.h
    struct iphdr* ipHead = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct ethhdr* ethHead = (struct ethhdr*)buffer;

    // switch based on the protocol of the frame
    switch (ntohs(ethHead->h_proto)) {
        case ETH_P_IP: // IPv4

            // if protocol is ARP, return
            if (proto == 'A')
                return 1;

            // process the packet based on the protocol
            switch (ipHead->protocol) {
                case 1: // ICMP
                    // filter for ICMP packets or All
                    if (proto != 'I' && proto != 'X')
                        return 1;

                    // check if ipHeader returns 1, if yes, meaning the packet doesn't match the filter
                    if (ipHeader(buffer, size, &ipHead) == 1)
                        return 1;
                    // process the ICMP header if the packet matches the filters 
                    icmpHeader(buffer, size, &ipHead);
                    icmp++;
                    break;

                case 6: // TCP
                    // filter for TCP packets or All
                    if (proto != 'T' && proto != 'X')
                        return 1;

                    // check if ipHeader returns 1, if yes, meaning the packet doesn't match the filter
                    if (ipHeader(buffer, size, &ipHead) == 1)
                        return 1;
                    // process the TCP header if the packet matches the filters
                    tcpHeader(buffer, size, &ipHead);
                    tcp++;
                    break;

                case 17: // UDP
                    // filter for UDP packets or All
                    if (proto != 'U' && proto != 'X')
                        return 1;

                    // check if ipHeader returns 1, if yes, meaning the packet doesn't match the filter
                    if (ipHeader(buffer, size, &ipHead) == 1)
                        return 1;
                    // process the UDP header if the packet matches the filters
                    udpHeader(buffer, size, &ipHead);
                    udp++;
                    break;

                default: // Other Protocols
                    // filter for All
                    if (proto != 'X')
                        return 1;
                    other++;
                    break;
            }
            break;

        case ETH_P_ARP: // ARP
            // filter for ARP packets or All
            if (proto != 'A' && proto != 'X')
                return 1;
            // if either source or destination IP is set, return
            if (srcIP[0] != '\0' || destIP[0] != '\0')
                return 1;

            // process the ARP header if the packet matches the filters
            ethernetHeader(buffer, size);
            arpHeader(buffer, size);
            arp++;
            break;

        default: // Other Ethernet Protocols
            // if protocol is not All, return
            if (proto != 'X')
                return 1;
            // if either source or destination IP is set, return
            if (srcIP[0] != '\0' || destIP[0] != '\0')
                return 1;

            otherEth++;
            break;
    }
}

// Signal handler for SIGINT
void sigintHandler(int sig) {
    printf("\nReceived SIGINT\n");
    // disable promiscuous mode if enabled
    if (prom == 1) {
        struct ifreq intf;
        strncpy(intf.ifr_name, interface, IFNAMSIZ);
        if (ioctl(rawSocket, SIOCGIFFLAGS, &intf) == -1) {
            perror("IOCTL failed to get interface flags!");
            close(rawSocket);
            fclose(logFile);
            exit(1);
        }
        intf.ifr_flags &= ~IFF_PROMISC;
        if (ioctl(rawSocket, SIOCSIFFLAGS, &intf) == -1) {
            perror("IOCTL failed to disable promiscuous mode!");
            close(rawSocket);
            fclose(logFile);
            exit(1);
        }
        printf("\nPromiscuous mode disabled\n");
    }
    close(rawSocket);
    fclose(logFile);
    printf("\nSocket closed\n");
    printf("\nFinished\n");
    exit(0);
}
