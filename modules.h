/*
* Header file for modules.c/main.c
* Contains function prototypes for modules.c
* Also includes necessary libraries used in both modules.c and main.c
*
* Author: Prajwal Nautiyal
* Date: 12 May 2024
*/

// Adding them here since both modules.c and main.c need them
#include <stdio.h>      // standard input/output
#include <string.h>     // string functions

#include <netinet/in.h>     // contains structs like sockaddr_in, in_addr etc
#include <arpa/inet.h>      // converts ip address to string and vice versa (inet_ntoa)
#include <netinet/ip.h>     // IP header (struct iphdr)

#include <netinet/if_ether.h>   // Ethernet header for Linux systems (struct ethhdr)
#include <net/ethernet.h>       // Ethernet header for BSD systems (struct ether_header) also has INT32_MAX XD

void ethernetHeader(unsigned char* buffer, int size);
int ipHeader(unsigned char* buffer, int size, struct iphdr** ipH);
void tcpHeader(unsigned char* buffer, int size, struct iphdr** ipH);
void udpHeader(unsigned char* buffer, int size, struct iphdr** ipH);
void icmpHeader(unsigned char* buffer, int size, struct iphdr** ipH);
void arpHeader(unsigned char* buffer, int size);
void payload(unsigned char* buffer, int size);
