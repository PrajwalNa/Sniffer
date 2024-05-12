/*
* Modules File
* This file contains the functions for parsing and printing the headers of the different network protocols
* The functions are called from the main file
*
* Author: Prajwal Nautiyal
* Date: 12 May 2024
*/

#include <netinet/tcp.h>        // TCP header (struct tcphdr)
#include <netinet/udp.h>        // UDP header (struct udphdr)
#include <netinet/ip_icmp.h>    // ICMP header (struct icmphdr)
#include <net/if_arp.h>         // ARP header (struct arphdr)

#include "modules.h"

extern FILE* logFile;
extern char srcIP[16], destIP[16];
extern char verbose, noEth, ascii, hex;


void ethernetHeader(unsigned char* buffer, int size) {
    // ethhdr is defined in netinet/if_ether.h
    // it has declarations for source and destination MAC addresses and protocol
    struct ethhdr* eth = (struct ethhdr*)buffer;

    fprintf(logFile, "\nEthernet Header\n");
    fprintf(logFile, "\t| Source MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logFile, "\t| Destination MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logFile, "\t| Protocol: %u\n", (unsigned short)eth->h_proto);
}


int ipHeader(unsigned char* buffer, int size, struct iphdr** ipH) {
    struct sockaddr_in src, dest;   // source and destination IP addresses in packet
    // set binary zeros to the sockaddr_in structs
    // then set the IP addresses to the source and destination IP addresses from the IP header
    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = (*ipH)->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = (*ipH)->daddr;

    // filter packets based on source and destination IP addresses if provided
    if (strlen(srcIP) > 0 && strlen(destIP) > 0) {
        if (strcmp(inet_ntoa(src.sin_addr), srcIP) != 0 && strcmp(inet_ntoa(dest.sin_addr), destIP) != 0) {
            return 1;
        }
    }
    else if (strlen(srcIP) > 0) {
        if (strcmp(inet_ntoa(src.sin_addr), srcIP) != 0) {
            return 1;
        }
    }
    else if (strlen(destIP) > 0) {
        if (strcmp(inet_ntoa(dest.sin_addr), destIP) != 0) {
            return 1;
        }
    }

    fprintf(logFile, "\n----------------------------------------------------");
    // if the ethernet header flag is not set, print the ethernet header to the log file
    if (noEth != 1) {
        ethernetHeader(buffer, size);
    }

    char* protocol;
    protocol = (*ipH)->protocol == 6 ? "TCP" : (*ipH)->protocol == 17 ? "UDP" : (*ipH)->protocol == 1 ? "ICMP" : "Other";

    fprintf(logFile, "\nIP Header\n");
    fprintf(logFile, "\t| Version: %d\n", (unsigned int)(*ipH)->version);
    // ihl (intenet header length) is the number of 32-bit words in the header, so multiply by 4 to get bytes
    fprintf(logFile, "\t| Header Length: %d DWORDS or %d Bytes\n", (unsigned int)(*ipH)->ihl, ((unsigned int)((*ipH)->ihl)) * 4);
    fprintf(logFile, "\t| Type of Service: %d\n", (unsigned int)(*ipH)->tos);
    // ntohs() {Network to Host short} converts 16 bit number from network byte order (big endian) to host byte order
    fprintf(logFile, "\t| Total Length: %d Bytes\n", ntohs((*ipH)->tot_len));
    fprintf(logFile, "\t| Identification: %d\n", ntohs((*ipH)->id));
    fprintf(logFile, "\t| Fragment Offset: %d\n", ntohs((*ipH)->frag_off));
    fprintf(logFile, "\t| Time to Live (TTL): %d\n", (unsigned int)(*ipH)->ttl);
    fprintf(logFile, "\t| Protocol: %d (%s)\n", (unsigned int)(*ipH)->protocol, protocol);
    fprintf(logFile, "\t| Checksum: %d\n", ntohs((*ipH)->check));
    // inet_ntoa() converts IP address to string
    fprintf(logFile, "\t| Source IP: %s\n", inet_ntoa(src.sin_addr));
    fprintf(logFile, "\t| Destination IP: %s\n", inet_ntoa(dest.sin_addr));

    return 0;
}


void arpHeader(unsigned char* buffer, int size) {
    struct arphdr* arp = (struct arphdr*)(buffer + sizeof(struct ethhdr));

    fprintf(logFile, "\nARP Header\n");
    fprintf(logFile, "\t| Hardware Type: %u\n", arp->ar_hrd);
    fprintf(logFile, "\t| Protocol Type: %u\n", arp->ar_pro);
    fprintf(logFile, "\t| Hardware Address Length: %u\n", arp->ar_hln);
    fprintf(logFile, "\t| Protocol Address Length: %u\n", arp->ar_pln);
    fprintf(logFile, "\t| Operation (opcode): %u\n", arp->ar_op);
    unsigned char* senderAddr = buffer + sizeof(struct ethhdr) + sizeof(struct arphdr);
    fprintf(logFile, "\t| Sender MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);
    fprintf(logFile, "\t| Sender IP Address: %u.%u.%u.%u\n", senderAddr[6], senderAddr[7], senderAddr[8], senderAddr[9]);
    unsigned char* targetAddr = buffer + sizeof(struct ethhdr) + sizeof(struct arphdr) + 10;
    fprintf(logFile, "\t| Target MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", targetAddr[0], targetAddr[1], targetAddr[2], targetAddr[3], targetAddr[4], targetAddr[5]);
    fprintf(logFile, "\t| Target IP Address: %u.%u.%u.%u\n", targetAddr[6], targetAddr[7], targetAddr[8], targetAddr[9]);

    // ARP protocol does not have a payload like higher level protocols
}


void tcpHeader(unsigned char* buffer, int size, struct iphdr** ipH) {
    struct tcphdr* tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + (*ipH)->ihl * 4);

    fprintf(logFile, "\nTCP Header\n");
    fprintf(logFile, "\t| Source Port: %u\n", ntohs(tcp->th_sport));
    fprintf(logFile, "\t| Destination Port: %u\n", ntohs(tcp->th_dport));
    // ntohl() {Network to Host long} converts 32 bit number from network byte order (big endian) to host byte order
    fprintf(logFile, "\t| Sequence Number: %u\n", ntohl(tcp->th_seq));
    fprintf(logFile, "\t| Acknowledgement Number: %u\n", ntohl(tcp->th_ack));
    fprintf(logFile, "\t| Header Length: %d DWORDS or %d BYTES\n", (unsigned int)tcp->th_off, (unsigned int)tcp->th_off * 4);
    fprintf(logFile, "\t|-Flags\n");
    fprintf(logFile, "\t\t| Reserved: %d\n", tcp->res1);    // Reserved bits for future use
    fprintf(logFile, "\t\t| FIN: %d\n", tcp->fin);  // No more data from sender
    fprintf(logFile, "\t\t| SYN: %d\n", tcp->syn);  // Synchronize sequence numbers
    fprintf(logFile, "\t\t| RST: %d\n", tcp->rst);  // Reset the connection
    fprintf(logFile, "\t\t| PSH: %d\n", tcp->psh);  // Push Function
    fprintf(logFile, "\t\t| ACK: %d\n", tcp->ack);  // Acknowledgement field significant
    fprintf(logFile, "\t\t| URG: %d\n", tcp->urg);  // Urgent Pointer field significant
    fprintf(logFile, "\t\t| ECE: %d\n", (tcp->th_flags & 0x40) ? 1 : 0);    // Explicit Congestion Notification Echo
    fprintf(logFile, "\t\t| CWR: %d\n", (tcp->th_flags & 0x80) ? 1 : 0);    // Congestion Window Reduced
    fprintf(logFile, "\t| Window: %d\n", ntohs(tcp->th_win));   // Advertised window size
    fprintf(logFile, "\t| Checksum: %d\n", ntohs(tcp->th_sum)); // Header Checksum
    fprintf(logFile, "\t| Urgent Pointer: %d\n", tcp->th_urp);  // Urgent Pointer

    // getting the total offset by adding the sizes of Eth frame and IP packet header
    unsigned int totalHead = sizeof(struct ethhdr) + (*ipH)->ihl * 4 + tcp->th_off * 4;
    unsigned int payloadSize = size - totalHead;    // also the size on data, which is the size of packet - size of headers
    payload(buffer + totalHead, payloadSize);       // send to payload function for printing the data after setting data offset to after the headers
}


void udpHeader(unsigned char* buffer, int size, struct iphdr** ipH) {
    struct udphdr* udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + (*ipH)->ihl * 4);

    fprintf(logFile, "\nUDP Header\n");
    fprintf(logFile, "\t| Source Port: %d\n", ntohs(udp->uh_sport));
    fprintf(logFile, "\t| Destination Port: %d\n", ntohs(udp->uh_dport));
    fprintf(logFile, "\t| Length: %d\n", ntohs(udp->uh_ulen));
    fprintf(logFile, "\t| Checksum: %d\n", ntohs(udp->uh_sum));

    // same process as TCP Headers
    unsigned int totalHead = sizeof(struct ethhdr) + (*ipH)->ihl * 4 + sizeof(struct udphdr);
    unsigned int payloadSize = size - totalHead;
    payload(buffer + totalHead, payloadSize);
}


void icmpHeader(unsigned char* buffer, int size, struct iphdr** ipH) {
    struct icmphdr* icmp = (struct icmphdr*)(buffer + sizeof(struct ethhdr) + (*ipH)->ihl * 4);

    // determine the type of ICMP packet
    char type[25];
    switch (icmp->type) {
        case 0:
            strncpy(type, "Echo Reply", 24);
            break;
        case 3:
            strncpy(type, "Destination Unreachable", 24);
            break;
        case 8:
            strncpy(type, "Echo Request", 24);
            break;
        case 11:
            strncpy(type, "Time Exceeded", 24);
            break;
        default:
            strncpy(type, "Other", 24);
            break;
    }
    type[24] = '\0';

    fprintf(logFile, "\nICMP Header\n");
    fprintf(logFile, "\t| Type: %d (%s)\n", icmp->type, type);
    fprintf(logFile, "\t| Code: %d\n", icmp->code);
    fprintf(logFile, "\t| Checksum: %d\n", ntohs(icmp->checksum));
    fprintf(logFile, "\t| Identifier: %d\n", ntohs(icmp->un.echo.id));
    fprintf(logFile, "\t| Sequence Number: %d\n", ntohs(icmp->un.echo.sequence));

    // same process as TCP headers
    unsigned int totalHead = sizeof(struct ethhdr) + (*ipH)->ihl * 4 + sizeof(struct icmphdr);
    unsigned int payloadSize = size - totalHead;
    payload(buffer + totalHead, payloadSize);
}


void payload(unsigned char* buffer, int size) {
    if (ascii == 0 && hex == 0)
        ascii = 1;  // default to ASCII if no option is provided

    fprintf(logFile, "\nData Payload\n");
    if (ascii == 1) {
        fprintf(logFile, "\t| ASCII\n");
        fprintf(logFile, "\t\t| ");
        // print the payload in ASCII
        for (int i = 0; i < size; i++) {    // size is the length of the packet
            if (i != 0 && i % 16 == 0) {  // print 16 bytes per line
                fprintf(logFile, " ");      // add a space between the two groups of 8 bytes
                for (int j = i - 16; j < i; j++) {
                    // if the byte is a printable character, print it  
                    if (buffer[j] >= 32 && buffer[j] <= 128) {
                        fprintf(logFile, "%c", (unsigned char)buffer[j]);
                    }
                    // else print a dot
                    else {
                        fprintf(logFile, ".");
                    }
                }
                fprintf(logFile, "\n");
                fprintf(logFile, "\t\t| ");
            }
        }
    }

    if (hex == 1) {
        fprintf(logFile, "\n\t| HEX\n");
        fprintf(logFile, "\t\t| ");
        // print the payload in HEX
        for (int i = 0; i < size; i++) {
            fprintf(logFile, "%.2X ", (unsigned int)buffer[i]);
            if (i != 0 && i % 16 == 0 && i) {  // print 16 bytes per line
                fprintf(logFile, "\n\t\t| ");
            }
        }
        fprintf(logFile, "\n");
    }
}
