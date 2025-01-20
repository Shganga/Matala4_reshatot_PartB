#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <poll.h>
#include <stdint.h>

#define MAX_HOPS 30
#define PACKET_SIZE 64
#define TIMEOUT 1 // Timeout in seconds
#define NUM_PROBES 3 // Number of ICMP requests per hop

// Define the custom IP header structure
struct ip_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dest_addr;
};

// Function prototypes
unsigned short checksum(void *b, int len);
void build_ip_header(struct ip_header *iph, uint32_t src_addr, uint32_t dest_addr, uint8_t ttl);
void build_icmp_packet(char *packet, int seq);
void traceroute(const char *destination);

#endif // TRACEROUTE_H
