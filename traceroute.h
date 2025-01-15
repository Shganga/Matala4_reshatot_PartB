#pragma once
#ifndef TRACEROUTE_H
#define TRACEROUTE_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <poll.h>

#define MAX_HOPS 30
#define PACKET_SIZE 64
#define TIMEOUT 1 // Timeout in seconds
#define NUM_PROBES 3 // Number of ICMP requests per hop

// Function prototypes
unsigned short checksum(void *b, int len);
void build_icmp_packet(char *packet, int seq);
void traceroute(const char *destination);

#endif // TRACEROUTE_H
