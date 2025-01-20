#include "traceroute.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include <netinet/ip_icmp.h>

// Global variables for destination address and timeout
struct sockaddr_in dest_addr;
struct timeval timeout;

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void build_ip_header(struct ip_header *iph, uint32_t src_addr, uint32_t dest_addr, uint8_t ttl) {
    memset(iph, 0, sizeof(struct ip_header));
    iph->version_ihl = (4 << 4) | (sizeof(struct ip_header) / 4); // Version: 4, Header Length: 5 (20 bytes)
    iph->tos = 0;
    iph->total_length = htons(sizeof(struct ip_header) + PACKET_SIZE);
    iph->identification = htons(rand() % 65536);
    iph->flags_offset = htons(0);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_ICMP;
    iph->checksum = 0; // Will be calculated later
    iph->src_addr = src_addr;
    iph->dest_addr = dest_addr;
    iph->checksum = checksum((void *)iph, sizeof(struct ip_header));
}

void build_icmp_packet(char *packet, int seq) {
    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = seq;
    icmp->checksum = 0; // Initially set to 0
    icmp->checksum = checksum(packet, PACKET_SIZE);
}

void traceroute(const char *destination) {
    int sockfd;
    struct timeval start, end;
    char packet[PACKET_SIZE];
    int ttl;

    // Create a raw socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Set destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, destination, &dest_addr.sin_addr) <= 0) {
        perror("Invalid destination address");
        exit(1);
    }

    // Set timeout for receiving packets
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting socket timeout");
        exit(1);
    }

    printf("traceroute to %s, %d hops max\n", destination, MAX_HOPS);

    for (ttl = 1; ttl <= MAX_HOPS; ttl++) {
        // Set TTL value for the socket
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("Error setting TTL");
            exit(1);
        }

        char ip_address[INET_ADDRSTRLEN] = "*";
        double rtts[NUM_PROBES] = {-1, -1, -1};
        int destination_reached = 0;

        for (int i = 0; i < NUM_PROBES; i++) {
            gettimeofday(&start, NULL);
            build_icmp_packet(packet, ttl);

            if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
                perror("Send failed");
                exit(1);
            }

            char response[PACKET_SIZE];
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);

            int bytes_received = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&recv_addr, &addr_len);
            gettimeofday(&end, NULL);

            if (bytes_received > 0) {
                if (inet_ntop(AF_INET, &(recv_addr.sin_addr), ip_address, INET_ADDRSTRLEN) == NULL) {
                    strcpy(ip_address, "*");
                }

                double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
                rtts[i] = rtt;

                struct ip_header *ip_hdr = (struct ip_header *)response;
                struct icmphdr *icmp_hdr = (struct icmphdr *)(response + (ip_hdr->version_ihl & 0x0F) * 4);

                if (icmp_hdr->type == ICMP_ECHOREPLY || memcmp(&recv_addr.sin_addr, &dest_addr.sin_addr, sizeof(recv_addr.sin_addr)) == 0) {
                    destination_reached = 1;
                }
            }
        }

        printf("%2d  %s  ", ttl, ip_address);
        for (int i = 0; i < NUM_PROBES; i++) {
            if (rtts[i] >= 0) {
                printf("%.3fms  ", rtts[i]);
            } else {
                printf("*  ");
            }
        }
        printf("\n");

        if (destination_reached) {
            printf("Destination reached.\n");
            break;
        }
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 3 || strcmp(argv[1], "-a") != 0) {
        fprintf(stderr, "Usage: sudo %s -a <destination_ip>\n", argv[0]);
        return 1;
    }

    traceroute(argv[2]);
    return 0;
}