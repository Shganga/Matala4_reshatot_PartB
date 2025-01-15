#include "traceroute.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>

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

void build_icmp_packet(char *packet, int ttl) {
    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = ttl;
    icmp->checksum = 0; // Initially set to 0
    icmp->checksum = checksum(packet, PACKET_SIZE);
}

void traceroute(const char *destination) {
    int sockfd;
    struct sockaddr_in dest_addr;
    struct timeval start, end;
    char packet[PACKET_SIZE];
    struct iphdr *ip_header;  // Use iphdr for IP header structure
    struct icmphdr *icmp_header;
    struct pollfd pfds[1];
    int ttl = 1;

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

    // Set timeout for receiving the packet
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting socket timeout");
        exit(1);
    }

    printf("traceroute to %s, %d hops max\n", destination, MAX_HOPS);

    // Loop through TTL values (1 to 30)
    for (ttl = 1; ttl <= MAX_HOPS; ttl++) {
        printf("%2d", ttl); // Print hop number

        // Set TTL value
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("Error setting TTL");
            exit(1);
        }

        // Send 3 probes per hop
        for (int i = 0; i < NUM_PROBES; i++) {
            gettimeofday(&start, NULL);
            build_icmp_packet(packet, ttl); // Build ICMP request packet
            if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
                perror("Send failed");
                exit(1);
            }

            // Set up the poll structure
            pfds[0].fd = sockfd;
            pfds[0].events = POLLIN;

            // Poll for incoming responses
            int ret = poll(pfds, 1, TIMEOUT * 1000); // Timeout in milliseconds
            if (ret > 0 && (pfds[0].revents & POLLIN)) {
                char response[PACKET_SIZE];
                socklen_t len = sizeof(dest_addr);
                if (recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&dest_addr, &len) < 0) {
                    perror("Recv failed");
                    exit(1);
                }

                gettimeofday(&end, NULL);
                double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;

                // Cast response buffer to iphdr header
                ip_header = (struct iphdr *)response;  // Use iphdr here

                // Correctly calculate the position of the ICMP header
                icmp_header = (struct icmphdr *)(response + (ip_header->ihl * 4));  // iphl is in 4-byte units

                // Print the IP address and RTT
                printf(" %s %.3fms", inet_ntoa(*(struct in_addr *)&ip_header->saddr), rtt);
            } else {
                printf(" *");
            }
            if (i < NUM_PROBES - 1) printf("\t");
        }
        printf("\n");

        // Check if the destination has been reached
        if (ip_header->daddr == dest_addr.sin_addr.s_addr) {
            printf("Destination reached\n");
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