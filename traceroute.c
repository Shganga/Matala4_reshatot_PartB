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
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    struct pollfd pfds[1];
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

    // Loop through TTL values
    for (ttl = 1; ttl <= MAX_HOPS; ttl++) {
        printf("%2d", ttl); // Print hop number
        int destination_reached = 0; // Flag to track if the destination is reached

        // Set TTL value for the socket
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("Error setting TTL");
            exit(1);
        }

        // Send 3 probes for the current TTL
        for (int i = 0; i < NUM_PROBES; i++) {
            gettimeofday(&start, NULL);
            build_icmp_packet(packet, ttl); // Build ICMP packet
            if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
                perror("Send failed");
                exit(1);
            }

            // Set up poll for receiving responses
            pfds[0].fd = sockfd;
            pfds[0].events = POLLIN;

            int ret = poll(pfds, 1, TIMEOUT * 1000); // Timeout in milliseconds
            if (ret > 0 && (pfds[0].revents & POLLIN)) {
                char response[PACKET_SIZE];
                struct sockaddr_in recv_addr;
                socklen_t addr_len = sizeof(recv_addr);

                if (recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&recv_addr, &addr_len) < 0) {
                    perror("Recv failed");
                    exit(1);
                }

                gettimeofday(&end, NULL);
                double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;

                // Extract IP and ICMP headers
                ip_header = (struct iphdr *)response;
                icmp_header = (struct icmphdr *)(response + (ip_header->ihl * 4));

                printf(" %s %.3fms", inet_ntoa(recv_addr.sin_addr), rtt);

                // Check if the destination has been reached
                if (memcmp(&recv_addr.sin_addr, &dest_addr.sin_addr, sizeof(recv_addr.sin_addr)) == 0) {
                    destination_reached = 1;
                }

            } else {
                printf(" *");
            }
            if (i < NUM_PROBES - 1) printf("\t");
        }
        printf("\n");

        // Exit if destination is reached
        if (destination_reached) {
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