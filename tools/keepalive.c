#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 4242
#define INTERVAL_SECONDS 5

static unsigned int ip_to_int(const char *ip_str)
{
    struct in_addr ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return 0;
    }

    return ntohl(ip.s_addr);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <Multicast group> <Interface address> <Report Address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sockfd;
    struct sockaddr_in multicast_addr;
    struct in_addr local_interface;
    unsigned int report_addr = ip_to_int(argv[3]);

    if (report_addr == 0)
        exit(EXIT_FAILURE);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_port = htons(PORT);
    multicast_addr.sin_addr.s_addr = inet_addr(argv[1]);

    local_interface.s_addr = inet_addr(argv[2]);
    setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, 
               (char *)&local_interface, sizeof(local_interface));

    while (1) {
        ssize_t sent = sendto(sockfd, &report_addr, sizeof(report_addr), 0,
                              (struct sockaddr *)&multicast_addr, sizeof(multicast_addr));
        if (sent < 0) {
            perror("sendto()");
            break;
        }

        printf("Keepalive was multicasted.\n");
        sleep(INTERVAL_SECONDS);
    }

    close(sockfd);
    return 0;
}
