#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <string.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "util.h"

void icmp_listener_callback(struct PACKET *upstream_packet, in_addr_t src_addr, int sockfd) {
    if (upstream_packet->sender == SERVER_MES){
        printf("%s \n", upstream_packet->content);
    }
}

int main(int argc, char **argv) {
    int opt, sockfd;
    char *ip_str = NULL;
    struct PACKET packet = {
        .sender = CLIENT_MES,
        .dir = {"/"},
        .content = {""},
    };
    while ((opt = getopt(argc, argv, "i:m:")) != -1) {
        switch (opt) {
            case 'i':
                ip_str = optarg;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s -i IP_ADDRESS\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (ip_str == NULL) {
        fprintf(stderr, "Usage: %s -i IP_ADDRESS\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct in_addr dest;
    if (inet_pton(AF_INET, ip_str, &dest) <= 0) {
        perror("inet_pton() failed");
        exit(EXIT_FAILURE);
    }
    int pid = fork();
    if (pid < 0) {
        perror("fork() failed");
        exit(EXIT_FAILURE);
    }
    if (pid == 0) {
        icmp_listener(icmp_listener_callback);
    }
    else {
        while(1){
            memset(packet.content, 0, DATA_SIZE);
            memset(packet.dir, 0, MAX_DIR_SIZE);
            sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
            packet.sender = CLIENT_MES;
            fgets(packet.content, DATA_SIZE, stdin); 
            if (strncmp(packet.content, "cd", 2) == 0) {      
                strncpy(packet.dir, packet.content + 3, strlen(packet.content) - 3);
                packet.content[0] = '\0';
                memset(packet.content, 0, DATA_SIZE);
            }      
            icmp_send(sockfd, &dest, &packet);
        }
    }
}