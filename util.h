#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define DATA_SIZE 50000
#define IDENTIFIER_ID 6666 // Yes, it doesn't matter.
#define MAX_DIR_SIZE 4096


enum SENDER {
    CLIENT_MES = 1,
    SERVER_MES
};

struct PACKET {
    enum SENDER sender;
    char dir[MAX_DIR_SIZE];
    char content[DATA_SIZE];
} __attribute__((packed));

typedef void (*icmp_callback)(struct PACKET *upstream_packet, in_addr_t src_addr, int sockfd);
uint16_t checksum(uint16_t *addr, int len);
void icmp_listener(icmp_callback callback);
void icmp_send(int sockfd, struct in_addr *dest, struct PACKET *packet);

#endif /* UTIL_H */