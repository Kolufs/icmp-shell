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
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>


#include "util.h"


uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  answer = ~sum;

  return (answer);
}

// The whole implementation regarding the packet transfer is likely an abdomination.
// Fault of my lack of knowledge in that matter.
// Sorry!

unsigned char *serialize(struct PACKET *packet) {
  unsigned char *buffer;

  size_t dir_len = strnlen(packet->dir, MAX_DIR_SIZE);
  size_t content_len = strnlen(packet->content, DATA_SIZE);

  buffer = (unsigned char *)malloc(dir_len+content_len+1);
  memset(buffer, '0', dir_len+content_len+1);
  
  buffer[0] = packet->sender;

  memcpy((char*)&buffer[1], packet->dir, dir_len);
  buffer[1 + dir_len] = '\0';
  memcpy((char*)&buffer[1 + 1 + dir_len], packet->content, content_len);
  buffer[1 + dir_len + content_len] = '\0';
  return buffer;
}

struct PACKET *deserialize(unsigned char *raw_packet) {
  struct PACKET *packet = (struct PACKET *) malloc(sizeof(struct PACKET));

  size_t dir_len = strnlen(raw_packet+1, MAX_DIR_SIZE);
  size_t content_len = strnlen(raw_packet+1+dir_len+1, DATA_SIZE);
  memset(packet, 0, sizeof(struct PACKET));

  packet->sender = raw_packet[0];

  strncpy(packet->dir, raw_packet+1, MAX_DIR_SIZE);
  packet->dir[dir_len+1] = '\0';
  strncpy(packet->content, raw_packet+1+dir_len+1, DATA_SIZE);
  packet->content[dir_len + content_len + 1] = '\0';
  return packet;
}

size_t packet_size(struct PACKET *packet) {
  return(strlen(packet->dir) + strlen(packet->content)+ 1 + 1);
}

void icmp_send(int sockfd, struct in_addr *dest, struct PACKET *packet) {
    int nb;
    char buffer[DATA_SIZE]; 
    struct icmphdr *icmp_header;
    struct sockaddr_in addr;
    unsigned char *serialized_packet;

    int packet_len = packet_size(packet);

    if(sockfd < 0){
        perror("Could not allocate");
        exit(EXIT_FAILURE);
    }

    icmp_header = (struct icmphdr *)malloc(sizeof(struct icmphdr) + packet_len);
    if (icmp_header == NULL) {
        perror("Could not allocate icmp_header");
        exit(EXIT_FAILURE);
    }

    memset(icmp_header, 0, sizeof(icmp_header));
    icmp_header->type = ICMP_ECHOREPLY;
    icmp_header->un.echo.id = IDENTIFIER_ID; 
    icmp_header->un.echo.sequence = 0;
    icmp_header->checksum = 0;
    serialized_packet = serialize(packet);
    memcpy(icmp_header + 1, serialized_packet, packet_len);
    icmp_header->checksum = checksum(icmp_header, sizeof(struct icmphdr) + packet_len);

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = dest->s_addr;
    addr.sin_family = AF_INET;
    if (sendto(sockfd, icmp_header, sizeof(struct icmphdr) + packet_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
        perror("Could not send icmp packet");
        exit(EXIT_FAILURE);
    }
    free(icmp_header);
}

void icmp_listener(icmp_callback callback) {
    int sockfd, nb, segment_flag = 0, offset = 0;
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    struct PACKET *packet;
    unsigned char packet_buffer[DATA_SIZE];

    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0) {
        perror("Could not allocate");
        exit(EXIT_FAILURE);
    }

    while (1) {
        memset(packet_buffer, 0, DATA_SIZE);
        nb = read(sockfd, packet_buffer, DATA_SIZE-1);
        ip_header = (struct iphdr *)&packet_buffer;
        icmp_header = (struct icmphdr *)(ip_header + 1);
        if (icmp_header->un.echo.id == IDENTIFIER_ID) {
          unsigned char *data = packet_buffer + sizeof(struct iphdr) + sizeof(struct icmphdr);
          packet = deserialize(data);
          callback(packet, ip_header->saddr, sockfd);
          free(packet);
        }
    }
}

