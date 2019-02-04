#ifndef RAW_SOCKET_WRAPPERS_H
#define RAW_SOCKET_WRAPPERS_H


#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>


#define IP4_HDRLEN 20 // Length of IPv4 Header
#define TCP_HDRLEN 20 // Length of TCP Header
#define SYN 0
#define ACK 1
#define SYNACK 2
#define FIN 3
#define RST 4
#define PSHACK 5
#define TCP 7
#define UDP 8
#define ICMP 9

struct packet_info{
    int protocol;
    int flag;
    int ack;
    int seq;
    int src_port;
    int dst_port;
    bool threewayhandshake;
    bool endconnection;
};

struct tcp_packet {
  struct ip iphdr;
  struct tcphdr tcphdr;
  unsigned char payload[BUFSIZ];
} tcp_packet;

uint16_t checksum(uint16_t *, int);
uint16_t tcp4_checksum(struct ip, struct tcphdr);
int generate_rand(double value);
struct addrinfo set_hints(int family, int socktype, int flags);
struct ifreq search_interface(char *ifc);
char *resolve_host(char *target, struct addrinfo hints);
void send_raw_tcp_packet(int src_port, int dst_port, struct ifreq interface, char* src_ip, char* dst_ip, int seq, int ack, int flags);

#endif
