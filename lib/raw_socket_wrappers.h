#ifndef RAW_SOCKET_WRAPPERS_H
#define RAW_SOCKET_WRAPPERS_H

#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>      //iphdr
#include <netinet/ip_icmp.h> //icmp
#include <netinet/tcp.h>     //tcphdr
#include <netinet/udp.h>     //udphdr
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#define IP4_HDRLEN 20 // Length of IPv4 Header
#define TCP_HDRLEN 20 // Length of TCP Header
#define UDP_HDRLEN 8  // Length of UDP Header
#define ICMP_HDRLEN 8 // Length of ICMP Header
#define SYN 0
#define ACK 1
#define SYNACK 2
#define FIN 3
#define RST 4
#define PSHACK 5
#define FINACK 6
#define TCP 7
#define UDP 8
#define ICMP 9


struct tcp_packet {
  struct ip iphdr;
  struct tcphdr tcphdr;
  char payload[BUFSIZ];
} tcp_packet;

struct udp_packet {
  struct ip iphdr;
  struct udphdr udphdr;
  char payload[BUFSIZ];
} udp_packet;

struct icmp_packet{
    struct ip iphdr;
    struct icmp icmphdr;
    char payload[BUFSIZ];
} icmp_packet;

struct packet_info {
  int protocol;
  int flag;
  int ack;
  int seq;
  int size; // amount of test cases
  /*struct tcp_packet *tcp_packet;
  struct udp_packet *udp_packet;
  struct icmp_packet *icmp_packet;*/
  bool threewayhandshake;
  bool endconnection;
};


uint8_t *packet;
struct tcp_packet *tcp_packets;
struct udp_packet *udp_packets;
struct icmp_packet *icmp_packets;
int src_port, dst_port;
struct addrinfo hints;
char *target, *src_ip, *dst_ip;
struct ifreq interface;
struct packet_info packet_info;
bool threewayhandshake;

uint16_t checksum(uint16_t *, int);
uint16_t udp4_checksum(struct ip iphdr, struct udphdr udphdr, uint8_t *payload,int payloadlen);
uint16_t icmp4_checksum(struct icmp icmphdr, uint8_t *payload, int payloadlen);
uint16_t tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload,int payloadlen);
int generate_rand(double value);
struct addrinfo set_hints(int family, int socktype, int flags);
struct ifreq search_interface(char *ifc);
char *resolve_host(char *target, struct addrinfo hints);
void send_raw_tcp_packet(struct ip ip, struct tcphdr tcphdr,char *data);
void send_raw_udp_packet(struct ip ip, struct udphdr udp, char *data);
//void send_raw_icmp_packet(uint8_t *packet, struct ip iphdr, struct icmp icmphdr,char *data);
void send_raw_icmp_packet( struct ip iphdr, struct icmp icmphdr,char *data);
struct ip build_ip_header(int IHL, int version, int tos, int len, int id, int flag1, int flag2, int flag3, int flag4, int ttl, int flag);
struct tcphdr build_tcp_header(int seq, int ack, int reserved, int offset,int flags, int window_size, int urgent);
struct udphdr build_udp_header(int payloadlen);
struct icmp build_icmp_header(int type, int code, int id, int seq);
void print_raw_ip_packet(struct ip ip);
void print_raw_tcp_packet(struct tcphdr tcphdr);
void print_raw_udp_packet();
void print_raw_icmp_packet();

#endif
