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

struct packet_info {
  int protocol;
  int flag;
  int ack;
  int seq;
  int src_port;
  int dst_port;
  int size; // amount of test cases
  bool threewayhandshake;
  bool endconnection;
};

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

int seq, src_port, dst_port;
struct addrinfo hints;
struct tcp_packet *testcases;
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
void send_raw_tcp_packet(int seq, int ack,char *data, int flags);
void send_raw_udp_packet(int seq, int ack,char *data, int flags);
void send_raw_icmp_packet(int seq, int ack,char *data, int flags);
struct ip build_ip_header(int IHL, int version, int tos, int len, int id, int flag1, int flag2, int flag3, int flag4, int ttl, int flag);
struct tcphdr build_tcp_header(int src_port, int dst_port, int seq, int ack, int reserved, int offset,int flags, int window_size, int urgent);
struct udphdr build_udp_header(int payloadlen);
struct icmp build_icmp_header(int type, int code, int id, int seq);

#endif
