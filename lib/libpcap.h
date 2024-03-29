#ifndef LIBPCAP_H
#define LIBPCAP_H

#include "raw_socket_wrappers.h"
#include "logging.h"
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h> //icmp
#include <netinet/ip.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <pcap.h>

#define SIZE_ETHERNET 14
pcap_t *interfaceinfo;

struct packet_info packet_capture(char *FILTER, struct packet_info packet_info);
void read_packet(u_char *args, const struct pcap_pkthdr *pkthdr,const u_char *packet);
void parse_ip(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet);
void parse_tcp(struct packet_info *packet_info,const struct pcap_pkthdr *pkthdr, const u_char *packet);
void parse_udp(struct packet_info *packet_info,const struct pcap_pkthdr *pkthdr, const u_char *packet);
void parse_icmp(struct packet_info *packet_info,const struct pcap_pkthdr *pkthdr, const u_char *packet);
void parse_payload(struct packet_info *packet_info, const u_char *payload,int len);
void create_filter(char *FILTER);
#endif
