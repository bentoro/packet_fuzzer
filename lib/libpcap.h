#ifndef LIBPCAP_H
#define LIBPCAP_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include "raw_socket_wrappers.h"


int packet_capture(char *FILTER, struct packet_info packet_info);
void read_packet(u_char *args, const struct pcap_pkthdr *pkthdr,const u_char *packet);
void parse_ip(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet);
void parse_tcp(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet);
void parse_payload(struct packet_info *packet_info, const u_char *payload, int len);
#endif
