#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/libpcap.h"
#include "../lib/raw_socket_wrappers.h"

int main(int argc, char **argv) {
  struct packet_info packet_info;
  struct addrinfo hints;
  char *target, *src_ip, *dst_ip;
  struct ifreq ifr;

  if(geteuid() != 0) {
    printf("Must run as root\n");
    exit(1);
  }

  target = (char *) calloc (40, sizeof(char));
  src_ip = (char *) calloc (INET_ADDRSTRLEN, sizeof(char));
  dst_ip = (char *) calloc (INET_ADDRSTRLEN, sizeof(char));

  // Interface to send packet through.
  ifr = search_interface("wlp2s0");

  strcpy (src_ip, "192.168.1.86");
  strcpy (target, "192.168.1.72");
  hints = set_hints(AF_INET, SOCK_STREAM, hints.ai_flags | AI_CANONNAME);

  // Resolve target using getaddrinfo().
  dst_ip = resolve_host(target, hints);
  packet_info.ack = 9;
  packet_info.seq = 9;
  packet_info.protocol = TCP;
  send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 0, 0, SYN);
  packet_capture("host 192.168.1.72 and tcp", packet_info);
  printf("ack: %d\n",packet_info.ack);
  printf("seq: %d\n",packet_info.seq);
  //send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 1, 1, ACK);
  //Packetcapture("host 192.168.1.72 and tcp");
  return (0);
}

