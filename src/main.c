#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/libpcap.h"
#include "../lib/raw_socket_wrappers.h"

int main(int argc, char **argv) {

  if(geteuid() != 0) {
    printf("Must run as root\n");
    exit(1);
  }
  int recv_socket, bytes_recv;
  char data[BUFSIZ];

  target = (char *) calloc (40, sizeof(char));
  src_ip = (char *) calloc (INET_ADDRSTRLEN, sizeof(char));
  dst_ip = (char *) calloc (INET_ADDRSTRLEN, sizeof(char));

  // Interface to send packet through.
  ifr = search_interface("wlp2s0");

  strcpy (src_ip, "192.168.1.85");
  strcpy (target, "192.168.1.81");
  hints = set_hints(AF_INET, SOCK_STREAM, hints.ai_flags | AI_CANONNAME);
  // Resolve target using getaddrinfo().
  dst_ip = resolve_host(target, hints);
  send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, 0, 0, NULL, SYN);
  //receive with raw sockets
  send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, 0, 0, NULL, SYN);
  //TODO: Make the filter more specific
  threewayhandshake = false;
  packet_info = packet_capture("src 192.168.1.81 and dst 192.168.1.85 and tcp", packet_info);
  int sock,packet_size;
  unsigned char *buffer = (unsigned char *)malloc(65536);
  struct sockaddr_in source_socket_address, dest_socket_address;
  if(sock = socket (PF_INET, SOCK_RAW, IPPROTO_TCP) == -1){
        perror("Failed to create socket");
        exit(1);
    }
  // recvfrom is used to read data from a socket
  packet_size = recvfrom(sock , buffer , 65536 , 0 , NULL, NULL);
  if (packet_size == -1) {
    printf("Failed to get packets\n");
    return 1;
  }

  struct iphdr *ip_packet = (struct iphdr *)buffer;

  memset(&source_socket_address, 0, sizeof(source_socket_address));
  source_socket_address.sin_addr.s_addr = ip_packet->saddr;
  memset(&dest_socket_address, 0, sizeof(dest_socket_address));
  dest_socket_address.sin_addr.s_addr = ip_packet->daddr;

  printf("Incoming Packet: \n");
  printf("Packet Size (bytes): %d\n",ntohs(ip_packet->tot_len));
  printf("Source Address: %s\n", (char *)inet_ntoa(source_socket_address.sin_addr));
  printf("Destination Address: %s\n", (char *)inet_ntoa(dest_socket_address.sin_addr));
  printf("Identification: %d\n\n", ntohs(ip_packet->id));
  threewayhandshake = true;
  //packet_info = packet_capture("src 192.168.1.81 and dst 192.168.1.85 and tcp", packet_info);
  //send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, (ntohl(6)), (ntohl(6)),NULL, FINACK);
  //sleep(1);
  //send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, (ntohl(packet_info.seq)), (ntohl(packet_info.ack)), "HELLO", PSHACK);
    /*if((recv_socket = socket(AF_INET, SOCK_RAW, 0)) < 0) {
        perror("receiving socket failed to open (root maybe required)");
    }

    bytes_recv = recv(recv_socket, data, sizeof(data), 0);
    printf("data: %s\n", data);
    */
  //send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, 1, 1, "HELLO", ACK);
  //threewayhandshake = true;
  //send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 1, 1, ACK);
  //send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 0, 0, ACK);
  //packet_info = packet_capture("src 192.168.1.72 and dst 192.168.1.86 and tcp", packet_info);
  return (0);
}

