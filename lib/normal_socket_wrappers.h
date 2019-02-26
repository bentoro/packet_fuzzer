#ifndef NORMAL_SOCKET_WRAPPERS_H
#define NORMAL_SOCKET_WRAPPERS_H

#include <stdbool.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/ip.h>

void send_normal_tcp_packet(int sending_socket, char *data, int length);
void send_normal_udp_packet(int sending_socket, char *data, int length, const struct sockaddr *dest_addr, socklen_t dest_len);
void recv_normal_tcp_packet(int socket, char *buf, size_t bufsize);
void recv_normal_udp_packet(int socket, char *buf, size_t bufsize, struct sockaddr_in client, socklen_t client_addr_len);

#endif
