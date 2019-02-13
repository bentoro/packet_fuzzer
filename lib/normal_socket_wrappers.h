#ifndef NORMAL_SOCKET_WRAPPERS_H
#define NORMAL_SOCKET_WRAPPERS_h

#include <stdbool.h>
#include <sys/socket.h>
#include <stdio.h>

bool send_normal_tcp_packet(int sending_socket, char *data, int length);
bool send_normal_udp_packet(int sending_socket, char *data, int length);

#endif
