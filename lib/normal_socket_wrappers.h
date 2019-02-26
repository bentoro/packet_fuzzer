#ifndef NORMAL_SOCKET_WRAPPERS_H
#define NORMAL_SOCKET_WRAPPERS_H

#include <stdbool.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>

#define MAXCONNECTION 128

struct addrinfo set_hints(int family, int socktype, int flags);
struct addrinfo set_addr_info(const char* address, const char *port, struct addrinfo hints);
int set_bind(int fd, struct addrinfo *p);
void set_listen(int fd);
int make_bind(const char *port);
int make_connect(const char *address, const char *port);
int Accept(int fd, struct sockaddr_storage *addr);
void send_normal_tcp_packet(int sending_socket, char *data, int length);
void send_normal_udp_packet(int sending_socket, char *data, int length, const struct sockaddr *dest_addr, socklen_t dest_len);
void recv_normal_tcp_packet(int socket, char *buf, size_t bufsize);
void recv_normal_udp_packet(int socket, char *buf, size_t bufsize, struct sockaddr_in client, socklen_t client_addr_len);

#endif
