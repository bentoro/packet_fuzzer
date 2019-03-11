#ifndef MAIN_H
#define MAIN_H

#include "../lib/libpcap.h"
#include "../lib/raw_socket_wrappers.h"
#include "../lib/normal_socket_wrappers.h"
#include "../lib/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(void) {
  puts("Usage options: \n"
       "\t-h  -   Host machine ip \n"
       "\t-t  -   Target machine ip\n"
       "\t-s  -   Source port\n"
       "\t-d  -   Destination port\n"
       "\t-p  -   Protocol type, TCP = 7, UDP = 8, ICMP = 9\n"
       "\t-r  -   Raw sockets (if false normal sockets will be used)\n"
       "\t-i  -   Interface to send packets\n"
       "\t-x  -   Test\n");
}
struct addrinfo servinfo;
struct sockaddr client; //for sending normal udp packets
socklen_t client_addr_len; //for sending normal udp packets
int opt, line = 1, line_count = 0, casecount, sending_socket,bytes_receieved;
FILE *config_file;
char interface_name[BUFSIZ];
char receieved_data[BUFSIZ];
char filter[BUFSIZ];
char buffer[BUFSIZ];
bool raw = false, tcp = false, udp = false, icmp = false, normal = true;
char string_port[BUFSIZ];

#endif
