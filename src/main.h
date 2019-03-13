#ifndef MAIN_H
#define MAIN_H

#include "../lib/libpcap.h"
#include "../lib/raw_socket_wrappers.h"
#include "../lib/normal_socket_wrappers.h"
#include "../lib/logging.h"
#include "../lib/fuzz.h"
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
       "\t-i  -   Interface to send packets\n"
       "\t-f  -   Feedback Algorithm\n"
       "\t-c  -   Number of testcases\n"
       "\t-i  -   Interface to send packets\n"
       "\t-x  -   Test\n");
}
struct addrinfo servinfo;
struct sockaddr client; //for sending normal udp packets
socklen_t client_addr_len; //for sending normal udp packets
int opt, line = 1, line_count = 0, casecount, sending_socket,bytes_receieved, total_testcases = 0, end = 1, current = 1;
FILE *config_file;
char interface_name[BUFSIZ];
char result[BUFSIZ];
char receieved_data[IP_MAXPACKET];
char filter[BUFSIZ];
char buffer[BUFSIZ];
bool raw = false, tcp = false, udp = false, icmp = false, normal = true, feedback = false, custom = true, complete = false;
char string_port[BUFSIZ];

#endif