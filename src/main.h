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
#include <getopt.h>

static void print_usage(void) {
  puts("Usage options: \n"
       "\t-h  -   Host machine ip \n"
       "\t-t  -   Target machine ip\n"
       "\t-s  -   Source port\n"
       "\t-d  -   Destination port\n"
       "\t-p  -   Protocol type, TCP = 7, UDP = 8, ICMP = 9\n"
       "\t-i  -   Interface to send packets\n"
       "\t-c  -   Number of testcases\n"
       "\t-f  -   Fuzz ratio\n"
       "\t-x  -   Test\n");
}


static struct option long_options[] = {
    {"saddr",         required_argument,  0,  0 },
    {"daddr",         required_argument,  0,  1 },
    {"sport",         required_argument,  0,  2 },
    {"dport",         required_argument,  0,  3 },
    {"proto",         required_argument,  0,  4 },
    {"raw",           optional_argument,  0,  5 },
    {"nic",           required_argument,  0,  6 },
    {"testcases",     required_argument,  0,  7 },
    {"fuzz",          optional_argument,  0,  8 },
    {"query",         required_argument,  0,  9 },
    {0,               0,                  0,  0 }
};

struct timespec delay, resume_delay;
struct addrinfo servinfo;
struct sockaddr client; //for sending normal udp packets
struct sockaddr_in rawclient; //for receiving icmp packets
socklen_t client_addr_len; //for sending normal udp packets
int opt, line = 1, line_count = 0, sending_socket,bytes_receieved, total_testcases = 0, current = 1,size = 1;
FILE *config_file;
char interface_name[BUFSIZ];
char result[BUFSIZ];
char receieved_data[IP_MAXPACKET];
char buffer[BUFSIZ];
char protocol[BUFSIZ];
char packet_buffer[IP_MAXPACKET];
bool raw = false, tcp = false, udp = false, icmp = false, normal = true, feedback = false, custom = true, complete = false, ifempty = false;
char string_port[BUFSIZ];

#endif
