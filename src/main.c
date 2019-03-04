#include "../lib/libpcap.h"
#include "../lib/raw_socket_wrappers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(void) {
  puts("Usage options: \n"
       "\t-h  -   Host machine ip \n"
       "\t-t  -   Target machine ip\n"
       "\t-s  -   Source port\n"
       "\t-d  -   Destination port\n"
       "\t-p  -   Protocol type, 0 = TCP, 1 = UDP, 2 = ICMP \n"
       "\t-r  -   Raw sockets\n"
       "\t-i  -   Interface\n");
}

int main(int argc, char **argv) {
  FILE *config_file;
  char buffer[BUFSIZ];
  int opt, line_count = 0;
  bool raw = false;
  bool normal = false;
  bool tcp = false;
  bool udp = false;
  //char interface_name[BUFSIZ];
  char value[BUFSIZ];

  target = (char *)calloc(40, sizeof(char));
  src_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
  dst_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));

  if (geteuid() != 0) {
    printf("Must run as root\n");
    exit(1);
  }
  /*
  while ((opt = getopt(argc, argv, "h:t:s:d:p:r:")) != -1) {
    switch (opt) {
    case 'h':
      strncpy(src_ip, optarg, sizeof(INET_ADDRSTRLEN));
      break;
    case 't':
      strncpy(dst_ip, optarg, sizeof(INET_ADDRSTRLEN));
      break;
    case 's':
      src_port = atoi(optarg);
      break;
    case 'd':
      dst_port = atoi(optarg);
      break;
    case 'p':
      packet_info.protocol = atoi(optarg);
      break;
    case 'r':
      raw = true;
      break;
    case 'i':
      strncpy(interface, optarg, sizeof(interface));
      ifr = search_interface("wlp2s0");
      break;
    default: /* ? 
      print_usage();
      exit(1);
    }
  }

  // open config file
  config_file = fopen("config", "r");

  // TODO: add validation
  // check how many testcases to create
  while (fgets(buffer, sizeof(buffer), config_file) != NULL) {
    line_count++;
  }

  // check if the file does not have a total amount of lines divisible by 3
  if (line_count % 3 == 0) {
    printf("# test cases: %i\n", (line_count / 3));
    rewind(config_file);
  } else {
    printf("Incorrect information too many lines in config file\n");
    exit(1);
  }

  // allocate space for the test cases
  testcases = calloc((line_count / 2), sizeof(tcp_packet));

  while (fgets(buffer, sizeof(buffer), config_file) != NULL) {
    buffer[strlen(buffer) - 1] = ' ';

    for (int i = 0; i < (int)strlen(buffer); i++) {
      // if the line only contains a space move on to next line
      if (strlen(buffer) == 1) {
        if (buffer[i] = ' ') {
          break;
        }
      }
      if (buffer[i] == ' ') {
        // store the string before a space
        printf("%s\n", value);
        memset(value, '\0', sizeof(value));
      } else {
        // concat the value in buffer to char
        strncat(value, &buffer[i], sizeof(buffer[i]));
      }
    }
    // next line in the config file
  }
  fclose(config_file);*/

  // Interface to send packet through.
  interface = search_interface("wlp2s0");
  src_port = 100;
  dst_port = 8045;
  strcpy(src_ip, "192.168.1.85");
  strcpy(target, "192.168.1.81");
  hints = set_hints(AF_INET, SOCK_STREAM, hints.ai_flags | AI_CANONNAME);
  // Resolve target using getaddrinfo().
  dst_ip = resolve_host(target, hints);
  send_raw_tcp_packet(0, 0, NULL, SYN);
  // TODO: Make the filter more specific
  threewayhandshake = false;
  packet_info = packet_capture("src 192.168.1.81 and dst 192.168.1.85 and tcp",packet_info);
  threewayhandshake = true;
  packet_info = packet_capture("src 192.168.1.81 and dst 192.168.1.85 and tcp",packet_info);
  // send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, 1, 1, "HELLO", ACK);
  // threewayhandshake = true;
  // send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 1, 1, ACK);
  // send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 0, 0, ACK);
  // packet_info = packet_capture("src 192.168.1.72 and dst 192.168.1.86 and
  // tcp", packet_info);
  return (0);
}
