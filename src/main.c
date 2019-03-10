#include "../lib/libpcap.h"
#include "../lib/raw_socket_wrappers.h"
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

int main(int argc, char **argv) {
  int opt, line = 1, line_count = 0, casecount;
  FILE *config_file;
  char interface_name[BUFSIZ];
  char buffer[BUFSIZ];
  bool raw = false, tcp = false, udp = false, icmp = false, normal = true;

  target = (char *)calloc(40, sizeof(char));
  src_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
  dst_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));

  //Check if user is Root
  if (geteuid() != 0) {
    printf("Must run as root\n");
    exit(1);
  }

  while ((opt = getopt(argc, argv, "h:t:s:d:p:ri:x")) != -1) {
    switch (opt) {
    case 'h':
      //set source ip
      strncpy(src_ip, optarg, sizeof(INET_ADDRSTRLEN));
      printf("src_ip: %s\n",optarg);
      break;
    case 't':
      //set destination ip
      strncpy(dst_ip, optarg, sizeof(INET_ADDRSTRLEN));
      printf("dst_ip: %s\n",optarg);
      break;
    case 's':
      //set source port
      src_port = atoi(optarg);
      printf("src_port: %d\n",atoi(optarg));
      break;
    case 'd':
      //set destination port
      dst_port = atoi(optarg);
      printf("src_port: %d\n",atoi(optarg));
      break;
    case 'p':
      //determine protocol
      packet_info.protocol = atoi(optarg);
      if(atoi(optarg) == TCP){
         tcp = true;
      } else if(atoi(optarg) == UDP){
         udp = true;
      }else if(atoi(optarg) == ICMP){
         icmp = true;
      }
      printf("protocol: %d\n",atoi(optarg));
      break;
    case 'r':
      //determine if raw sockets are going to be used
      raw = true;
      normal = false;
      printf("raw: true\n");
      break;
    case 'i':
      strncpy(interface_name, optarg, sizeof(interface_name));
      interface = search_interface(interface_name);
      break;
    case 'x':
      // Interface to send packet through.
      interface = search_interface("wlp2s0");
      src_port = 8045;
      packet_info.protocol = UDP;
      printf("protocol: TCP\n");
      printf("src_port: %i\n", src_port);
      dst_port = 8045;
      printf("dst_port: %i\n",dst_port);
      strcpy(src_ip, "192.168.1.85");
      printf("src_ip: %s\n",src_ip);
      strcpy(target, "192.168.1.81");
      printf("dst_ip: %s\n",target);
      break;
    default: /* ? */
      print_usage();
      exit(1);
    }
  }
  if(normal && icmp){
      printf("If ICMP are to be used use normal sockets.\n");
      exit(0);
  }

  hints = set_hints(AF_INET, SOCK_STREAM, hints.ai_flags | AI_CANONNAME);
  // Resolve target using getaddrinfo().
  dst_ip = resolve_host(target, hints);
  // open config file
  config_file = fopen("config", "r");

  // TODO: add validation
  // check how many testcases to create
  while (fgets(buffer, sizeof(buffer), config_file) != NULL) {
    line_count++;
  }

  // check if the file does not have a total amount of lines divisible by 3
  if (line_count % 3 == 0) {
    printf("# test cases: %i \n\n", (line_count / 3));
    packet_info.size = (line_count/3);
    casecount = packet_info.size;
    rewind(config_file);
  } else {
    printf("Incorrect information too many lines in config file\n");
    exit(1);
  }


  // allocate space for the test cases
  if(packet_info.protocol == TCP){
      print_time();
      printf(" Allocated room for TCP packet\n");
      tcp_packets = calloc(1, sizeof(struct tcp_packet));
  }else if(packet_info.protocol == UDP){
      print_time();
      printf(" Allocated room for UDP packet\n");
      udp_packets = calloc(1, sizeof(struct udp_packet));
  }else if(packet_info.protocol == ICMP){
      print_time();
      printf(" Allocated room for ICMP packet\n");
      icmp_packets = calloc(1, sizeof(struct icmp_packet));
      packet = (uint8_t *)calloc(IP_MAXPACKET, sizeof(uint8_t));
  }

  while (fgets(buffer, sizeof(buffer), config_file) != NULL) {
    int temp[BUFSIZ];
    char payload[BUFSIZ];
    char value[BUFSIZ];
    buffer[strlen(buffer) - 1] = ' ';
    int counter = 0;
    //store one line at a time
    //printf("%s\n\n", buffer);
    if(line != 3){
        for (int i = 0; i < (int)strlen(buffer); i++) {
          // if the line only contains a space move on to next line
          if (strlen(buffer) == 1) {
            if (buffer[i] = ' ') {
              break;
            }
          }
          if (buffer[i] == ' ') {
              int ch = 0;
            // store the string before a space
            // check if the field should be fuzzed
            if(strcmp(value, "FUZZ") == 0){
                printf("FUZZ\n");
                ch = 1337;
            } else {
                ch = atoi(value);

            }
            temp[counter] = ch;
            //printf("%i\n", temp[counter]);
            memset(value, '\0', sizeof(value));
            counter++;
          } else {
            // concat the value in buffer to char
            strncat(value, &buffer[i], sizeof(buffer[i]));
          }
        }
    } else {
        strncpy(payload, buffer,sizeof(buffer));
    }
    //printf("first: %s\n",temp[0]);
    if(line ==  1){
          print_time();
          printf(" Test case #%i \n", (packet_info.size-casecount + 1));
          if(packet_info.protocol == TCP){
              tcp_packets[packet_info.size-casecount].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_time();
              printf(" IP Header filled \n");
              print_time();
              print_raw_ip_packet(tcp_packets[packet_info.size-casecount].iphdr);

          }else if(packet_info.protocol == UDP){
              udp_packets[packet_info.size-casecount].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_time();
              printf(" IP Header filled \n");
              print_time();
              print_raw_ip_packet(udp_packets[packet_info.size-casecount].iphdr);

          }else if(packet_info.protocol == ICMP){
              icmp_packets[packet_info.size-casecount].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_time();
              printf(" IP Header filled \n");
              print_time();
              print_raw_ip_packet(icmp_packets[packet_info.size-casecount].iphdr);

          }
          line++;
    } else if(line == 2){
          if(packet_info.protocol == TCP){
              tcp_packets[packet_info.size-casecount].tcphdr = build_tcp_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6]);
              print_time();
              printf(" TCP Header filled \n");
              print_time();
              print_raw_tcp_packet(tcp_packets[packet_info.size-casecount].tcphdr);

          }else if(packet_info.protocol == UDP){
              udp_packets[packet_info.size-casecount].udphdr = build_udp_header(temp[0]);
              print_time();
              printf(" UDP Header filled \n");
              print_time();
              print_raw_udp_packet(udp_packets[packet_info.size-casecount].udphdr);

          }else if(packet_info.protocol == ICMP){
              icmp_packets[packet_info.size-casecount].icmphdr = build_icmp_header(temp[0],temp[1],temp[2],temp[3]);
              print_time();
              printf(" ICMP Header filled \n");
              print_time();
              print_raw_icmp_packet(icmp_packets[packet_info.size-casecount].icmphdr);

          }
        line++;
    } else if(line == 3){
          if(payload[0] == ' '){
                  print_time();
                  printf("PAYLOAD IS EMPTY\n");
          } else {
          if(packet_info.protocol == TCP){
              strncpy(tcp_packets[packet_info.size-casecount].payload, payload,strlen(payload)-1);
              print_time();
              printf(" TCP Payload filled \n");
              print_time();
              printf(" Payload: %s\n", tcp_packets[packet_info.size-casecount].payload);
              print_time();
              send_raw_tcp_packet(tcp_packets[packet_info.size-casecount].iphdr, tcp_packets[packet_info.size-casecount].tcphdr, tcp_packets[packet_info.size-casecount].payload);
          }else if(packet_info.protocol == UDP){
              strncpy(udp_packets[packet_info.size-casecount].payload, payload, strlen(payload)-1);
              print_time();
              printf(" UDP Payload filled \n");
              print_time();
              printf(" Payload: %s\n", udp_packets[packet_info.size-casecount].payload);
              print_time();
              send_raw_udp_packet(udp_packets[packet_info.size-casecount].iphdr, udp_packets[packet_info.size-casecount].udphdr, udp_packets[packet_info.size-casecount].payload);
          }else if(packet_info.protocol == ICMP){
              strncpy(icmp_packets[packet_info.size-casecount].payload, payload, strlen(payload) -1);
              print_time();
              printf(" ICMP Payload filled \n");
              print_time();
              printf(" Payload: %s\n", icmp_packets[packet_info.size-casecount].payload);
              print_time();
              send_raw_icmp_packet(icmp_packets[packet_info.size-casecount].iphdr, icmp_packets[packet_info.size-casecount].icmphdr, icmp_packets[packet_info.size-casecount].payload);
          }

          }
        printf("\n");
        casecount--;
        line = 1;
    }
    // next line in the config file

  }
  //send_raw_tcp_packet(tcp_packets[packet_info.size].iphdr, tcp_packets[packet_info.size].tcphdr, tcp_packets[packet_info.size].payload);
  //send_raw_udp_packet(build_ip_header(5,4,0,28,0,0,0,0,0,255,UDP), build_udp_header(8), "HELLO");
  //send_raw_udp_packet(udp_packets[packet_info.size].iphdr, udp_packets[packet_info.size].udphdr, udp_packets[packet_info.size].payload);
  //send_raw_icmp_packet(build_ip_header(5,4,0,28, 0,0,0,0,0,255,ICMP), build_icmp_header(8, 0,1000,0), "hello");
  //send_raw_icmp_packet(icmp_packets[packet_info.size].iphdr, icmp_packets[packet_info.size].icmphdr, icmp_packets[packet_info.size].payload);
  //send_raw_udp_packet(packet_info.udp_packet[packet_info.size].iphdr, packet_info.udp_packet[packet_info.size].udphdr, packet_info.udp_packet[packet_info.size].payload);
  //send_raw_tcp_packet(0,0, "hello", SYN);
  /*send_raw_tcp_packet(0, 0, NULL, SYN);
  // TODO: Make the filter more specific
  threewayhandshake = false;
  packet_info = packet_capture("src 192.168.1.81 and dst 192.168.1.85 and tcp",packet_info);
  threewayhandshake = true;
  packet_info = packet_capture("src 192.168.1.81 and dst 192.168.1.85 and tcp",packet_info);*/
  // send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, 1, 1, "HELLO", ACK);
  // threewayhandshake = true;
  // send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 1, 1, ACK);
  // send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 0, 0, ACK);
  // packet_info = packet_capture("src 192.168.1.72 and dst 192.168.1.86 and
  // tcp", packet_info);

  //fclose(config_file);
  free(target);
  free(src_ip);
  free(dst_ip);
  return (0);
}
