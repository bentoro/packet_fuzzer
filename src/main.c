#include "../lib/libpcap.h"
#include "../lib/raw_socket_wrappers.h"
#include "../lib/normal_socket_wrappers.h"
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
  struct addrinfo hints, servinfo;
  struct sockaddr client; //for sending normal udp packets
  socklen_t client_addr_len; //for sending normal udp packets
  int opt, line = 1, line_count = 0, casecount, sending_socket;//for normal packets
  FILE *config_file;
  char interface_name[BUFSIZ];
  char buffer[BUFSIZ];
  bool raw = false, tcp = false, udp = false, icmp = false, normal = true;
  char string_port[BUFSIZ];

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
      strcpy(string_port, optarg);
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
      raw = false;
      normal = true;
      interface = search_interface("wlp2s0");
      src_port = 8045;
      packet_info.protocol = UDP;
      printf("protocol: TCP\n");
      printf("src_port: %i\n", src_port);
      dst_port = 8045;
      strcpy(string_port,"8045");
      printf("dst_port: %i\n",dst_port);
      strcpy(src_ip, "192.168.1.85");
      printf("src_ip: %s\n",src_ip);
      strcpy(target, "127.0.0.1");
      printf("dst_ip: %s\n",target);
      break;
    default: /* ? */
      print_usage();
      exit(1);
    }
  }
  if(raw){
      hints = set_hints(AF_INET, SOCK_STREAM, hints.ai_flags | AI_CANONNAME);
      // Resolve target using getaddrinfo().
      dst_ip = resolve_host(target, hints);
      // open config file
  }
  config_file = fopen("config", "r");

  // TODO: add validation
  // check how many testcases to create
  while (fgets(buffer, sizeof(buffer), config_file) != NULL) {
    line_count++;
  }

  // check if the file does not have a total amount of lines divisible by 3
  if(raw){
      if (line_count % 3 == 0) {
        printf("# test cases: %i \n\n", (line_count / 3));
        packet_info.size = (line_count/3);
      } else {
        printf("Incorrect information too many lines in config file\n");
        exit(1);
      }
  } else {
        printf("# test cases: %i \n\n", (line_count));
        packet_info.size = (line_count);
        line = 3;
  }
  casecount = packet_info.size;
  rewind(config_file);


  // allocate space for the test cases
  if(packet_info.protocol == TCP){
      printf("Allocated room for TCP\n\n");
      tcp_packets = calloc(1, sizeof(struct tcp_packet));
      if(normal){
        sending_socket = start_tcp_client(target, string_port);
      }
  }else if(packet_info.protocol == UDP){
      printf("Allocated room for UDP\n\n");
      udp_packets = calloc(1, sizeof(struct udp_packet));
      if(normal){
          hints = set_hints(AF_UNSPEC,SOCK_DGRAM, 0);
          servinfo = set_addr_info(target, string_port, hints);
          sending_socket = start_udp_client(target, string_port);
      }
  }else if(packet_info.protocol == ICMP){
      printf("Allocated room for ICMP\n\n");
      icmp_packets = calloc(1, sizeof(struct icmp_packet));
      packet = (uint8_t *)calloc(IP_MAXPACKET, sizeof(uint8_t));
  }

  //parse the config file for test cases
  while (fgets(buffer, sizeof(buffer), config_file) != NULL) {
    int temp[BUFSIZ];
    char payload[BUFSIZ];
    char value[BUFSIZ];
    buffer[strlen(buffer) - 1] = ' ';
    int counter = 0;
    //store one line at a time
    //printf("%s\n\n", buffer);
    if(line != 3 && !normal){
        for (int i = 0; i < (int)strlen(buffer); i++) {
          // if the line only contains a space move on to next line
          if (strlen(buffer) == 1) {
            if (buffer[i] = ' ') {
              break;
            }
          }
          if (buffer[i] == ' ') {
            // store the string before a space
            int ch = atoi(value);
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
          if(packet_info.protocol == TCP){
              printf("Filled IP Packet\n");
              tcp_packets[packet_info.size-casecount].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_raw_ip_packet(tcp_packets[packet_info.size-casecount].iphdr);

          }else if(packet_info.protocol == UDP){
              printf("FILLED IP PACKET\n");
              udp_packets[packet_info.size-casecount].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_raw_ip_packet(udp_packets[packet_info.size-casecount].iphdr);

          }else if(packet_info.protocol == ICMP){
              printf("FILLED IP PACKET\n");
              icmp_packets[packet_info.size-casecount].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_raw_ip_packet(icmp_packets[packet_info.size-casecount].iphdr);

          }
          line++;
    } else if(line == 2){
          if(packet_info.protocol == TCP){
              printf("FILLED TCP PACKET\n");
              tcp_packets[packet_info.size-casecount].tcphdr = build_tcp_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6]);
              print_raw_tcp_packet(tcp_packets[packet_info.size-casecount].tcphdr);

          }else if(packet_info.protocol == UDP){
              printf("FILLED UDP PACKET\n");
              udp_packets[packet_info.size-casecount].udphdr = build_udp_header(temp[0]);
              print_raw_udp_packet(udp_packets[packet_info.size-casecount].udphdr);

          }else if(packet_info.protocol == ICMP){
              printf("FILLED ICMP PACKET\n");
              icmp_packets[packet_info.size-casecount].icmphdr = build_icmp_header(temp[0],temp[1],temp[2],temp[3]);
              print_raw_icmp_packet(icmp_packets[packet_info.size-casecount].icmphdr);

          }
        line++;
    } else if(line == 3){
          if(payload[0] == ' '){
                  printf("PAYLOAD IS EMPTY\n");
          } else {
          if(packet_info.protocol == TCP){
              printf("FILLED TCP PAYLOAD\n");
              strncpy(tcp_packets[packet_info.size-casecount].payload, payload,strlen(payload)-1);
              printf("PAYLOAD: %s\n", tcp_packets[packet_info.size-casecount].payload);
              if(normal){
                  send_normal_tcp_packet(sending_socket, tcp_packets[packet_info.size-casecount].payload, strlen(tcp_packets[packet_info.size-casecount].payload));
              } else {
                  send_raw_tcp_packet(tcp_packets[packet_info.size-casecount].iphdr, tcp_packets[packet_info.size-casecount].tcphdr, tcp_packets[packet_info.size-casecount].payload);

              }
          }else if(packet_info.protocol == UDP){
              printf("FILLED UDP PAYLOAD\n");
              strncpy(udp_packets[packet_info.size-casecount].payload, payload, strlen(payload)-1);
              printf("PAYLOAD: %s\n", udp_packets[packet_info.size].payload);
              if(normal){
                  send_normal_udp_packet(sending_socket, udp_packets[packet_info.size-casecount].payload, strlen(udp_packets[packet_info.size-casecount].payload), servinfo.ai_addr, servinfo.ai_addrlen);
              } else {
                  send_raw_udp_packet(udp_packets[packet_info.size-casecount].iphdr, udp_packets[packet_info.size-casecount].udphdr, udp_packets[packet_info.size-casecount].payload);
              }
              }else if(packet_info.protocol == ICMP){
              printf("FILLED ICMP PAYLOAD\n");
              strncpy(icmp_packets[packet_info.size-casecount].payload, payload, strlen(payload) -1);
              printf("PAYLOAD: %s\n", icmp_packets[packet_info.size].payload);
              send_raw_icmp_packet(icmp_packets[packet_info.size-casecount].iphdr, icmp_packets[packet_info.size-casecount].icmphdr, icmp_packets[packet_info.size-casecount].payload);
              }

          }
        printf("\n");
        casecount--;
        if(!normal){
            line = 1;
        }
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
