#include "main.h"

int main(int argc, char **argv) {
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
      raw = true;
      normal = false;
      interface = search_interface("wlp2s0");
      src_port = 8045;
      packet_info.protocol = ICMP;
      printf("protocol: UDP\n");
      printf("src_port: %i\n", src_port);
      dst_port = 8045;
      strcpy(string_port,"8045");
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
  if(raw){
      print_time();
      create_filter(filter);
      hints = set_hints(AF_INET, SOCK_STREAM, 0);
      // Resolve target using getaddrinfo().
      dst_ip = resolve_host(target, hints);
      // open config file
  }else if(normal && icmp){
      printf("If ICMP are to be used use normal sockets.\n");
      exit(0);
  }

  // open config file
  config_file = fopen("config", "r");
  replay = false;
  // TODO: add validation
  // check how many testcases to create
  while (fgets(buffer, sizeof(buffer), config_file) != NULL) {
    line_count++;
  }

  // check if the file does not have a total amount of lines divisible by 3
  if(normal){
        printf("# test cases: %i \n\n", (line_count));
        packet_info.size = (line_count);
        line = 3;
  } else {
          if (line_count % 3 == 0) {
            printf("# test cases: %i \n\n", (line_count / 3));
            packet_info.size = (line_count/3);
          } else {
            printf("Incorrect information too many lines in config file\n");
            exit(1);
          }
  }
  casecount = packet_info.size;
  rewind(config_file);


  // allocate space for the test cases
  if(packet_info.protocol == TCP){
      print_time();
      printf(" Allocated room for TCP packet\n");
      tcp_packets = calloc(1, sizeof(struct tcp_packet));
      if(normal){
        print_time();
        sending_socket = start_tcp_client(target, string_port);
      }
  }else if(packet_info.protocol == UDP){
      print_time();
      printf(" Allocated room for UDP packet\n");
      udp_packets = calloc(1, sizeof(struct udp_packet));
      if(normal){
          print_time();
          hints = set_hints(AF_UNSPEC,SOCK_DGRAM, 0);
          servinfo = set_addr_info(target, string_port, hints);
          sending_socket = start_udp_client(target, string_port);
      }
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
    if(line != 3 && !normal){
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
              memset(tcp_packets,'\0',sizeof(tcp_packet));
              tcp_packets[packet_info.size-casecount].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_time();
              printf(" IP Header filled \n");
              print_time();
              print_raw_ip_packet(tcp_packets[packet_info.size-casecount].iphdr);

          }else if(packet_info.protocol == UDP){
              memset(udp_packets,'\0',sizeof(udp_packet));
              udp_packets[packet_info.size-casecount].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_time();
              printf(" IP Header filled \n");
              print_time();
              print_raw_ip_packet(udp_packets[packet_info.size-casecount].iphdr);

          }else if(packet_info.protocol == ICMP){
              memset(icmp_packets,'\0',sizeof(icmp_packet));
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
replaypacket:
          if(payload[0] == ' '){
                  print_time();
                  printf("PAYLOAD IS EMPTY\n");
          } else {
          if(packet_info.protocol == TCP){
              if(normal){
                  print_time();
                  printf(" Test case #%i \n", (packet_info.size-casecount + 1));
              }
              strncpy(tcp_packets[packet_info.size-casecount].payload, payload,strlen(payload)-1);
              print_time();
              printf(" TCP Payload filled \n");
              print_time();
              printf(" Normal TCP Packet sent to %s - Payload: %s\n", target,tcp_packets[packet_info.size-casecount].payload);
              if(normal){
                  print_time();
                  send_normal_tcp_packet(sending_socket, tcp_packets[packet_info.size-casecount].payload, strlen(tcp_packets[packet_info.size-casecount].payload));
                  bytes_receieved = recv(sending_socket, receieved_data, sizeof(receieved_data),0);
                  printf(" Received: %s \n", receieved_data);
                  memset(receieved_data, '\0', sizeof(receieved_data));
              } else {
                  print_time();
                  send_raw_tcp_packet(tcp_packets[packet_info.size-casecount].iphdr, tcp_packets[packet_info.size-casecount].tcphdr, tcp_packets[packet_info.size-casecount].payload);
              }
          }else if(packet_info.protocol == UDP){
              if(normal){
                  print_time();
                  printf(" Test case #%i \n", (packet_info.size-casecount + 1));
              }
              strncpy(udp_packets[packet_info.size-casecount].payload, payload, strlen(payload)-1);
              print_time();
              printf(" UDP Payload filled \n");
              print_time();
              printf(" Normal Packet sent to %s - Payload: %s\n", target,udp_packets[packet_info.size-casecount].payload);

              if(normal){
                  send_normal_udp_packet(sending_socket, udp_packets[packet_info.size-casecount].payload, strlen(udp_packets[packet_info.size-casecount].payload), servinfo.ai_addr, servinfo.ai_addrlen);
                  bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                  print_time();
                  printf(" Received: %s \n", receieved_data);
                  memset(receieved_data, '\0', sizeof(receieved_data));
              } else {
                  print_time();
                  send_raw_udp_packet(udp_packets[packet_info.size-casecount].iphdr, udp_packets[packet_info.size-casecount].udphdr, udp_packets[packet_info.size-casecount].payload);
              }
          }else if(packet_info.protocol == ICMP){
              strncpy(icmp_packets[packet_info.size-casecount].payload, payload, strlen(payload) -1);
              print_time();
              printf(" ICMP Payload filled \n");
              print_time();
              printf(" Payload: %s\n", icmp_packets[packet_info.size-casecount].payload);
              print_time();
              send_raw_icmp_packet(icmp_packets[packet_info.size-casecount].iphdr, icmp_packets[packet_info.size-casecount].icmphdr, icmp_packets[packet_info.size-casecount].payload);
              packet_info = packet_capture(filter, packet_info);
              if(replay == true){
                replay = false;
                goto replaypacket;
              }
          }

          }
        printf("\n");
        casecount--;
        if(!normal){
            line = 1;
        }
    }
  }
  //fclose(config_file);
  free(target);
  free(src_ip);
  free(dst_ip);
  return (0);
}
