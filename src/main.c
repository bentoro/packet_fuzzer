#include "main.h"

int main(int argc, char **argv) {
  struct timespec tim, tim2;
  tim.tv_sec  = 0;
  tim.tv_nsec = 500000000L;
  target = (char *)calloc(40, sizeof(char));
  src_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
  dst_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
  //Check if user is Root
  if (geteuid() != 0) {
    printf("Must run as root\n");
    exit(1);
  }

  while ((opt = getopt(argc, argv, "h:t:s:d:p:rifc:x")) != -1) {
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
      strcpy(string_port, optarg);
      printf("dst_port: %d\n",atoi(optarg));
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
      raw = true;
      normal = false;
      printf("raw: true\n");
      break;
    case 'i':
      strncpy(interface_name, optarg, sizeof(interface_name));
      interface = search_interface(interface_name);
      break;
    case 'f':
      feedback = true;
      custom = false;
      printf("Feedback Algorithm: true\n");
      break;
    case 'c':
      total_testcases = atoi(optarg);
      printf("Total # of testcaes: %i\n",atoi(optarg));
      break;
    case 'x':
      // Interface to send packet through.
      feedback = true;
      custom = false;
      raw = true;
      normal = false;
      interface = search_interface("wlp2s0");
      src_port = 8045;
      strcpy(result,"HELLO");
      packet_info.protocol = TCP;
      printf("protocol: UDP\n");
      printf("src_port: %i\n", src_port);
      dst_port = 8045;
      //changed source port
      printf("dst_port: %i\n",dst_port);
      strcpy(string_port,"8045");
      strcpy(src_ip, "192.168.1.85");
      printf("src_ip: %s\n",src_ip);
      strcpy(target, "192.168.1.81");
      printf("dst_ip: %s\n",target);
      break;
    default:  /*?*/
      print_usage();
      exit(1);
    }
  }

  total_testcases = 10;
  set_fuzz_ratio(0.50);

  if(raw){
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
  rewind(config_file);
  // allocate space for the test cases
  if(packet_info.protocol == TCP){
      print_time();
      printf(" Allocated room for TCP packet\n");
      //Allocate atleast half of the total test cases
      tcp_packets = calloc(((total_testcases)/2)+1, sizeof(struct tcp_packet));
      sending_socket = start_tcp_raw_client();
      three_way_handshake(sending_socket);
      if(normal){
        print_time();
        sending_socket = start_tcp_client(target, string_port);
      }
  }else if(packet_info.protocol == UDP){
      print_time();
      printf(" Allocated room for UDP packet\n");
      //Allocate atleast half of the total test cases
      udp_packets = calloc((total_testcases)/2, sizeof(struct udp_packet));
      sending_socket = start_udp_server(src_port);
      if(normal){
          print_time();
          hints = set_hints(AF_UNSPEC,SOCK_DGRAM, 0);
          servinfo = set_addr_info(target, string_port, hints);
          sending_socket = start_udp_client(target, string_port);
      }
  }else if(packet_info.protocol == ICMP){
      print_time();
      printf(" Allocated room for ICMP packet\n");
      sending_socket = start_icmp_client();
	  client_addr_len = sizeof(icmpclient);
      //Allocate atleast half of the total test cases
      icmp_packets = calloc((total_testcases)/2, sizeof(struct icmp_packet));
      packet = (uint8_t *)calloc(IP_MAXPACKET, sizeof(uint8_t));
      sending_socket = start_icmp_client();
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
          printf(" Test case #%i \n", (casecount + 1));
          if(packet_info.protocol == TCP){
              memset(tcp_packets,'\0',sizeof(tcp_packet));
              tcp_packets[0].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_time();
              printf(" IP Header filled \n");
              print_time();
              print_raw_ip_packet(tcp_packets[0].iphdr);

          }else if(packet_info.protocol == UDP){
              memset(udp_packets,'\0',sizeof(udp_packet));
              udp_packets[0].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_time();
              printf(" IP Header filled \n");
              print_time();
              print_raw_ip_packet(udp_packets[0].iphdr);

          }else if(packet_info.protocol == ICMP){
              memset(icmp_packets,'\0',sizeof(icmp_packet));
              icmp_packets[0].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              print_time();
              printf(" IP Header filled \n");
              print_time();
              print_raw_ip_packet(icmp_packets[0].iphdr);

          }
          line++;
    } else if(line == 2){
          if(packet_info.protocol == TCP){
              if((casecount + 1) == 1){
                //first packet seq = seq and ack = ack
                tcp_packets[0].tcphdr = build_tcp_header((packet_info.seq), (packet_info.ack),temp[2],temp[3],temp[4],temp[5],temp[6]);
              } else {
                //consecutive packets seq = ack and ack = seq
                tcp_packets[0].tcphdr = build_tcp_header((packet_info.ack), (packet_info.seq),temp[2],temp[3],temp[4],temp[5],temp[6]);
              }
              print_time();
              printf(" TCP Header filled \n");
              print_time();
              print_raw_tcp_packet(tcp_packets[0].tcphdr);

          }else if(packet_info.protocol == UDP){
              udp_packets[0].udphdr = build_udp_header(temp[0]);
              print_time();
              printf(" UDP Header filled \n");
              print_time();
              print_raw_udp_packet(udp_packets[0].udphdr);
          }else if(packet_info.protocol == ICMP){
              icmp_packets[0].icmphdr = build_icmp_header(temp[0],temp[1],temp[2],temp[3]);
              print_time();
              printf(" ICMP Header filled \n");
              print_time();
              print_raw_icmp_packet(icmp_packets[0].icmphdr);
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
                  printf(" Test case #%i \n", (casecount + 1));
              }
              strncpy(tcp_packets[0].payload, payload,strlen(payload)-1);
              print_time();
              printf(" TCP Payload filled \n");
              print_time();
              printf(" TCP Packet sent to %s - Payload: %s\n", target,tcp_packets[0].payload);
              if(normal){
                  print_time();
                  send_normal_tcp_packet(sending_socket, tcp_packets[0].payload, strlen(tcp_packets[0].payload));
                  bytes_receieved = recv(sending_socket, receieved_data, sizeof(receieved_data),0);
                  printf(" Received: %s \n", receieved_data);
                  memset(receieved_data, '\0', sizeof(receieved_data));
              } else {
                  print_time();
                  send_raw_tcp_packet(tcp_packets[0].iphdr, tcp_packets[0].tcphdr, tcp_packets[0].payload);
                  recv_data = false;
                  while(recv_data == false){
                      if(recvfrom(sending_socket, packet_buffer, sizeof(packet_buffer), 0, (struct sockaddr*)&icmpclient, &client_addr_len) < 0){
                          perror("recvfrom");
                        } else{
                            strcpy(receieved_data,recv_tcp_packet(packet_buffer));
                        }
                  }
                  printf("payload: %s\n", receieved_data);
                  if(search(receieved_data, result, sizeof(result))){
                      printf("Found matching string\n");
                      tcp_packets[end] = tcp_packets[0];
                      print_time();
                      print_tcp_packet(tcp_packets[end]);
                      end++;
                  }
                  memset(receieved_data, '\0', sizeof(receieved_data));
                  memset(packet_buffer, '\0', sizeof(packet_buffer));
              }
          }else if(packet_info.protocol == UDP){
              if(normal){
                  print_time();
                  printf(" Test case #%i \n", (casecount + 1));
              }
              strncpy(udp_packets[0].payload, payload, strlen(payload)-1);
              print_time();
              printf(" UDP Payload filled \n");
              print_time();
              printf(" UDP Packet sent to %s - Payload: %s\n", target,udp_packets[0].payload);

              if(normal){
                  send_normal_udp_packet(sending_socket, udp_packets[0].payload, strlen(udp_packets[0].payload), servinfo.ai_addr, servinfo.ai_addrlen);
                  bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                  print_time();
                  printf(" Received: %s \n", receieved_data);
                  memset(receieved_data, '\0', sizeof(receieved_data));
              } else {
                  print_time();
                  send_raw_udp_packet(udp_packets[0].iphdr, udp_packets[0].udphdr, udp_packets[0].payload);
                  memset(receieved_data,'\0', sizeof(receieved_data));
                  bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                  print_time();
                  printf(" Received: %s \n", receieved_data);
                  if(search(receieved_data, result, sizeof(result))){
                      printf("Found matching string\n");
                      udp_packets[end] = udp_packets[0];
                      print_time();
                      print_udp_packet(udp_packets[end]);
                      end++;
                  }
                  memset(receieved_data, '\0', sizeof(receieved_data));
              }
          }else if(packet_info.protocol == ICMP){
              strncpy(icmp_packets[0].payload, payload, strlen(payload) -1);
              print_time();
              printf(" ICMP Payload filled \n");
              print_time();
              printf(" Payload: %s\n", icmp_packets[0].payload);
              print_time();
              send_raw_icmp_packet(icmp_packets[0].iphdr, icmp_packets[0].icmphdr, icmp_packets[0].payload);
              memset(receieved_data,'\0', sizeof(receieved_data));
              if(recvfrom(sending_socket, receieved_data, sizeof(receieved_data), 0, (struct sockaddr*)&icmpclient, &client_addr_len) < 0){
                    perror("recvfrom");
              } else {
                    strcpy(receieved_data,recv_icmp_packet(receieved_data));
              }
              print_time();
              printf(" Received: %s \n", receieved_data);
              if(replay == true){
                replay = false;
                goto replaypacket;
              } else {
                  if(search(receieved_data, result, sizeof(result))){
                      printf("Found matching string\n");
                      icmp_packets[end] = icmp_packets[0];
                      print_time();
                      print_icmp_packet(icmp_packets[end]);
                      end++;
                  }
              }
          }
          }
        printf("\n");
        casecount++;
        if(!normal){
            line = 1;
        }
    }
  }

  while(!complete){
      printf("CURRENT: %i\n", current);
      printf("END: %i\n", end);
      if(total_testcases != casecount){
              print_time();
              printf(" Test case #%i \n", (casecount + 1));
          if(packet_info.protocol == TCP){
              if(current == end){
                //no more items in the queue
                tcp_packets[1] = tcp_packets[current-1];
                current = 1;
              }
              print_time();
              printf(" TCP Payload filled \n");
              print_time();
              strcpy(tcp_packets[current].payload,fuzz_payload(tcp_packets[current].payload,sizeof(tcp_packets[current].payload)));
              printf(" TCP Packet sent to %s - Payload: %s\n", target,tcp_packets[current].payload);
              if(normal){
                  print_time();
                  send_normal_tcp_packet(sending_socket, tcp_packets[current].payload, strlen(tcp_packets[current].payload));
                  bytes_receieved = recv(sending_socket, receieved_data, sizeof(receieved_data),0);
                  printf(" Received: %s \n", receieved_data);
                  memset(receieved_data, '\0', sizeof(receieved_data));
              } else {
                  print_time();
                  if((casecount + 1) == 1){
                    //first packet seq = seq and ack = ack
                    tcp_packets[current].tcphdr = build_tcp_header((packet_info.seq), (packet_info.ack),tcp_packets[current].tcphdr.th_x2,tcp_packets[current].tcphdr.th_off,PSHACK,ntohs(tcp_packets[current].tcphdr.th_win),ntohs(tcp_packets[current].tcphdr.th_urp));
                    /*tcp_packets[current].tcphdr.th_seq = packet_info.seq;
                    tcp_packets[current].tcphdr.ack_seq = packet_info.ack;*/
                  } else {
                    //consecutive packets seq = ack and ack = seq
                    /*tcp_packets[current].tcphdr.th_seq = packet_info.ack;
                    tcp_packets[current].tcphdr.ack_seq = packet_info.seq;*/
                    tcp_packets[current].tcphdr = build_tcp_header((packet_info.ack), (packet_info.seq),tcp_packets[current].tcphdr.th_x2,tcp_packets[current].tcphdr.th_off,PSHACK,ntohs(tcp_packets[current].tcphdr.th_win),ntohs(tcp_packets[current].tcphdr.th_urp));
                  }
                  send_raw_tcp_packet(tcp_packets[current].iphdr, tcp_packets[current].tcphdr, tcp_packets[current].payload);
                  print_tcp_packet(tcp_packets[current]);
                  recv_data = false;
                  while(recv_data == false){
                      if(recvfrom(sending_socket, packet_buffer, sizeof(packet_buffer), 0, (struct sockaddr*)&icmpclient, &client_addr_len) < 0){
                          perror("recvfrom");
                        } else{
                            strcpy(receieved_data,recv_tcp_packet(packet_buffer));
                        }
                  }
                  printf("payload: %s\n", receieved_data);
                  if(search(receieved_data, result, sizeof(result))){
                      printf("Found matching string\n");
                      tcp_packets[end] = tcp_packets[0];
                      print_time();
                      print_tcp_packet(tcp_packets[end]);
                      end++;
                  }
                  memset(receieved_data, '\0', sizeof(receieved_data));
                  memset(packet_buffer, '\0', sizeof(packet_buffer));

              }
          }else if(packet_info.protocol == UDP){
              if(current == end){
                //no more items in the queue
                udp_packets[1] = udp_packets[current-1];
                current = 1;
              }
              if(normal){
                  print_time();
                  printf(" Test case #%i \n", (casecount + 1));
              }
              print_time();
              printf(" UDP Payload filled \n");
              print_time();
              strcpy(udp_packets[current].payload,fuzz_payload(udp_packets[current].payload,sizeof(udp_packets[current].payload)));

              printf(" UDP Packet sent to %s - Payload: %s\n", target,udp_packets[current].payload);
              if(normal){
                  send_normal_udp_packet(sending_socket, udp_packets[current].payload, strlen(udp_packets[current].payload), servinfo.ai_addr, servinfo.ai_addrlen);
                  bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                  print_time();
                  printf(" Received: %s \n", receieved_data);
                  memset(receieved_data, '\0', sizeof(receieved_data));
              } else {
                  print_time();
                  print_udp_packet(udp_packets[current]);
                  print_time();
                  send_raw_udp_packet(udp_packets[current].iphdr, udp_packets[current].udphdr, udp_packets[current].payload);
                  bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                  print_time();
                  printf(" Received: %s \n\n", receieved_data);
                  if(search(receieved_data, result, sizeof(result))){
                      printf("Found matching string\n");
                      udp_packets[end] = udp_packets[current];
                      print_time();
                      print_udp_packet(udp_packets[end]);
                      end++;
                  }
                  memset(receieved_data, '\0', sizeof(receieved_data));
              }
          }else if(packet_info.protocol == ICMP){
replaypacket1:
              if(current == end){
                //no more items in the queue
                icmp_packets[1] = icmp_packets[current-1];
                current = 1;
              }
              print_time();
              printf(" ICMP Payload filled \n");
              strcpy(icmp_packets[current].payload,fuzz_payload(icmp_packets[current].payload,sizeof(icmp_packets[current].payload)));
              print_time();
              printf(" Payload: %s\n", icmp_packets[current].payload);
              print_time();
              send_raw_icmp_packet(icmp_packets[current].iphdr, icmp_packets[current].icmphdr, icmp_packets[current].payload);
              memset(receieved_data,'\0', sizeof(receieved_data));
              if(recvfrom(sending_socket, receieved_data, sizeof(receieved_data), 0, (struct sockaddr*)&icmpclient, &client_addr_len) < 0){
                    perror("recvfrom");
              } else {
                    strcpy(receieved_data,recv_icmp_packet(receieved_data));
              }
              print_time();
              printf(" Received: %s \n", receieved_data);
              if(replay == true){
                replay = false;
                goto replaypacket1;
              } else {
                  if(search(receieved_data, result, sizeof(result))){
                      printf("Found matching string\n");
                      icmp_packets[end] = icmp_packets[0];
                      print_time();
                      print_icmp_packet(icmp_packets[end]);
                      end++;
                  }
              }
          }
        current++;
        casecount++;
      }else {
        complete = true;
        if(packet_info.protocol == TCP && raw){
            end_tcp_connection(sending_socket);
        }
      }
  }
  //fclose(config_file);
  free(target);
  free(src_ip);
  free(dst_ip);
  return (0);
}
