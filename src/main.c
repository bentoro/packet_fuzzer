#include "main.h"

int main(int argc, char **argv) {
  //initilize the seed as the current time
  srand( time(NULL) );
  target = (char *)calloc(40, sizeof(char));
  src_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
  dst_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));

  //Check if user is Root
  if (geteuid() != 0) {
    printf("Must run as root\n");
    exit(1);
  }

    print_time();
    printf("Configuration Summary\n");
    while ((opt = getopt(argc, argv, "h:t:s:d:p:rifc:x")) != -1) {
        switch (opt) {
        case 'h':
            //set source ip
            strncpy(src_ip, optarg, sizeof(INET_ADDRSTRLEN));
            print_time();
            printf(" Source ip: %s\n", optarg);
            break;
        case 't':
            //set destination ip
            strncpy(dst_ip, optarg, sizeof(INET_ADDRSTRLEN));
            print_time();
            printf(" Destination ip: %s\n", optarg);
            break;
        case 's':
            //set source port
            src_port = atoi(optarg);
            print_time();
            printf(" Source Ip: %d\n", atoi(optarg));
            break;
        case 'd':
            //set destination port
            dst_port = atoi(optarg);
            strcpy(string_port, optarg);
            print_time();
            printf(" Destination port: %d\n", atoi(optarg));
            break;
        case 'p':
            //determine protocol
            packet_info.protocol = atoi(optarg);
            if (atoi(optarg) == TCP) {
                print_time();
                printf(" Protocol: TCP\n");
                tcp = true;
            } else if (atoi(optarg) == UDP) {
                udp = true;
                print_time();
                printf(" Protocol: UDP\n");
            } else if (atoi(optarg) == ICMP) {
                icmp = true;
                print_time();
                printf(" Protocol: ICMP\n");
            }
            break;
        case 'r':
            raw = true;
            normal = false;
            print_time();
            printf(" Raw sockets: True\n");
            break;
        case 'i':
            strncpy(interface_name, optarg, sizeof(interface_name));
            interface = search_interface(interface_name);
            break;
        case 'f':
            feedback = true;
            custom = false;
            print_time();
            printf(" Feedback Algorithm: true\n");
            break;
        case 'c':
            total_testcases = atoi(optarg);
            print_time();
            printf(" Total # of testcaes: %i\n", atoi(optarg));
            break;
        case 'x':
            // Interface to send packet through.
            feedback = true;
            custom = false;
            raw = false;
            normal = true;
            interface = search_interface("wlp2s0");
            src_port = 100;
            strcpy(result, "correct");
            packet_info.protocol = UDP;
            printf("protocol: TCP\n");
            printf("src_port: %i\n", src_port);
            dst_port = 8045;
            //changed source port
            printf("dst_port: %i\n", dst_port);
            strcpy(string_port, "8045");
            strcpy(src_ip, "192.168.1.73");
            printf("src_ip: %s\n", src_ip);
            strcpy(target, "192.168.1.75");
            printf("dst_ip: %s\n", target);
            break;
        default:
            /*?*/
            print_usage();
            exit(1);
        }
    }

  total_testcases = 500;
  set_fuzz_ratio(0.60);
  log_file = fopen("log","wb+");
  replys = fopen("replys","wb+");
  debug = true;

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
                printf("# test cases: %i \n\n", (line_count / 3));
                packet_info.size = (line_count/3);
          }
  }
  rewind(config_file);
  // allocate space for the test cases
  if(packet_info.protocol == TCP){
      replay_counter = 0;
      pshack_flag = false;
      strncpy(protocol, "TCP",sizeof("TCP"));
      delay.tv_sec = 0;
      delay.tv_nsec = 500000000L;
      print_time();
      printf(" Allocated room for TCP packet\n");
      log_print_time();
      fprintf(log_file," Allocated room for TCP packet\n");
      //create_filter(filter);
      //Allocate atleast half of the total test cases
      tcp_packets = calloc(((total_testcases)/2)+1, sizeof(struct tcp_packet));
      if(normal){
        delay.tv_sec = 1;
        delay.tv_nsec = 0;
        print_time();
        sending_socket = start_tcp_client(target, string_port);
      } else {
          sending_socket = start_tcp_raw_client();
          client_addr_len = sizeof(rawclient);
          send_raw_syn_packet(sending_socket);
          if(nanosleep(&delay, &resume_delay) < 0) {
          }

      }
  }else if(packet_info.protocol == UDP){
      strncpy(protocol, "UDP", sizeof("UDP"));
      delay.tv_sec = 0;
      delay.tv_nsec = 500000000;
      print_time();
      printf(" Allocated room for UDP packet\n");
      log_print_time();
      fprintf(log_file, " Allocated room for UDP packet\n");
      //Allocate atleast half of the total test cases
      udp_packets = calloc((total_testcases)/2, sizeof(struct udp_packet));
      sending_socket = start_udp_server(src_port);
	  client_addr_len = sizeof(rawclient);
      if(normal){
          delay.tv_sec = 0;
          delay.tv_nsec = 0;
          print_time();
          hints = set_hints(AF_UNSPEC,SOCK_DGRAM, 0);
          servinfo = set_addr_info(target, string_port, hints);
          sending_socket = start_udp_client(target, string_port);
      }
  }else if(packet_info.protocol == ICMP){
      strncpy(protocol, "ICMP", sizeof("ICMP"));
      delay.tv_sec = 1;
      delay.tv_nsec = 0;
      print_time();
      printf(" Allocated room for ICMP packet\n");
      log_print_time();
      fprintf(log_file," Allocated room for ICMP packet\n");
      sending_socket = start_icmp_client();
	  client_addr_len = sizeof(rawclient);
      //Allocate atleast half of the total test cases
      icmp_packets = calloc((total_testcases)/2, sizeof(struct icmp_packet));
      packet = (uint8_t *)calloc(IP_MAXPACKET, sizeof(uint8_t));
  }


  if((line_count != 0)){
      while (fgets(buffer, sizeof(buffer), config_file) != NULL) {
        int temp[BUFSIZ];
        char payload[BUFSIZ];
        char value[BUFSIZ];
        buffer[strlen(buffer) - 1] = ' ';
        int counter = 0;
        //store one line at a time
        if(line != 3 && !normal){
            for (int i = 0; i < (int)strlen(buffer); i++) {
              // if the line only contains a space move on to next line
              if (strlen(buffer) == 1) {
                if (buffer[i] = ' ') {
                  break;
                }
              }
              // Look for a string before a space
              if (buffer[i] == ' ') {
                  int ch = 0;
                // check if the field should be fuzzed
                if(strcmp(value, "FUZZ") == 0){
                    if(debug){
                        printf("FUZZ\n");
                    }
                    ch = 1339;
                } else {
                    ch = atoi(value);
                }
                temp[counter] = ch;
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

        if(line ==  1){
              print_time();
              printf(" Test case #%i \n", (casecount + 1));
              log_print_time();
              fprintf(log_file," Test case #%i \n", (casecount + 1));
              if(packet_info.protocol == TCP){
                  print_time();
                  printf(" IP Header filled \n");
                  log_print_time();
                  fprintf(log_file," IP Header filled \n");
                  memset(tcp_packets,'\0',sizeof(tcp_packet));
                  tcp_packets[0].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              }else if(packet_info.protocol == UDP){
                  memset(udp_packets,'\0',sizeof(udp_packet));
                  udp_packets[0].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
              }else if(packet_info.protocol == ICMP){
                  memset(icmp_packets,'\0',sizeof(icmp_packet));
                  icmp_packets[0].iphdr = build_ip_header(temp[0], temp[1],temp[2],temp[3],temp[4],temp[5],temp[6],temp[7],temp[8],temp[9],temp[10]);
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
              }else if(packet_info.protocol == UDP){
                  udp_packets[0].udphdr = build_udp_header(temp[0]);
              }else if(packet_info.protocol == ICMP){
                  icmp_packets[0].icmphdr = build_icmp_header(temp[0],temp[1],temp[2],temp[3]);
              }
              print_time();
              printf(" %s Header filled \n",protocol);
              log_print_time();
              fprintf(log_file," %s Header filled \n",protocol);
            line++;
        } else if(line == 3){
replaypacket:
              if(normal){
                      print_time();
                      printf(" Test case #%i \n", (casecount + 1));
                      log_print_time();
                      fprintf(log_file," Test case #%i \n", (casecount + 1));
              }
              if(payload[0] == ' '){
                      print_time();
                      printf("PAYLOAD IS EMPTY\n");
                      log_print_time();
                      fprintf(log_file,"PAYLOAD IS EMPTY\n");
              } else {
              print_time();
              printf(" %s Payload filled \n",protocol);
              log_print_time();
              fprintf(log_file," %s Payload filled \n",protocol);
              print_time();
              printf(" %s Packet sent to %s\n",protocol, target);
              log_print_time();
              fprintf(log_file," %s Packet sent to %s\n",protocol, target);
              if(packet_info.protocol == TCP){
                  memset(tcp_packets[0].payload, '\0',sizeof(tcp_packets[0].payload));
                  strncpy(tcp_packets[0].payload, payload,strlen(payload)-1);
                  if(normal){
                      print_time();
                      printf(" Payload: %s\n",tcp_packets[0].payload);
                      log_print_time();
                      fprintf(log_file," Payload: %s\n",tcp_packets[0].payload);
                      print_time();
                      log_print_time();
                      send_normal_tcp_packet(sending_socket, tcp_packets[0].payload, strlen(tcp_packets[0].payload));
                      bytes_receieved = recv(sending_socket, receieved_data, sizeof(receieved_data),0);
                      printf(" Received: %s \n", receieved_data);
                      fprintf(log_file," Received: %s \n", receieved_data);
                      if(search(receieved_data, result, strlen(result))){
                          print_time();
                          printf(" Found matching string packet added to queue #%i\n", size);
                          log_print_time();
                          fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                          tcp_packets[size] = tcp_packets[0];
                          print_tcp_packet(tcp_packets[size]);
                          log_print_tcp_packet(tcp_packets[size]);
                          size++;
                      }
                      memset(receieved_data, '\0', sizeof(receieved_data));
                  } else {
                      print_tcp_packet(tcp_packets[size]);
                      log_print_tcp_packet(tcp_packets[size]);
                      send_raw_tcp_packet(tcp_packets[0].iphdr, tcp_packets[0].tcphdr, tcp_packets[0].payload);
                      pshack_flag = false;
                      while(pshack_flag == false){
                          if(recvfrom(sending_socket, packet_buffer, sizeof(packet_buffer), 0, (struct sockaddr*)&rawclient, &client_addr_len) < 0){
                              perror("recvfrom");
                            } else{
                                strcpy(receieved_data,recv_tcp_packet(packet_buffer));
                            }
                      }
                      /*while(pshack_flag == false){
                          packet_info = packet_capture(filter, packet_info);
                          replay_counter++;
                      }*/
                          //replay_counter = 0;
                          print_time();
                          printf(" Received reply from %s \n", target);
                          log_print_time();
                          fprintf(log_file," Received reply from %s \n", target);
                          /*pshack_flag = false;
                          strcpy(receieved_data,reply_payload);*/
                          if(search(receieved_data, result, strlen(result))){
                              print_time();
                              printf(" Found matching string packet added to queue #%i\n", size);
                              log_print_time();
                              fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                              tcp_packets[size] = tcp_packets[0];
                              print_tcp_packet(tcp_packets[size]);
                              log_print_tcp_packet(tcp_packets[size]);
                              size++;
                          }
                      memset(receieved_data, '\0', sizeof(receieved_data));
                      memset(packet_buffer, '\0', sizeof(packet_buffer));
                  }
              }else if(packet_info.protocol == UDP){
                  memset(udp_packets[0].payload, '\0',sizeof(udp_packets[0].payload));
                  strncpy(udp_packets[0].payload, payload, strlen(payload)-1);
                  print_time();
                  printf(" UDP Payload filled \n");
                  log_print_time();
                  fprintf(log_file," UDP Payload filled \n");
                  print_time();
                  printf(" UDP Packet sent to %s\n", target);
                  log_print_time();
                  fprintf(log_file," UDP Packet sent to %s\n", target);
                  if(normal){
                      send_normal_udp_packet(sending_socket, udp_packets[0].payload, strlen(udp_packets[0].payload), servinfo.ai_addr, servinfo.ai_addrlen);
                      bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                      print_time();
                      printf(" Received: %s \n", receieved_data);
                      if(search(receieved_data, result, sizeof(result))){
                          print_time();
                          printf(" Found matching string packet added to queue #%i\n", size);
                          log_print_time();
                          fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                          udp_packets[size] = udp_packets[0];
                          print_udp_packet(udp_packets[size]);
                          log_print_udp_packet(udp_packets[size]);
                          size++;
                      }
                      memset(receieved_data, '\0', sizeof(receieved_data));
                  } else {
                      print_udp_packet(udp_packets[0]);
                      send_raw_udp_packet(udp_packets[0].iphdr, udp_packets[0].udphdr, udp_packets[0].payload);
                      memset(receieved_data,'\0', sizeof(receieved_data));
                      bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                      print_time();
                      printf(" Received: %s \n", receieved_data);
                      log_print_time();
                      fprintf(log_file," Received: %s \n", receieved_data);
                      if(search(receieved_data, result, sizeof(result))){
                          print_time();
                          printf(" Found matching string packet added to queue #%i\n", size);
                          log_print_time();
                          fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                          udp_packets[size] = udp_packets[0];
                          print_udp_packet(udp_packets[size]);
                          log_print_udp_packet(udp_packets[size]);
                          size++;
                      }
                      memset(receieved_data, '\0', sizeof(receieved_data));
                  }
              }else if(packet_info.protocol == ICMP){
                  memset(icmp_packets[0].payload, '\0',sizeof(icmp_packets[0].payload));
                  strncpy(icmp_packets[0].payload, payload, strlen(payload) -1);
                  print_time();
                  printf(" ICMP Packet sent to %s\n", target);
                  log_print_time();
                  fprintf(log_file," ICMP Packet sent to %s\n", target);
                  print_icmp_packet(icmp_packets[0]);
                  send_raw_icmp_packet(icmp_packets[0].iphdr, icmp_packets[0].icmphdr, icmp_packets[0].payload);
                  memset(receieved_data,'\0', sizeof(receieved_data));
                  if(recvfrom(sending_socket, receieved_data, sizeof(receieved_data), 0, (struct sockaddr*)&rawclient, &client_addr_len) < 0){
                        perror("recvfrom");
                  } else {
                        strcpy(receieved_data,recv_icmp_packet(receieved_data));
                  }
                  if(replay == true){
                    replay = false;
                    goto replaypacket;
                  } else {
                      print_time();
                      printf(" Received reply from %s \n", target);
                      log_print_time();
                      fprintf(log_file," Received reply from %s \n", target);
                      if(search(receieved_data, result, sizeof(result))){
                          print_time();
                          printf(" Found matching string packet added to queue #%i\n", size);
                          log_print_time();
                          fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                          icmp_packets[size] = icmp_packets[0];
                          print_icmp_packet(icmp_packets[size]);
                          log_print_icmp_packet(icmp_packets[size]);
                          size++;
                      }
                  }
              } //ICMP
            }
            printf("\n");
            fprintf(log_file,"\n");
            if(nanosleep(&delay, &resume_delay) < 0) {
            }
            casecount++;
            if(!normal){
                line = 1;
            } //line3
        }
      }//fgets
  }else {
      print_time();
      printf(" No user test cases\n");
      log_print_time();
      fprintf(log_file," No user test cases\n");
  }

  while(!complete){
      if(debug){
          printf("CURRENT: %i\n", current);
          printf("size: %i\n", size);
      }
      if(total_testcases != casecount){
replaypacket1:
              print_time();
              printf(" Test case #%i \n", (casecount + 1));
              print_time();
              printf(" %s Packet filled \n",protocol);
              log_print_time();
              fprintf(log_file," Test case #%i \n", (casecount + 1));
              log_print_time();
              fprintf(log_file," %s Packet filled \n",protocol);
          if(packet_info.protocol == TCP){
              if(casecount+1 == 1){
                tcp_packets[current].iphdr = build_ip_header(5,4,0,40,0,0,0,0,0,255,7);
                tcp_packets[current].tcphdr = build_tcp_header(1337,0,0,5,PSHACK,64249,0);
                strcpy(tcp_packets[current].payload, "hello");

              }else if(current == size || size ==1){
                //no more items in the queue
                if(size == 1){
                    current = 0;
                } else {
                    current = 1;
                }
              }
              strcpy(tcp_packets[current].payload,fuzz_payload(tcp_packets[current].payload,sizeof(tcp_packets[current].payload)));
              print_tcp_packet(tcp_packets[current]);
              if(normal){
                  print_time();
                  send_normal_tcp_packet(sending_socket, tcp_packets[current].payload, strlen(tcp_packets[current].payload));
                  bytes_receieved = recv(sending_socket, receieved_data, sizeof(receieved_data),0);
                  printf(" Received: %s \n", receieved_data);
                  fprintf(log_file," Received: %s \n", receieved_data);
                  if(search(receieved_data, result, sizeof(result))){
                      print_time();
                      printf(" Found matching string packet added to queue #%i\n", size);
                      log_print_time();
                      fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                      tcp_packets[size] = tcp_packets[0];
                      print_tcp_packet(tcp_packets[size]);
                      log_print_tcp_packet(tcp_packets[size]);
                      size++;
                  }
                  memset(receieved_data, '\0', sizeof(receieved_data));
              } else {
                  if((casecount + 1) == 1){
                    //first packet seq = seq and ack = ack
                    tcp_packets[current].tcphdr.th_seq = htonl(packet_info.seq);
                    tcp_packets[current].tcphdr.ack_seq = htonl(packet_info.ack);
                  } else {
                    //consecutive packets seq = ack and ack = seq
                    tcp_packets[current].tcphdr.th_seq = htonl(packet_info.ack);
                    tcp_packets[current].tcphdr.ack_seq = htonl(packet_info.seq);
                  }
                  send_raw_tcp_packet(tcp_packets[current].iphdr, tcp_packets[current].tcphdr, tcp_packets[current].payload);
                  print_tcp_packet(tcp_packets[current]);
                  pshack_flag = false;
                  while(pshack_flag == false){
                      if(recvfrom(sending_socket, packet_buffer, sizeof(packet_buffer), 0, (struct sockaddr*)&rawclient, &client_addr_len) < 0){
                          perror("recvfrom");
                        } else{
                            print_time();
                            printf(" Received reply from %s \n", target);
                            fprintf(log_file," Received reply from %s \n", target);
                            strcpy(receieved_data,recv_tcp_packet(packet_buffer));
                        }
                  }
                  if(search(receieved_data, result, sizeof(result))){
                      print_time();
                      printf(" Found matching string packet added to queue #%i\n", size);
                      log_print_time();
                      fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                      tcp_packets[size] = tcp_packets[0];
                      print_tcp_packet(tcp_packets[size]);
                      log_print_tcp_packet(tcp_packets[size]);
                      size++;
                  }
                  memset(receieved_data, '\0', sizeof(receieved_data));
                  memset(packet_buffer, '\0', sizeof(packet_buffer));

              }
          }else if(packet_info.protocol == UDP){
              if(casecount + 1 == 1){
                udp_packets[current].iphdr = build_ip_header(5,4,0,28,0,0,0,0,0,255,8);
                udp_packets[current].udphdr = build_udp_header(8);
                strcpy(udp_packets[current].payload, "hello");
              }else if(current == size || size == 1){
                //no more items in the queue
                if(size == 1){
                    current = 0;
                } else {
                    current = 1;
                }
              }
              strcpy(udp_packets[current].payload,fuzz_payload(udp_packets[current].payload,sizeof(udp_packets[current].payload)));
              print_udp_packet(udp_packets[current]);
              printf(" UDP Packet sent to %s - Payload: %s\n", target,udp_packets[current].payload);
              log_print_udp_packet(udp_packets[current]);
              fprintf(log_file," UDP Packet sent to %s - Payload: %s\n", target,udp_packets[current].payload);
              if(normal){
                  print_udp_packet(udp_packets[size]);
                  send_normal_udp_packet(sending_socket, udp_packets[current].payload, strlen(udp_packets[current].payload), servinfo.ai_addr, servinfo.ai_addrlen);
                  bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                  print_time();
                  printf(" Received: %s \n", receieved_data);
                  fprintf(log_file," Received: %s \n\n", receieved_data);
                  if(search(receieved_data, result, sizeof(result))){
                      print_time();
                      printf(" Found matching string packet added to queue #%i\n", size);
                      log_print_time();
                      fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                      udp_packets[size] = udp_packets[current];
                      print_udp_packet(udp_packets[size]);
                      log_print_udp_packet(udp_packets[size]);
                      size++;
                  }
                  memset(receieved_data, '\0', sizeof(receieved_data));
              } else {
                  print_time();
                  print_udp_packet(udp_packets[current]);
                  send_raw_udp_packet(udp_packets[current].iphdr, udp_packets[current].udphdr, udp_packets[current].payload);
                  bytes_receieved = recvfrom(sending_socket, receieved_data, sizeof(receieved_data),0,(struct sockaddr *)&client, &client_addr_len);
                  print_time();
                  printf(" Received: %s \n\n", receieved_data);
                  fprintf(log_file," Received: %s \n\n", receieved_data);
                  if(search(receieved_data, result, sizeof(result))){
                      print_time();
                      printf(" Found matching string packet added to queue #%i\n", size);
                      log_print_time();
                      fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                      udp_packets[size] = udp_packets[current];
                      print_time();
                      print_udp_packet(udp_packets[size]);
                      log_print_udp_packet(udp_packets[size]);
                      size++;
                  }
                  memset(receieved_data, '\0', sizeof(receieved_data));
              }
          }else if(packet_info.protocol == ICMP){
              if(casecount + 1 == 1){
                icmp_packets[current].iphdr = build_ip_header(5,4,0,28,0,0,0,0,0,255,9);
                icmp_packets[current].icmphdr = build_icmp_header(8,0,1000,0);
                strcpy(icmp_packets[current].payload, "hello");
              }else if(current == size || size == 1){
                //no more items in the queue
                if(size == 1){
                    current = 0;
                } else {
                    current = 1;
                }
              }
              strcpy(icmp_packets[current].payload,fuzz_payload(icmp_packets[current].payload,sizeof(icmp_packets[current].payload)));
              print_icmp_packet(icmp_packets[current]);
              send_raw_icmp_packet(icmp_packets[current].iphdr, icmp_packets[current].icmphdr, icmp_packets[current].payload);
              memset(receieved_data,'\0', sizeof(receieved_data));
              if(recvfrom(sending_socket, receieved_data, sizeof(receieved_data), 0, (struct sockaddr*)&rawclient, &client_addr_len) < 0){
                    perror("recvfrom");
              } else {
                    print_time();
                    printf(" Received reply from %s \n", target);
                    fprintf(log_file," Received reply from %s \n", target);
                    strcpy(receieved_data,recv_icmp_packet(receieved_data));
              }
              print_time();
              printf(" Received: %s \n", receieved_data);
              log_print_time();
              fprintf(log_file," Received: %s \n", receieved_data);
              if(replay == true){
                replay = false;
                goto replaypacket1;
              } else {
                  if(search(receieved_data, result, sizeof(result))){
                      print_time();
                      printf(" Found matching string packet added to queue #%i\n", size);
                      log_print_time();
                      fprintf(log_file," Found matching string packet added to queue #%i\n", size);
                      icmp_packets[size] = icmp_packets[0];
                      print_icmp_packet(icmp_packets[size]);
                      log_print_icmp_packet(icmp_packets[size]);
                      size++;
                  }
              }
          }

        if(nanosleep(&delay, &resume_delay) < 0) {
        }
        current++;
        casecount++;
        printf("\n");
      }else {
        complete = true;
        if(packet_info.protocol == TCP && raw){
            send_raw_fin_packet(sending_socket);
            //send_raw_fin_packet(sending_socket);
        }
      }
  }
  //fclose(log_file);
  //fclose(replys);
  //fclose(config_file);
  free(target);
  free(src_ip);
  free(dst_ip);
  return (0);
}
