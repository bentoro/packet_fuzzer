
#include "raw_socket_wrappers.h"

/* =====================================================================================
 *
 *       function: resolve_host
 *
 *         return: char *
 *
 *       Parameters:
 *                  char *target - target machine
 *                  struct addrinfo hints -  hints
 *       Notes:
 *              Gets the host
 *
 * ====================================================================================*/
char *resolve_host(char *target, struct addrinfo hints) {
  int status;
  void *tmp;
  char *dst_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
  struct addrinfo *res;
  struct sockaddr_in *ipv4;

  if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
    exit(0);
  }

  ipv4 = (struct sockaddr_in *)res->ai_addr;
  tmp = &(ipv4->sin_addr);

  if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop()");
    exit(EXIT_FAILURE);
  }

  freeaddrinfo(res);
  return dst_ip;
}

/* =====================================================================================
 *
 *       function: search_interface
 *
 *         return: struct ifreq
 *
 *       Parameters:
 *                  char *ifc - interface
 *       Notes:
 *              search for the interface for the socket
 *
 * ====================================================================================*/
struct ifreq search_interface(char *ifc) {
  // dont need to return socket as it is only used to search for the interface
  char *interface = (char *)malloc(40 * sizeof(char));
  memset(interface, 0, 40 * sizeof(char));
  struct ifreq ifr;
  int tmp_socket;

  // Interface to send packet through.
  strcpy(interface, ifc);

  //socket to search for Interface
  if ((tmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("socket() failed to get socket descriptor for using ioctl() ");
    exit(EXIT_FAILURE);
  }

  //Look up interface with ioctl() for sendto()
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
  if (ioctl(tmp_socket, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl() failed to find interface ");
    exit(0);
  }
  print_time();
  printf("Interface: %s\n", interface);
  log_print_time();
  fprintf(log_file,"Interface: %s\n", interface);

  close(tmp_socket);
  free(interface);
  return ifr;
}

/* =====================================================================================
 *
 *       function: checksum
 *
 *         return: uint16_t
 *
 *       Parameters:
 *                  uint16_t *addr - address
 *                  int len - length of the packet
 *       Notes:
 *              Calculate the checksum value
 *
 * ====================================================================================*/
uint16_t checksum(uint16_t *addr, int len) {
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t *)addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  answer = ~sum;

  return (answer);
}
/* =====================================================================================
 *
 *       function: tcp4_checksum
 *
 *         return: uint16_t
 *
 *       Parameters:
 *                  struct ip iphdr - ip header
 *                  struct tcphdr tcphdr - tcp header
 *                  uint8_t *payload - payload
 *                  int payloadlen - length of payload
 *                  int len - length of the packet
 *
 *       Author: P.D. Buchan
 *
 *       Notes:
 *              Calculate the checksum value
 *
 * ====================================================================================*/
uint16_t tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload,int payloadlen) {
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int i, chksumlen = 0;

  memset(buf, 0, IP_MAXPACKET);

  ptr = &buf[0]; // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
  ptr += sizeof(iphdr.ip_src.s_addr);
  chksumlen += sizeof(iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
  ptr += sizeof(iphdr.ip_dst.s_addr);
  chksumlen += sizeof(iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0;
  ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
  ptr += sizeof(iphdr.ip_p);
  chksumlen += sizeof(iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons(sizeof(tcphdr) + payloadlen);
  memcpy(ptr, &svalue, sizeof(svalue));
  ptr += sizeof(svalue);
  chksumlen += sizeof(svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy(ptr, &tcphdr.th_sport, sizeof(tcphdr.th_sport));
  ptr += sizeof(tcphdr.th_sport);
  chksumlen += sizeof(tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy(ptr, &tcphdr.th_dport, sizeof(tcphdr.th_dport));
  ptr += sizeof(tcphdr.th_dport);
  chksumlen += sizeof(tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy(ptr, &tcphdr.th_seq, sizeof(tcphdr.th_seq));
  ptr += sizeof(tcphdr.th_seq);
  chksumlen += sizeof(tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy(ptr, &tcphdr.th_ack, sizeof(tcphdr.th_ack));
  ptr += sizeof(tcphdr.th_ack);
  chksumlen += sizeof(tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy(ptr, &cvalue, sizeof(cvalue));
  ptr += sizeof(cvalue);
  chksumlen += sizeof(cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy(ptr, &tcphdr.th_flags, sizeof(tcphdr.th_flags));
  ptr += sizeof(tcphdr.th_flags);
  chksumlen += sizeof(tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy(ptr, &tcphdr.th_win, sizeof(tcphdr.th_win));
  ptr += sizeof(tcphdr.th_win);
  chksumlen += sizeof(tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0;
  ptr++;
  *ptr = 0;
  ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy(ptr, &tcphdr.th_urp, sizeof(tcphdr.th_urp));
  ptr += sizeof(tcphdr.th_urp);
  chksumlen += sizeof(tcphdr.th_urp);

  // Copy payload to buf
  memcpy(ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  i = 0;
  while (((payloadlen + i) % 2) != 0) {
    i++;
    chksumlen++;
    ptr++;
  }

  return checksum((uint16_t *)buf, chksumlen);
}
/* =====================================================================================
 *
 *       function: udp4_checksum
 *
 *         return: uint16_t
 *
 *       Parameters:
 *                  struct ip iphdr - ip header
 *                  struct udphdr udphdr - udp header
 *                  uint8_t *payload - payload
 *                  int payloadlen - length of payload
 *                  int len - length of the packet
 *
 *       Author: P.D. Buchan
 *
 *       Notes:
 *              Calculate the checksum value
 *
 * ====================================================================================*/
uint16_t udp4_checksum(struct ip iphdr, struct udphdr udphdr, uint8_t *payload,int payloadlen) {
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0]; // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
  ptr += sizeof(iphdr.ip_src.s_addr);
  chksumlen += sizeof(iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
  ptr += sizeof(iphdr.ip_dst.s_addr);
  chksumlen += sizeof(iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0;
  ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
  ptr += sizeof(iphdr.ip_p);
  chksumlen += sizeof(iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
  ptr += sizeof(udphdr.len);
  chksumlen += sizeof(udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
  ptr += sizeof(udphdr.source);
  chksumlen += sizeof(udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
  ptr += sizeof(udphdr.dest);
  chksumlen += sizeof(udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
  ptr += sizeof(udphdr.len);
  chksumlen += sizeof(udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0;
  ptr++;
  *ptr = 0;
  ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy(ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i = 0; i < payloadlen % 2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum((uint16_t *)buf, chksumlen);
}

/* =====================================================================================
 *
 *       function: icmp4_checksum
 *
 *         return: uint16_t
 *
 *       Parameters:
 *                  struct ip iphdr - ip header
 *                  struct icmp icmphdr - icmp header
 *                  uint8_t *payload - payload
 *                  int payloadlen - length of payload
 *                  int len - length of the packet
 *
 *       Author: P.D. Buchan
 *
 *       Notes:
 *              Calculate the checksum value
 *
 * ====================================================================================*/
uint16_t icmp4_checksum(struct icmp icmphdr, uint8_t *payload, int payloadlen) {
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0]; // ptr points to beginning of buffer buf

  // Copy Message Type to buf (8 bits)
  memcpy(ptr, &icmphdr.icmp_type, sizeof(icmphdr.icmp_type));
  ptr += sizeof(icmphdr.icmp_type);
  chksumlen += sizeof(icmphdr.icmp_type);

  // Copy Message Code to buf (8 bits)
  memcpy(ptr, &icmphdr.icmp_code, sizeof(icmphdr.icmp_code));
  ptr += sizeof(icmphdr.icmp_code);
  chksumlen += sizeof(icmphdr.icmp_code);

  // Copy ICMP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0;
  ptr++;
  *ptr = 0;
  ptr++;
  chksumlen += 2;

  // Copy Identifier to buf (16 bits)
  memcpy(ptr, &icmphdr.icmp_id, sizeof(icmphdr.icmp_id));
  ptr += sizeof(icmphdr.icmp_id);
  chksumlen += sizeof(icmphdr.icmp_id);

  // Copy Sequence Number to buf (16 bits)
  memcpy(ptr, &icmphdr.icmp_seq, sizeof(icmphdr.icmp_seq));
  ptr += sizeof(icmphdr.icmp_seq);
  chksumlen += sizeof(icmphdr.icmp_seq);

  // Copy payload to buf
  memcpy(ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i = 0; i < payloadlen % 2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum((uint16_t *)buf, chksumlen);
}


/* =====================================================================================
 *
 *       function: send_raw_icmp_packet
 *
 *         return: void
 *
 *       Parameters:
 *                  struct ip iphdr - ip header
 *                  struct icmp icmphdr - icmp header
 *                  char *data - payload
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Send a raw ICMP packet
 *
 * ====================================================================================*/
void send_raw_icmp_packet(struct ip iphdr, struct icmp icmphdr,char *data) {
  int payloadlen = 0, sd;
  struct sockaddr_in sin;
  uint8_t packet[IP_MAXPACKET];
  const int on = 1;
  payloadlen = strlen((const char *)data);
  iphdr.ip_len =  iphdr.ip_len+ htons(payloadlen); // IP header + UDP header + payload len
  if(iphdr.ip_tos == (unsigned char)1339){
    iphdr.ip_tos = generate_rand(65535);                            // TOS
      printf("FUZZ\n");
      printf("tos: %u\n",iphdr.ip_tos);
  }
  if(iphdr.ip_len == 1339){
      iphdr.ip_len =htons(generate_rand(65535)); // length: IP header + TCP header
      if(debug){
          printf("FUZZ\n");
          printf("len: %u\n",iphdr.ip_len);
      }
  }
  if(iphdr.ip_id == 1339){
      iphdr.ip_id = htons(generate_rand(65535));             // ID
      if(debug){
          printf("FUZZ\n");
          printf("id: %u\n",iphdr.ip_id);
      }
  }
  if(iphdr.ip_ttl == (unsigned char)1339){
      iphdr.ip_ttl = generate_rand(65535);       // TTL
      if(debug){
          printf("FUZZ\n");
          printf("TTL: %u\n",iphdr.ip_ttl);
      }
  }
  iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

  // Calculate ICMP header checksum
  if(icmphdr.icmp_type == (unsigned char)1339){
      int rando = generate_rand(18);
      while(rando == 7 || rando == 6){
         rando = generate_rand(18);
      }
      icmphdr.icmp_type = rando;         // message code - 0
      if(debug){
          printf("FUZZ\n");
          printf("type: %u\n",icmphdr.icmp_type);
      }
  }
  if(icmphdr.icmp_code == (unsigned char)1339){
      icmphdr.icmp_code = generate_rand(15);         // message code - 0
      if(debug){
          printf("FUZZ\n");
          printf("code: %u\n",icmphdr.icmp_code);
      }
  }
  if(icmphdr.icmp_id == 1339){
      icmphdr.icmp_id = htons(generate_rand(65535)); // usually PID of sending process
      if(debug){
          printf("FUZZ\n");
          printf("id: %u\n",icmphdr.icmp_id);
      }
  }
  if(icmphdr.icmp_seq == 1339){
      icmphdr.icmp_seq = htons(generate_rand(65535));   // starts at 0
      if(debug){
          printf("FUZZ\n");
          printf("seq: %u\n",icmphdr.icmp_seq);
      }
  }
  icmphdr.icmp_cksum = icmp4_checksum(icmphdr, (uint8_t *)data, payloadlen);
  memcpy((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

  // Copy the IP header.
  memcpy(packet, &iphdr, IP4_HDRLEN);
  // Copy the ICMP Header
  memcpy((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);
  // Copy the ICMP payload
  memcpy(packet + IP4_HDRLEN + ICMP_HDRLEN, data, payloadlen);
  //let the Kernel know where to send the raw datagram
  //Fill the in_addr with the desired destination IP and pass the struct to sendto()
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }

  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt() failed to set IP_HDRINCL ");
    exit(EXIT_FAILURE);
  }

  // Bind socket to interface index.
  if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface)) < 0) {
    perror("setsockopt() failed to bind to interface ");
    exit(EXIT_FAILURE);
  }

  if (sendto(sd, packet, IP4_HDRLEN + ICMP_HDRLEN + payloadlen, 0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
    perror("sendto() failed ");
    exit(EXIT_FAILURE);
  }
  print_time();
  printf(" ICMP Packet sent\n");

  close(sd);
}


/* =====================================================================================
 *
 *       function: send_raw_udp_packet
 *
 *         return: void
 *
 *       Parameters:
 *                  struct ip iphdr - ip header
 *                  struct udphdr udphdr - udp header
 *                  char *data - payload
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Send a raw UDP packet
 *
 * ====================================================================================*/
void send_raw_udp_packet(struct ip ip, struct udphdr udp, char *data) {
  struct sockaddr_in sin;
  struct udp_packet packet;
  int sending_socket, payloadlen = 0;
  const int on = 1;

  if (data != NULL) {
    sprintf(packet.payload, "%s", data);
    payloadlen = strlen(packet.payload);
  }

  //Build IP Header
  packet.iphdr = ip;
  if(packet.iphdr.ip_tos == (unsigned char)1339){
      packet.iphdr.ip_tos = generate_rand(65535);// TOS
      if(debug){
          printf("FUZZ\n");
          printf("tos: %i\n",packet.iphdr.ip_tos);
      }
  }
  if(packet.iphdr.ip_len == 1339){
      packet.iphdr.ip_len =htons(generate_rand(65535)); // length: IP header + TCP header
      if(debug){
          printf("FUZZ\n");
          printf("len: %i\n",packet.iphdr.ip_len);
      }
  }
  if(packet.iphdr.ip_id == 1339){
      packet.iphdr.ip_id = htons(generate_rand(65535));             // ID
      if(debug){
          printf("FUZZ\n");
          printf("id: %i\n",packet.iphdr.ip_len);
      }
  }

  if(packet.iphdr.ip_ttl == (unsigned char)1339){
      packet.iphdr.ip_ttl = generate_rand(65535);       // TTL
      if(debug){
          printf("FUZZ\n");
          printf("ttl: %i\n",packet.iphdr.ip_ttl);
      }
  }
  packet.iphdr.ip_len =  packet.iphdr.ip_len+ htons(payloadlen); // IP header + UDP header + payload len
  packet.iphdr.ip_sum = checksum((uint16_t *)&packet.iphdr, IP4_HDRLEN);

  // UDP header
  packet.udphdr = udp;
  packet.udphdr.len = packet.udphdr.len + htons(payloadlen);
  /*if(packet.udphdr.len == 1339){
    int rando = (generate_rand(10)+8);
    printf("Rand value: %i",rando);
    packet.udphdr.len = htons(rando); // Length of Datagram = UDP Header + UDP Data
    if(debug){
        printf("FUZZ\n");
        printf("len :%u\n",packet.udphdr.len);
    }
  }*/
  packet.udphdr.check = udp4_checksum(packet.iphdr, packet.udphdr,(uint8_t *)packet.payload, payloadlen);

  //let the Kernel know where to send the raw datagram
  //Fill the in_addr with the desired destination IP and pass the struct to sendto()
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = packet.iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sending_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }

  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt(sending_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt() failed to set IP_HDRINCL ");
    exit(EXIT_FAILURE);
  }

  // Bind socket to interface index.
  if (setsockopt(sending_socket, SOL_SOCKET, SO_BINDTODEVICE, &interface,sizeof(interface)) < 0) {
    perror("setsockopt() failed to bind to interface ");
    exit(EXIT_FAILURE);
  }
  print_time();
  printf(" UDP Packet sent\n");
  // Send packet`.
  if (sendto(sending_socket, &packet, IP4_HDRLEN + UDP_HDRLEN + payloadlen, 0,
             (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
    perror("sendto() failed ");
    exit(EXIT_FAILURE);
  }

  close(sending_socket);
}


/* =====================================================================================
 *
 *       function: send_raw_tcp_packet
 *
 *         return: void
 *
 *       Parameters:
 *                  struct ip iphdr - ip header
 *                  struct tcphdr tcp - tcp header
 *                  char *data - payload
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Send a raw TCP packet
 *
 * ====================================================================================*/
void send_raw_tcp_packet(struct ip ip, struct tcphdr tcp,char *data) {
  int sending_socket, payloadlen = 0;
  const int on = 1;
  struct sockaddr_in sin;
  struct tcp_packet packet;

  if (data != NULL) {
    sprintf (packet.payload, "%s", data);
    payloadlen = strlen(packet.payload);
  }
  //Build IP Header
  packet.iphdr = ip;
  if(packet.iphdr.ip_tos == (unsigned char)1339){
      packet.iphdr.ip_tos = generate_rand(65535);// TOS
      if(debug){
          printf("FUZZ\n");
          printf("tos: %i",packet.iphdr.ip_tos);
      }
  }
  if(packet.iphdr.ip_len == 1339){
      packet.iphdr.ip_len =htons(generate_rand(65535)); // length: IP header + TCP header
      if(debug){
          printf("FUZZ\n");
          printf("len: %i",ntohs(packet.iphdr.ip_len));
      }
  }
  if(packet.iphdr.ip_id == 1339){
      packet.iphdr.ip_id = htons(generate_rand(65535));             // ID
      if(debug){
          printf("FUZZ\n");
          printf("id: %i",ntohs(packet.iphdr.ip_id));
      }
  }
  if(packet.iphdr.ip_ttl == (unsigned char)1339){
      packet.iphdr.ip_ttl = generate_rand(65535);       // TTL
      if(debug){
          printf("FUZZ\n");
          printf("ttl: %i",packet.iphdr.ip_ttl);
      }
  }
  packet.iphdr.ip_len =  packet.iphdr.ip_len+ htons(payloadlen); // IP header + UDP header + payload len
  packet.iphdr.ip_sum = checksum((uint16_t *)&packet.iphdr, IP4_HDRLEN);

  //Build TCP Header
  packet.tcphdr = tcp;
  //tcp = build_tcp_header(seq,ack,0, (TCP_HDRLEN/4), flags,64240,0);
  if (packet.tcphdr.th_sport == 1339) {
      packet.tcphdr.th_sport = generate_rand(65535);
      if(debug){
          printf("FUZZ\n");
          printf("sport: %u\n",packet.tcphdr.th_sport);
      }
  }
  if (packet.tcphdr.th_dport == 1339) {
      packet.tcphdr.th_dport = generate_rand(65535);
      if(debug){
          printf("FUZZ\n");
          printf("dport: %u\n",packet.tcphdr.th_dport);
      }
  }
  if(packet.tcphdr.th_seq == 1339){
    packet.tcphdr.th_seq = htonl(generate_rand(UINT_MAX)); // SEQ
      if(debug){
          printf("FUZZ\n");
          printf("seq: %u\n",packet.tcphdr.th_seq);
      }
  }
  if(packet.tcphdr.th_ack == 1339){
      packet.tcphdr.th_ack = htonl(generate_rand(65535)); // ACK - 0 for first packet
      if(debug){
          printf("FUZZ\n");
          printf("ack: %u\n",packet.tcphdr.th_ack);
      }
  }
  if(packet.tcphdr.th_win == 1339){
      packet.tcphdr.th_win = htons(generate_rand(65535)); // Window size
      if(debug){
          printf("FUZZ\n");
          printf("WIN: %i\n", packet.tcphdr.th_win);
      }
  }
  if(packet.tcphdr.th_urp == 1339){
      packet.tcphdr.th_urp = htons(generate_rand(65535));     // Urgent Pointer
      if(debug){
          printf("FUZZ\n");
          printf("urg: %i",packet.tcphdr.th_urp);
      }
  }

  packet.tcphdr.th_sum = tcp4_checksum(packet.iphdr, packet.tcphdr,(uint8_t *)packet.payload, payloadlen);
  //Let the Kernel know where to send the raw datagram
  //Fill the in_addr with the desired destination IP and pass the struct to sendto()
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = packet.iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sending_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }
  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt(sending_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt() failed to set IP_HDRINCL ");
    exit(EXIT_FAILURE);
  }

  // Bind socket to interface index.
  if (setsockopt(sending_socket, SOL_SOCKET, SO_BINDTODEVICE, &interface,sizeof(interface)) < 0) {
    perror("setsockopt() failed to bind to interface ");
    exit(EXIT_FAILURE);
  }

  if (sendto(sending_socket, &packet, IP4_HDRLEN + TCP_HDRLEN + payloadlen, 0,
             (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("sendto() failed ");
    exit(EXIT_FAILURE);
  }
  print_time();
  printf(" TCP Packet sent\n");
  close(sending_socket);
}

/* =====================================================================================
 *
 *       function: build_ip_header
 *
 *         return: struct ip
 *
 *       Parameters:
 *                  int IHL - IHL
 *                  int version -version
 *                  int tos - tos
 *                  int len - length
 *                  int id - len
 *                  int flag1 - flag1
 *                  int flag2 - flag2
 *                  int flag3 - flag3
 *                  int flag4 - flag4
 *                  int ttl - ttl
 *                  int flag - flag
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Build IP Packet
 *
 * ====================================================================================*/
struct ip build_ip_header(int IHL, int version, int tos, int len, int id, int flag1, int flag2, int flag3, int flag4, int ttl, int flag) {
  int status;
  int *ip_flags = (int *)calloc(4, sizeof(int));
  struct ip iphdr;
  iphdr.ip_hl = IHL; // header length = 5
  iphdr.ip_v = version;                              // version = 4
  if(tos == 1339){
    iphdr.ip_tos = (unsigned char)1339;                            // TOS
  } else {
    iphdr.ip_tos = tos;                            // TOS
  }
  if(len == 1339){
      iphdr.ip_len =1339; // length: IP header + TCP header
  } else {
      iphdr.ip_len =htons(len); // length: IP header + TCP header
  }
  if(id == 1339){
      iphdr.ip_id = 1339;             // ID
  }else {
      iphdr.ip_id = htons(id);             // ID
  }
  if(id == 1339){
      iphdr.ip_id = 1339;             // ID
  }else {
      iphdr.ip_id = htons(id);             // ID
  }
  ip_flags[0] = flag1;                    // Zero
  ip_flags[1] = flag2;                    // Don't frag
  ip_flags[2] = flag3;                    // More frag
  ip_flags[3] = flag4;                    // Frag offset
  iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) +(ip_flags[2] << 13) + ip_flags[3]);
  if(ttl == 1339){
      iphdr.ip_ttl = (unsigned char)1339;       // TTL
  }else {
      iphdr.ip_ttl = ttl;       // TTL
  }
  if(flag == TCP){
    iphdr.ip_p = IPPROTO_TCP; // Protocol
  }else if (flag == UDP){
    iphdr.ip_p = IPPROTO_UDP; // Protocol 17 is UDP
  }else if (flag == ICMP){
    iphdr.ip_p = IPPROTO_ICMP; // Protocol 1 is ICMP
  }
  // Source IPv4 address (32 bits)
  if ((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    perror("inet_pton, src_ip");
    exit(EXIT_FAILURE);
  }
  // Destination IPv4 address (32 bits)
  if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    perror("inet_pton, dst_ip");
    exit(EXIT_FAILURE);
  }
  iphdr.ip_sum = 1;
  iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);
  free(ip_flags);
  return iphdr;
}

/* =====================================================================================
 *
 *       function: build_tcp_header
 *
 *         return: struct tcphdr
 *
 *       Parameters:
 *               int seq - seq
 *               int ack - ack
 *               int reserved - reserved
 *               int offset - offset
 *               int flags - flags
 *               int window_size - window size
 *               int urgent - urgent
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Build TCP Packet
 *
 * ====================================================================================*/
struct tcphdr build_tcp_header(int seq, int ack, int reserved, int offset,int flags, int window_size, int urgent) {
  int *tcp_flags;
  struct tcphdr tcphdr;
  tcp_flags = (int *)calloc(8, sizeof(int));

  if (src_port == 1339) {
    tcphdr.th_sport = 1339;
  } else {
    tcphdr.th_sport = htons(src_port);
  }
  if (dst_port == 1339) {
    tcphdr.th_dport = 1339;
  } else {
    tcphdr.th_dport = htons(dst_port);
  }
  if(seq == 1339){
    tcphdr.th_seq = 1339; // SEQ
  } else {
    tcphdr.th_seq = htonl(seq); // SEQ
  }
  if(ack == 1339){
    tcphdr.th_ack = 1339; // ACK - 0 for first packet
  }else {
    tcphdr.th_ack = htonl(ack); // ACK - 0 for first packet
  }

  tcphdr.th_x2 = reserved;               // Reserved
  tcphdr.th_off = offset; // Offset

  // Flags (8 bits)
  if (flags == PSHACK) {
    tcp_flags[0] = 0; // FIN
    tcp_flags[1] = 0; // SYN
    tcp_flags[3] = 1; // PSH
    tcp_flags[4] = 1; // ACK
    tcp_flags[2] = 0; // RST
  } else if (flags == SYNACK) {
    tcp_flags[0] = 0; // FIN
    tcp_flags[1] = 1; // SYN
    tcp_flags[3] = 0; // PSH
    tcp_flags[4] = 1; // ACK
    tcp_flags[2] = 0; // RST
  } else if (flags == FINACK) {
    tcp_flags[0] = 1; // FIN
    tcp_flags[1] = 0; // SYN
    tcp_flags[3] = 0; // PSH
    tcp_flags[4] = 1; // ACK
    tcp_flags[2] = 0; // RST
  } else if (flags == FIN) {
    tcp_flags[0] = 1; // FIN
    tcp_flags[1] = 0; // SYN
    tcp_flags[3] = 0; // PSH
    tcp_flags[4] = 0; // ACK
    tcp_flags[2] = 0; // RST
  } else if (flags == SYN) {
    tcp_flags[0] = 0; // FIN
    tcp_flags[1] = 1; // SYN
    tcp_flags[3] = 0; // PSH
    tcp_flags[4] = 0; // ACK
    tcp_flags[2] = 0; // RST
  } else if (flags == ACK) {
    tcp_flags[0] = 0; // FIN
    tcp_flags[1] = 0; // SYN
    tcp_flags[3] = 0; // PSH
    tcp_flags[4] = 1; // ACK
    tcp_flags[2] = 0; // RST
  } else if (flags == RST) {
    tcp_flags[0] = 0; // FIN
    tcp_flags[1] = 0; // SYN
    tcp_flags[3] = 0; // PSH
    tcp_flags[4] = 0; // ACK
    tcp_flags[2] = 1; // RST
  }
  tcp_flags[5] = 0; // URG
  tcp_flags[6] = 0; // ECE
  tcp_flags[7] = 0; // CWR
  tcphdr.th_flags = 0;
  for (int i = 0; i < 8; i++) {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }
  //64240
  if(window_size == 1339){
    tcphdr.th_win = 1339; // Window size
  } else {
    tcphdr.th_win = htons(window_size); // Window size
  }

  if(urgent == 1339){
    tcphdr.th_urp = 1339;     // Urgent Pointer
  }else {
    tcphdr.th_urp = htons(urgent);     // Urgent Pointer
  }
  free(tcp_flags);
  return tcphdr;
}


/* =====================================================================================
 *
 *       function: build_udp_header
 *
 *         return: struct udphdr
 *
 *       Parameters:
 *               int len - length
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Build UDP Packet
 *
 * ====================================================================================*/
struct udphdr build_udp_header(int len) {
  struct udphdr udphdr;
  udphdr.source = htons(src_port);
  udphdr.dest = htons(dst_port);

  /*if(len == 1339){
    printf("FUZZING UDP LEN\n");
    udphdr.len = 1339; // Length of Datagram = UDP Header + UDP Data
  }else {*/
    udphdr.len = htons(len); // Length of Datagram = UDP Header + UDP Data
  //}

  return udphdr;
}


/* =====================================================================================
 *
 *       function: build_icmp_header
 *
 *         return: struct icmphdr
 *
 *       Parameters:
 *               int type - type
 *               int code - code
 *               int id - id
 *               int seq - sequence number
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Build ICMP Packet
 *
 * ====================================================================================*/
struct icmp build_icmp_header(int type, int code, int id, int seq) {
  struct icmp icmphdr;
  //ICMP_ECHO
  if(type == 1339){
      icmphdr.icmp_type = (unsigned char)1339;         // message code - 0
  } else {
      icmphdr.icmp_type = type;         // message code - 0
  }
  if(code == 1339){
      icmphdr.icmp_code = (unsigned char)1339;         // message code - 0
  } else {
      icmphdr.icmp_code = code;         // message code - 0
  }
  if(id == 1339){
      icmphdr.icmp_id = 1339; // usually PID of sending process
  }else {
      icmphdr.icmp_id = htons(id); // usually PID of sending process
  }
  if(seq == 1339){
      icmphdr.icmp_seq = 1339;   // starts at 0
  } else {
      icmphdr.icmp_seq = htons(seq);   // starts at 0
  }
  icmphdr.icmp_cksum = 0;
  return icmphdr;
}


/* =====================================================================================
 *
 *       function: print_raw_ip_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct ip ip - ip struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw IP Packet
 *
 * ====================================================================================*/
void print_raw_ip_packet(struct ip ip){
   print_time();
   printf(" %02x %02x %02x %i %02x %02x %i %02x %s %s %02x\n",ip.ip_hl,ip.ip_v, ip.ip_tos, ntohs(ip.ip_len), ip.ip_id, ip.ip_off, ip.ip_ttl,ip.ip_p, src_ip, dst_ip, ip.ip_sum);
}

/* =====================================================================================
 *
 *       function: print_raw_tcp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct tcphdr tcphdr - tcp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw tcp Packet
 *
 * ====================================================================================*/
void print_raw_tcp_packet(struct tcphdr tcphdr){
   print_time();
   printf(" %i %i %02x %i %02x %02x %02x %i %02x\n",src_port, dst_port,ntohl(tcphdr.th_seq), ntohl(tcphdr.th_ack),tcphdr.th_x2,tcphdr.th_off,tcphdr.th_flags, ntohs(tcphdr.th_win), ntohs(tcphdr.th_urp));

}


/* =====================================================================================
 *
 *       function: print_raw_udp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct tcphdr udphdr - udp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw udp Packet
 *
 * ====================================================================================*/
void print_raw_udp_packet(struct udphdr udphdr){
   print_time();
   printf(" %i %i %i\n",src_port, dst_port,ntohs(udphdr.len));

}


/* =====================================================================================
 *
 *       function: print_raw_udp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct tcphdr udphdr - udp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw udp Packet
 *
 * ====================================================================================*/
void print_raw_icmp_packet(struct icmp icmp){
   print_time();
   printf(" %i %i %i %i\n",icmp.icmp_type, icmp.icmp_code,ntohs(icmp.icmp_id), ntohs(icmp.icmp_seq));

}

/* =====================================================================================
 *
 *       function: print_raw_udp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct tcphdr udphdr - udp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw udp Packet
 *
 * ====================================================================================*/

void print_tcp_packet(struct tcp_packet tcp){
    print_raw_ip_packet(tcp.iphdr);
    print_raw_tcp_packet(tcp.tcphdr);
    print_time();
    printf(" Payload: %s\n",tcp.payload);
}


/* =====================================================================================
 *
 *       function: print_raw_udp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct tcphdr udphdr - udp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw udp Packet
 *
 * ====================================================================================*/
void print_udp_packet(struct udp_packet udp){
    print_raw_ip_packet(udp.iphdr);
    print_raw_udp_packet(udp.udphdr);
    print_time();
    printf(" Payload: %s\n",udp.payload);
}


/* =====================================================================================
 *
 *       function: print_raw_icmp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct icm_packet icmp - icmp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw icmp Packet
 *
 * ====================================================================================*/
void print_icmp_packet(struct icmp_packet icmp){
    print_raw_ip_packet(icmp.iphdr);
    print_raw_icmp_packet(icmp.icmphdr);
    print_time();
    printf(" Payload: %s\n",icmp.payload);
}


/* =====================================================================================
 *
 *       function: log_print_time()
 *
 *         return: void
 *
 *       Parameters:
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Print the current time
 *
 * ====================================================================================*/
void log_print_time() {
    time_t t = time(NULL);
    struct tm tm = * localtime( & t);
    fprintf(log_file,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}


/* =====================================================================================
 *
 *       function: log_print_raw_ip_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               struct ip ip - udp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print ip packet to log file
 *
 * ====================================================================================*/
void log_print_raw_ip_packet(struct ip ip) {
    log_print_time();
    fprintf(log_file," %02x %02x %02x %i %02x %02x %i %02x %s %s %02x\n", ip.ip_hl, ip.ip_v, ip.ip_tos, ntohs(ip.ip_len), ip.ip_id, ip.ip_off, ip.ip_ttl, ip.ip_p, src_ip, dst_ip, ip.ip_sum);
}


/* =====================================================================================
 *
 *       function: log_print_raw_tcp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct tcphdr tcphdr - tcp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw tcp Packet to log file
 *
 * ====================================================================================*/
void log_print_raw_tcp_packet(struct tcphdr tcphdr) {
    log_print_time();
    fprintf(log_file, " %i %i %02x %i %02x %02x %02x %i %02x\n", src_port, dst_port, ntohl(tcphdr.th_seq), ntohl(tcphdr.th_ack), tcphdr.th_x2, tcphdr.th_off, tcphdr.th_flags, ntohs(tcphdr.th_win), ntohs(tcphdr.th_urp));

}


/* =====================================================================================
 *
 *       function: log_print_raw_udp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct udphdr udphdr - udp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw udp Packet to log file
 *
 * ====================================================================================*/
void log_print_raw_udp_packet(struct udphdr udphdr) {
    log_print_time();
    fprintf(log_file," %i %i %i\n", src_port, dst_port, ntohs(udphdr.len));

}


/* =====================================================================================
 *
 *       function: print_raw_icmp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct icmp icmp - icmp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw icmp Packet to log file
 *
 * ====================================================================================*/
void log_print_raw_icmp_packet(struct icmp icmp) {
    log_print_time();
    fprintf(log_file," %i %i %i %i\n", icmp.icmp_type, icmp.icmp_code, ntohs(icmp.icmp_id), ntohs(icmp.icmp_seq));

}


/* =====================================================================================
 *
 *       function: print_raw_tcp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct tcphdr tcphdr - tcp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw tcp Packet to log file
 *
 * ====================================================================================*/
void log_print_tcp_packet(struct tcp_packet tcp) {
    log_print_raw_ip_packet(tcp.iphdr);
    log_print_raw_tcp_packet(tcp.tcphdr);
    log_print_time();
    fprintf(log_file," Payload: %s\n", tcp.payload);
}


/* =====================================================================================
 *
 *       function: log_print_raw_udp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct tcphdr udphdr - udp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw udp Packet to log file
 *
 * ====================================================================================*/
void log_print_udp_packet(struct udp_packet udp) {
    log_print_raw_ip_packet(udp.iphdr);
    log_print_raw_udp_packet(udp.udphdr);
    log_print_time();
    fprintf(log_file," Payload: %s\n", udp.payload);
}


/* =====================================================================================
 *
 *       function: log_print_raw_icmp_packet
 *
 *         return: void
 *
 *       Parameters:
 *               struct icmp_paacket icmp - icmp struct packet
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print raw icmp Packet to log file
 *
 * ====================================================================================*/
void log_print_icmp_packet(struct icmp_packet icmp) {
    log_print_raw_ip_packet(icmp.iphdr);
    log_print_raw_icmp_packet(icmp.icmphdr);
    log_print_time();
    fprintf(log_file," Payload: %s\n", icmp.payload);
}


/* =====================================================================================
 *
 *       function: generate_rand()
 *
 *         return: void
 *
 *       Parameters:
 *               double value - value to set random
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Generate a random value
 *
 * ====================================================================================*/
int generate_rand(double value) {
  return (int)(rand() % (int)value);
}


/* =====================================================================================
 *
 *       function: send_raw_syn_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               int sending_socket - sending socket
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Send a tcp raw syn packet
 *
 * ====================================================================================*/
void send_raw_syn_packet(int sending_socket){
    struct sockaddr_in tcpclient; //for receiving icmp packets
    socklen_t len; //for sending normal udp packets
    len = sizeof(tcpclient);
    char buf[IP_MAXPACKET];
    //send SYN packet
    send_raw_tcp_packet(build_ip_header(5,4,0,40,0,0,0,0,0,255,7),build_tcp_header(generate_rand(UINT_MAX/2),0,0,5,SYN,64249,0), NULL);
    syn_flag = false;
    packet_info = packet_capture(filter, packet_info);
    /*
    if(recvfrom(sending_socket, buf, sizeof(buf), 0, (struct sockaddr*)&tcpclient, &len) < 0){
      perror("recvfrom");
    } else{
        recv_tcp_packet(buf);
    }*/
}


/* =====================================================================================
 *
 *       function: send_raw_fin_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               int sending_socket - sending socket
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Send a tcp raw inn packet
 *
 * ====================================================================================*/
void send_raw_fin_packet(int sending_socket){
    struct sockaddr_in tcpclient; //for receiving icmp packets
    socklen_t len; //for sending normal udp packets
    len = sizeof(tcpclient);
    char buf[IP_MAXPACKET];
    send_raw_tcp_packet(build_ip_header(5,4,0,40,0,0,0,0,0,255,7),build_tcp_header((packet_info.ack),(packet_info.seq),0,5,FINACK,64249,0), NULL);
    fin_flag = true;
    if(fin_flag){
        /*if(recvfrom(sending_socket, buf, sizeof(buf), 0, (struct sockaddr*)&tcpclient, &len) < 0){
          perror("recvfrom");
        } else{
            recv_tcp_packet(buf);
        }
        memset(buf, '\0',sizeof(buf));*/
        packet_info = packet_capture(filter, packet_info);
    }
}


/* =====================================================================================
 *
 *       function: start_icmp_client()
 *
 *         return: void
 *
 *       Parameters:
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Start icmp client
 *
 * ====================================================================================*/
int start_icmp_client(){
    int sending_socket;

	if((sending_socket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP))<0){
		perror("socket");
		exit(0);
	}
	return sending_socket;
}


/* =====================================================================================
 *
 *       function: start_tcp_raw_client()
 *
 *         return: void
 *
 *       Parameters:
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Start tcp raw client
 *
 * ====================================================================================*/
int start_tcp_raw_client(){
    int sending_socket;

	if((sending_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP))<0){
		perror("socket");
		exit(0);
	}
	return sending_socket;
}


/* =====================================================================================
 *
 *       function: recv_icmp_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               void *packet - raw packet bytes
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              ICMP receive loop
 *
 * ====================================================================================*/
char *recv_icmp_packet(void *packet){
  time_t t = time(NULL);
  struct tm tm = * localtime( & t);
  struct iphdr *ip;
  struct icmp *icmp;
  const char *payload;
  int size_ip;
  int size_icmp;
  int size_payload;
  ip = (struct iphdr *)(packet);
  size_ip = ip->ihl * 4;
  icmp = (struct icmp *)(packet + size_ip);
  size_icmp = ICMP_HDRLEN;
  payload = (char *)(packet + size_ip + size_icmp);
  size_payload = ntohs(ip->tot_len) - (size_ip + size_icmp);
  if(ip->saddr == inet_addr(dst_ip) && ip->daddr == inet_addr(src_ip)){
      print_time();
      printf(" %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
      print_time();
      printf(" %i %i %i %i\n",icmp->icmp_type, icmp->icmp_code,ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
      print_time();
      printf(" Payload: %s\n", payload);
      fprintf(replys, "Test case #%i , reply from %s\n",(casecount +1), target);
      fprintf(replys,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
      fprintf(replys," %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
      fprintf(replys,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
      fprintf(replys," %i %i %i %i\n",icmp->icmp_type, icmp->icmp_code,ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
      fprintf(replys,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
      fprintf(replys," Payload: %s\n\n", payload);
      return (char *)payload;
  } else {
    //wrong source and destination ip
    replay = true;
    return NULL;
  }
}


/* =====================================================================================
 *
 *       function: recv_tcp_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               void *packet - raw packet bytes
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              TCP receive loop
 *
 * ====================================================================================*/
char *recv_tcp_packet(void *packet){
  time_t t = time(NULL);
  struct tm tm = * localtime( & t);
  struct iphdr *ip;
  struct tcphdr *tcp;
  const char *payload;
  int size_ip;
  int size_tcp;
  ip = (struct iphdr *)(packet);
  size_ip = ip->ihl * 4;
  tcp = (struct tcphdr *)(packet + size_ip);
  size_tcp = TCP_HDRLEN;
  payload = (char *)(packet + size_ip + size_tcp);
  if(ip->saddr == inet_addr(dst_ip) && ip->daddr == inet_addr(src_ip) && ntohs(tcp->th_sport) == dst_port && ntohs(tcp->th_dport) == src_port){
      if(!tcp->rst){
          if(tcp->fin && tcp->ack){
              if(fin_flag){
                  send_raw_tcp_packet(build_ip_header(5,4,0,40,0,0,0,0,0,255,7),build_tcp_header((ntohl(tcp->ack_seq)),(ntohl(tcp->th_seq)+1),0,5,ACK,64240,0), NULL);
              }
          }else if(tcp->syn && tcp->ack){
              if(!syn_flag){
                  packet_info.seq = ntohl(tcp->ack_seq);
                  packet_info.ack = ntohl(tcp->th_seq) + 1;
                  send_raw_tcp_packet(build_ip_header(5,4,0,40,0,0,0,0,0,255,7),build_tcp_header((ntohl(tcp->ack_seq)),(ntohl(tcp->th_seq)+1),0,5,ACK,64240,0), NULL);
                  syn_flag = true;
              }
          }else if(tcp->psh && tcp->ack){
                  packet_info.seq = ntohl(tcp->th_seq) + ((ntohs(ip->tot_len)-(TCP_HDRLEN+IP4_HDRLEN)));
                  packet_info.ack = ntohl(tcp->ack_seq);
                  send_raw_tcp_packet(build_ip_header(5,4,0,40,0,0,0,0,0,255,7),build_tcp_header((ntohl(tcp->ack_seq)),(ntohl(tcp->th_seq)+((ntohs(ip->tot_len)-(TCP_HDRLEN+IP4_HDRLEN)))),0,5,ACK,64240,0), NULL);
                  print_time();
                  printf(" %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
                  fprintf(replys,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
                  fprintf(replys, "Test case #%i , reply from %s\n",(casecount +1), target);
                  fprintf(replys,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
                  fprintf(replys," %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
                  print_time();
                  printf("  %i %i %02x %i %02x %02x %02x %i %02x\n",src_port, dst_port,ntohl(tcp->th_seq), ntohl(tcp->th_ack),tcp->th_x2,tcp->th_off,tcp->th_flags, ntohs(tcp->th_win), ntohs(tcp->th_urp));
                  fprintf(replys,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
                  fprintf(replys,"  %i %i %02x %i %02x %02x %02x %i %02x\n",src_port, dst_port,ntohl(tcp->th_seq), ntohl(tcp->th_ack),tcp->th_x2,tcp->th_off,tcp->th_flags, ntohs(tcp->th_win), ntohs(tcp->th_urp));
                  print_time();
                  printf(" Payload: %s \n", payload);
                  fprintf(replys,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
                  fprintf(replys," Payload: %s \n\n", payload);
                  pshack_flag = true;
                  return (char *)payload;
          }else if(tcp->syn){
              return "syn";
          }else if (tcp->fin){
              return "fin";
          }else if(tcp->rst){
              return "rst";
          }else if (tcp->ack){
              return "ack";
          }
      }
  }
  return "none";
}
/*
int start_udp_server(int PORT){
	int optval = 1;
	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(PORT);
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    int sending_socket;
    printf("Listening on port %i\n",PORT);
	if((sending_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP))<0){
		perror("socket");
		exit(0);
	}

	setsockopt(sending_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

	if ((bind(sending_socket, (struct sockaddr *)&server_address, sizeof(server_address))) < 0) {
		printf("could not bind socket\n");
	}
	return sending_socket;
}

char *recv_udp_packet(void *packet){
  int size_ip, size_udp,size_payload;
  struct iphdr *ip;
  struct udphdr *udp;
  const char *payload;
  ip = (struct iphdr *)(packet);
  size_ip = ip->ihl * 4;
  udp = (struct udphdr *)(packet + size_ip);
  size_udp = ICMP_HDRLEN;
  payload = (char *)(packet + size_ip + size_udp);
  size_payload = ntohs(ip->tot_len) - (size_ip + size_udp);
  if(ip->saddr == inet_addr(dst_ip) && ip->daddr == inet_addr(src_ip) && htons(udp->source) == dst_port && htons(udp->dest) == src_port){
      print_time();
      printf(" %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
      print_time();
      printf(" %i %i %i\n",src_port, dst_port,ntohs(udp->len));
      print_time();
      printf(" payload: %s\n", payload);
      return (char *)payload;
  } else {
    //wrong source and destination ip
    replay = true;
    return NULL;
  }
}*/
