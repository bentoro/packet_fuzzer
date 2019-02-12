
#include "raw_socket_wrappers.h"

// TODO: add to seperate library once working!
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

// TODO: add to seperate library once working!
struct addrinfo set_hints(int family, int socktype, int flags) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));

  hints.ai_family = family;     // IPV4
  hints.ai_socktype = socktype; // TCP
  hints.ai_flags = flags;

  return hints;
}

struct ifreq search_interface(char *ifc) {
  // dont need to return socket as it is only used to search for the interface index
  char *interface = (char *)malloc(40 * sizeof(char));
  memset(interface, 0, 40 * sizeof(char));
  struct ifreq ifr;
  int tmp_socket;

  // Interface to send packet through.
  strcpy(interface, ifc);

  // interface/
  // return interface
  // Submit request for a socket descriptor to look up interface.
  if ((tmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("socket() failed to get socket descriptor for using ioctl() ");
    exit(EXIT_FAILURE);
  }

  // Use ioctl() to look up interface index which we will use to
  // bind socket descriptor sd to specified interface with setsockopt() since
  // none of the other arguments of sendto() specify which interface to use.
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
  if (ioctl(tmp_socket, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl() failed to find interface ");
    exit(0);
  }

  printf("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

  close(tmp_socket);
  free(interface);
  return ifr;
}

// Computing the internet checksum (RFC 1071).
uint16_t checksum(uint16_t *addr, int len) {
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *)addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr) {
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  // ptr points to beginning of buffer buf
  ptr = &buf[0];

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
  svalue = htons(sizeof(tcphdr));
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

  return checksum((uint16_t *)buf, chksumlen);
}

uint16_t udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen){
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

int generate_rand(double value) {
  time_t t;
  srand((unsigned)time(&t));
  return 1 + (int)(value * rand() / RAND_MAX + 1.0);
}

void send_raw_udp_packet(int src_port, int dst_port, struct ifreq interface, char* src_ip, char* dst_ip, int seq, int ack, char *data, int flags) {
  struct sockaddr_in sin;
  struct udp_packet packet;
  int i, *ip_flags, *tcp_flags, status, sending_socket, payloadlen = 0;
  const int on = 1;

  ip_flags = (int *)calloc(4, sizeof(int));
  tcp_flags = (int *)calloc(8, sizeof(int));

  if(data != NULL){
        sprintf (packet.payload, "%s", data);
        payloadlen = strlen(packet.payload);
  }

  //IP HEADER
  packet.iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
  packet.iphdr.ip_v = 4; //ip veriosn
  packet.iphdr.ip_tos = 0;
  packet.iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + payloadlen); // IP header + UDP header + payload len
  packet.iphdr.ip_id = htons (0);
  ip_flags[0] = 0; //Zero
  ip_flags[1] = 0; //Don't frag
  ip_flags[2] = 0; // More frag
  ip_flags[3] = 0; //Frag offset
  packet.iphdr.ip_off = htons ((ip_flags[0] << 15)+ (ip_flags[1] << 14)+ (ip_flags[2] << 13)+  ip_flags[3]);
  packet.iphdr.ip_ttl = 255; //TTL
  packet.iphdr.ip_p = IPPROTO_UDP; //Protocol 17 is UDP

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(packet.iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(packet.iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  packet.iphdr.ip_sum = 0;
  packet.iphdr.ip_sum = checksum ((uint16_t *) &packet.iphdr, IP4_HDRLEN);

  //UDP header
  packet.udphdr.source = htons (4950);
  packet.udphdr.dest = htons (8045);
  packet.udphdr.len = htons (UDP_HDRLEN + payloadlen); //Length of Datagram = UDP Header + UDP Data
  packet.udphdr.check = udp4_checksum (packet.iphdr, packet.udphdr, (uint8_t *)packet.payload, payloadlen);

  // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
  // For that, we need to specify a destination for the kernel in order for it
  // to decide where to send the raw datagram. We fill in a struct in_addr with
  // the desired destination IP address, and pass this structure to the sendto() function.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = packet.iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sending_socket = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt (sending_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    perror ("setsockopt() failed to set IP_HDRINCL ");
    exit (EXIT_FAILURE);
  }

  // Bind socket to interface index.
  if (setsockopt (sending_socket, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    perror ("setsockopt() failed to bind to interface ");
    exit (EXIT_FAILURE);
  }

  // Send packet.
  if (sendto (sending_socket, &packet, IP4_HDRLEN + UDP_HDRLEN + payloadlen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    perror ("sendto() failed ");
    exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sending_socket);

  // Free allocated memory.
  free(ip_flags);
}


void send_raw_tcp_packet(int src_port, int dst_port, struct ifreq interface, char* src_ip, char* dst_ip, int seq, int ack, int flags) {
  struct sockaddr_in sin;
  int *ip_flags, *tcp_flags, status, sending_socket;
  const int on = 1;
  struct tcp_packet packet;
  memset(&packet, 0, sizeof(struct tcp_packet));
  ip_flags = (int *)calloc(4, sizeof(int));
  tcp_flags = (int *)calloc(8, sizeof(int));

  // IPv4 header
  packet.iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t); //header length = 5
  packet.iphdr.ip_v = 4; //version = 4
  packet.iphdr.ip_tos = 0; //TOS
  packet.iphdr.ip_len = htons(IP4_HDRLEN + TCP_HDRLEN); //length: IP header + TCP header
  packet.iphdr.ip_id = htons(0); //ID
  ip_flags[0] = 0; //Zero
  ip_flags[1] = 0; //Don't frag
  ip_flags[2] = 0; //More frag
  ip_flags[3] = 0; //Frag offset
  packet.iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) +(ip_flags[2] << 13) + ip_flags[3]);
  packet.iphdr.ip_ttl = 255; //TTL
  packet.iphdr.ip_p = IPPROTO_TCP; //Protocol
  printf("src_ip: %s\n", src_ip);
  printf("dst_ip: %s\n", dst_ip);
  // Source IPv4 address (32 bits)
  if ((status = inet_pton(AF_INET, src_ip, &(packet.iphdr.ip_src))) != 1) {
      perror("inet_pton, src_ip");
      exit(EXIT_FAILURE);
  }
  // Destination IPv4 address (32 bits)
  if ((status = inet_pton(AF_INET, dst_ip, &(packet.iphdr.ip_dst))) != 1) {
      perror("inet_pton, dst_ip");
    exit(EXIT_FAILURE);
  }

  packet.iphdr.ip_sum = 0;
  packet.iphdr.ip_sum = checksum((uint16_t *)&packet.iphdr, IP4_HDRLEN);

  // TCP header
  if (src_port == 0) {
    packet.tcphdr.th_sport = generate_rand(65535.0);
  } else {
    packet.tcphdr.th_sport = src_port;
  }
  if (dst_port == 0) {
    packet.tcphdr.th_dport = generate_rand(65535.0);
  } else {
    packet.tcphdr.th_dport = htons(dst_port);
  }
  packet.tcphdr.th_seq = htonl(seq); //SEQ
  printf("SEQ: %u \n", ntohl(packet.tcphdr.th_seq));
  packet.tcphdr.th_ack = htonl(ack); //ACK - 0 for first packet
  printf("ACK: %u \n", ntohl(packet.tcphdr.th_ack));
  packet.tcphdr.th_x2 = 0; //Reserved
  packet.tcphdr.th_off = TCP_HDRLEN / 4; //Offset

  // Flags (8 bits)
  if(flags == PSHACK){
    tcp_flags[0] = 0; //FIN
    tcp_flags[1] = 0; //SYN
    tcp_flags[3] = 1; //PSH
    tcp_flags[4] = 1; //ACK
    tcp_flags[2] = 0; //RST
  }else if(flags == SYNACK){
    tcp_flags[0] = 0; //FIN
    tcp_flags[1] = 1; //SYN
    tcp_flags[3] = 0; //PSH
    tcp_flags[4] = 1; //ACK
    tcp_flags[2] = 0; //RST
  }else if(flags == FINACK){
    tcp_flags[0] = 1; //FIN
    tcp_flags[1] = 0; //SYN
    tcp_flags[3] = 0; //PSH
    tcp_flags[4] = 1; //ACK
    tcp_flags[2] = 0; //RST
  }else if(flags == FIN){
    tcp_flags[0] = 1; //FIN
    tcp_flags[1] = 0; //SYN
    tcp_flags[3] = 0; //PSH
    tcp_flags[4] = 0; //ACK
    tcp_flags[2] = 0; //RST
  } else if(flags == SYN){
    tcp_flags[0] = 0; //FIN
    tcp_flags[1] = 1; //SYN
    tcp_flags[3] = 0; //PSH
    tcp_flags[4] = 0; //ACK
    tcp_flags[2] = 0; //RST
  }else if(flags == ACK){
    tcp_flags[0] = 0; //FIN
    tcp_flags[1] = 0; //SYN
    tcp_flags[3] = 0; //PSH
    tcp_flags[4] = 1; //ACK
    tcp_flags[2] = 0; //RST
  }else if(flags == RST){
    tcp_flags[0] = 0; //FIN
    tcp_flags[1] = 0; //SYN
    tcp_flags[3] = 0; //PSH
    tcp_flags[4] = 0; //ACK
    tcp_flags[2] = 1; //RST
  }
  tcp_flags[5] = 0; //URG
  tcp_flags[6] = 0; //ECE
  tcp_flags[7] = 0; //CWR
  packet.tcphdr.th_flags = 0;
  for (int i = 0; i < 8; i++) {
    packet.tcphdr.th_flags += (tcp_flags[i] << i);
  }

  packet.tcphdr.th_win = htons(64240); //Window size
  packet.tcphdr.th_urp = htons(0); //Urgent Pointer
  packet.tcphdr.th_sum = tcp4_checksum(packet.iphdr, packet.tcphdr);

  // Empty the payload
  memset(packet.payload, 0, sizeof(packet.payload));
  // The kernel is going to prepare layer 2 information (ethernet frame header)
  // for us. For that, we need to specify a destination for the kernel in order
  // for it to decide where to send the raw datagram. We fill in a struct
  // in_addr with the desired destination IP address, and pass this structure to
  // the sendto() function.
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

  // Send packet.
  if (sendto(sending_socket, &packet, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
    perror("sendto() failed ");
    exit(EXIT_FAILURE);
  }
  printf("Packet sent\n");
  close(sending_socket);
  // Free allocated memory.
  free(ip_flags);
  free(tcp_flags);
}
