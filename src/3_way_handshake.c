#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#define SYN 0
#define ACK 1
#define SYNACK 2
#define FIN 3
#define PSHACK 4
#define IP4_HDRLEN 20 // Length of IPv4 Header
#define TCP_HDRLEN 20 // Length of TCP Header

struct packet_info{

} packet_info;

struct tcp_packet {
  struct ip iphdr;
  struct tcphdr tcphdr;
  unsigned char payload[BUFSIZ];
} tcp_packet;

uint16_t checksum(uint16_t *, int);
uint16_t tcp4_checksum(struct ip, struct tcphdr);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);
int generate_rand(double value);
struct addrinfo set_hints(int family, int socktype, int flags);
struct ifreq search_interface(char *ifc);
char *resolve_host(char *target, struct addrinfo hints);
void send_raw_tcp_packet(int src_port, int dst_port, struct ifreq interface, char* src_ip, char* dst_ip, int seq, int ack, int flags);
int Packetcapture(char *FILTER, struct packet_info packet_info);
void ReadPacket(u_char *args, const struct pcap_pkthdr *pkthdr,const u_char *packet);
void ParseTCP(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet);
void ParseIP(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet);
void ParsePayload(struct packet_info *packet_info, const u_char *payload, int len);

int ack;
int seq;

int main(int argc, char **argv) {
  struct addrinfo hints;
  char *target, *src_ip, *dst_ip;
  struct ifreq ifr;

  if(geteuid() != 0) {
    printf("Must run as root\n");
    exit(1);
    }

  target = (char *) calloc (40, sizeof(char));
  src_ip = (char *) calloc (INET_ADDRSTRLEN, sizeof(char));
  dst_ip = (char *) calloc (INET_ADDRSTRLEN, sizeof(char));

  // Interface to send packet through.
  ifr = search_interface("wlp2s0");

  strcpy (src_ip, "192.168.1.86");
  strcpy (target, "192.168.1.72");
  /*char src[BUFSIZ];
  char dst[BUFSIZ];
  strcpy (src, "192.168.1.86");
  strcpy (dst, "192.168.1.72");*/
  hints = set_hints(AF_INET, SOCK_STREAM, hints.ai_flags | AI_CANONNAME);

  // Resolve target using getaddrinfo().
  dst_ip = resolve_host(target, hints);
  send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 0, 0, SYN);
  send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 1, 1, ACK);
  //Packetcapture("host 192.168.1.72 and tcp");
  return (EXIT_SUCCESS);
}

int Packetcapture(char *FILTER, struct packet_info packet_info) {
//int Packetcapture(char *FILTER) {
  pcap_t *interfaceinfo;
  char errorbuffer[PCAP_ERRBUF_SIZE];
  struct bpf_program fp; // holds fp program info
  pcap_if_t *interface_list;
  bpf_u_int32 netp = 0; // holds the ip

  // find the first network device capable of packet capture
  if (pcap_findalldevs(&interface_list, errorbuffer) == -1) {
    printf("pcap_findalldevs: %s\n", errorbuffer);
    exit(0);
  }

  // open the network device
  if ((interfaceinfo = pcap_open_live(interface_list->name, BUFSIZ, 1, -1,
                                      errorbuffer)) == NULL) {
    printf("pcap_open_live(): %s\n", errorbuffer);
    exit(0);
  }

  if (pcap_compile(interfaceinfo, &fp, FILTER, 0, netp) == -1) {
    perror("pcap_comile");
  }

  if (pcap_setfilter(interfaceinfo, &fp) == -1) {
    perror("pcap_setfilter");
  }

  pcap_loop(interfaceinfo, -1, ReadPacket, (u_char*)&packet_info);
  return 0;
}

void ReadPacket(u_char *args, const struct pcap_pkthdr *pkthdr,const u_char *packet) {

  struct packet_info* packet_info = NULL;
  packet_info = (struct filter *) args;
  // grab the type of packet
  struct ether_header *ethernet;
  u_char dst_host[ETHER_ADDR_LEN], src_host[ETHER_ADDR_LEN];
  ethernet = (struct ether_header *)packet;
  u_int16_t type = ntohs(ethernet->ether_type);

  // TODO: May not print the mac address not sure if really needed
  // ether_dhost
  // ether_shost
  // ether_type
  if (type == ETHERTYPE_IP) {
    ParseIP(packet_info, pkthdr, packet);
  }
}

void ParseIP(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
  // const struct my_ip* ip;
  struct iphdr *ip;
  u_int length = pkthdr->len;
  u_int hlen, off, version;
  int len;

  // skip past the ethernet header
  ip = (struct iphdr *)(packet + sizeof(struct ether_header));
  length -= sizeof(struct ether_header);

  if (length < sizeof(struct iphdr)) {
    printf("Packet length is incorrect %d", length);
    exit(1);
  }

  len = ntohs(ip->tot_len);
  hlen = ip->ihl;
  version = ip->version;
  off = ntohs(ip->frag_off);

  printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ip->ihl,ip->version, ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
  if (version != 4) {
    perror("Unknown error");
    exit(1);
  } else if (hlen < 5) {
    perror("Bad header length");
    exit(1);
  } else if (length < (u_int)len) {
    perror("Truncated IP");
    exit(1);
  } else if (ip->protocol == IPPROTO_TCP) {
    ParseTCP(packet_info, pkthdr, packet);
  }
}

void ParseTCP(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
  struct iphdr *ip;
  // const struct sniff_tcp *tcp=0;
  struct tcphdr *tcp;
  const u_char *payload;
  int size_ip;
  int size_tcp;
  int size_payload;

  printf("\nTCP Packet\n");

  ip = (struct iphdr *)(packet + 14);
  // size_ip = IP_HL(ip)*4;
  // tcp = (struct sniff_tcp*)(packet + 14 + size_ip);
  // size_tcp = TH_OFF(tcp)*4;
  // header length is IHL * 4
  size_ip = ip->ihl * 4;
  tcp = (struct tcphdr *)(packet + 14 + size_ip);
  //#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  size_tcp = tcp->doff * 4;
  printf("size_tcp: %c", size_tcp);

  if (size_tcp < 20) {
    perror("TCP: Control packet length is incorrect");
    exit(1);
  }
  //dont print if rst packet
  if(!tcp->rst){
      printf("Source port: %d\n", ntohs(tcp->th_sport));
      printf("Destination port: %d\n", ntohs(tcp->th_dport));
      printf("Sequence #: %u\n", ntohs(tcp->seq));
      printf("Acknowledgement: %u \n", ntohs(tcp->ack_seq));
      printf("Syn: %d\n", tcp->syn);
      //printf("Fin: %d\n", tcp->fin);
      //printf("Rst: %d\n", tcp->rst);
      printf("Psh: %d\n", tcp->psh);
      printf("Ack: %d\n", tcp->ack);
  }
  payload = (u_char *)(packet + 14 + size_ip + size_tcp);
  size_payload = ntohs(ip->tot_len) - (size_ip + size_tcp);

  if (size_payload > 0) {
    printf("Payload (%d bytes):\n", size_payload);
    ParsePayload(packet_info,payload, size_payload);
  }
}

void ParsePayload(struct packet_info *packet_info, const u_char *payload, int len) {
  struct iphdr *ip;
  struct tcphdr *tcp;
  // const struct sniff_tcp *tcp=0;
  // const struct my_ip *ip;
  printf("Payload: \n");
  printf("%s", payload);
  printf("%08X", payload); // print payload in HEX
}

// TODO: add to seperate library once working!
char *resolve_host(char *target, struct addrinfo hints) {
  int status;
  void *tmp;
  char *dst_ip = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
  struct addrinfo *res;
  struct sockaddr_in *ipv4;

  if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
    exit(EXIT_FAILURE);
  }

  ipv4 = (struct sockaddr_in *)res->ai_addr;
  tmp = &(ipv4->sin_addr);

  if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf(stderr, "inet_ntop() failed.\nError message: %s", strerror(status));
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

int generate_rand(double value) {
  time_t t;
  srand((unsigned)time(&t));
  return 1 + (int)(value * rand() / RAND_MAX + 1.0);
}

void send_raw_tcp_packet(int src_port, int dst_port, struct ifreq interface, char* src_ip, char* dst_ip, int seq, int ack, int flags) {
  struct sockaddr_in sin;
  int i, *ip_flags, *tcp_flags, status, sending_socket;
  const int on = 1;
  struct tcp_packet packet;
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
  if(seq != 0){
    packet.tcphdr.th_seq = htonl(seq); //SEQ
  } else {
    packet.tcphdr.th_seq = htonl(0); //SEQ
  }
  if(ack != 0){
    packet.tcphdr.th_ack = htonl(ack); //ACK - 0 for first packet
  } else {
    packet.tcphdr.th_ack = htonl(0); //ACK - 0 for first packet
  }
  packet.tcphdr.th_x2 = 0; //Reserved
  packet.tcphdr.th_off = TCP_HDRLEN / 4; //Offset

  // Flags (8 bits)
  if(flags == FIN){
    tcp_flags[0] = 1; //Fin
  } else {
    tcp_flags[0] = 0; //Fin
  }
  if(flags == SYN){
    tcp_flags[1] = 1; //SYN
  } else {
    tcp_flags[1] = 0; //SYN
  }
  if(flags == PSHACK){
    tcp_flags[3] = 1; //PSH
  } else {
    tcp_flags[3] = 0; //PSH
  }
  if(flags == PSHACK){
    tcp_flags[4] = 1; //ACK
  } else if(flags == ACK){
    tcp_flags[4] = 1; //ACK
  }else {
    tcp_flags[4] = 0; //ACK
  }
  tcp_flags[2] = 0; //RST
  tcp_flags[5] = 0; //URG
  tcp_flags[6] = 0; //ECE
  tcp_flags[7] = 0; //CWR
  packet.tcphdr.th_flags = 0;
  for (i = 0; i < 8; i++) {
    packet.tcphdr.th_flags += (tcp_flags[i] << i);
  }

  packet.tcphdr.th_win = htons(65535); //Window size
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

  // Close socket descriptor.
  close(sending_socket);

  // Free allocated memory.
  free(ip_flags);
  free(tcp_flags);
}
