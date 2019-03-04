#include "libpcap.h"

struct packet_info packet_capture(char *FILTER, struct packet_info packet_info) {
//int Packetcapture(char *FILTER) {
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

  pcap_loop(interfaceinfo, -1, read_packet, (u_char*)&packet_info);
  return packet_info;
}

void read_packet(u_char *args, const struct pcap_pkthdr *pkthdr,const u_char *packet) {

  struct packet_info* packet_info = NULL;
  packet_info = (struct packet_info *) args;
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
    parse_ip(packet_info, pkthdr, packet);
  }
}

void parse_ip(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
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

  printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ip->version,ip->ihl, ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, htonl(ip->saddr), htonl(ip->daddr));
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
    parse_tcp(packet_info, pkthdr, packet);
  }
}

void parse_tcp(struct packet_info *packet_info, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
  struct iphdr *ip;
  struct tcphdr *tcp;
  const u_char *payload;
  int size_ip;
  int size_tcp;
  int size_payload;

  printf("\nTCP Packet\n");
  packet_info->protocol = TCP;

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
      printf("Sequence #: %u\n", ntohl(tcp->seq));
      packet_info->seq = ntohl(tcp->seq);
      printf("Acknowledgement: %u \n", ntohl(tcp->ack_seq));
      packet_info->ack = ntohl(tcp->ack_seq);
      printf("Len: %d\n", ntohs(ip->tot_len));
      if(tcp->fin && tcp->ack){
          printf("FinAck: true\n");
          packet_info->flag = FINACK;
      }else if(tcp->syn && tcp->ack){
          if(!threewayhandshake){
              send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, 1, (ntohl(tcp->th_seq) + 1), NULL, ACK);
              send_raw_tcp_packet(100, 8045, ifr, src_ip,dst_ip, 1, (ntohl(tcp->th_seq) + 1), "HELLO", PSHACK);
          }
          // Interface to send packet through.
          packet_info->flag = SYNACK;
          printf("SynAck: true\n");
      }else if(tcp->psh && tcp->ack){
          printf("PshAck: true\n");
          packet_info->flag = PSHACK;
      }else if(tcp->syn){
          printf("Syn: true\n");
          packet_info->flag = SYN;
      }else if (tcp->fin){
          printf("Fin: true\n");
          packet_info->flag = FIN;
      }else if(tcp->rst){
          printf("Rst: true\n");
          packet_info->flag = RST;
      }else if (tcp->ack){
          packet_info->flag = ACK;
          printf("Ack: true\n");
      }
  }

  /*payload = (u_char *)(packet + 14 + size_ip + size_tcp);
  size_payload = ntohs(ip->tot_len) - (size_ip + size_tcp);

  if (size_payload > 0) {
    printf("Payload (%d bytes):\n", size_payload);
    //parse_payload(packet_info,payload, size_payload);
  }*/
  pcap_breakloop(interfaceinfo);
}

void parse_payload(struct packet_info *packet_info, const u_char *payload, int len) {
  struct iphdr *ip;
  struct tcphdr *tcp;
  printf("Payload: \n");
  printf("%s", payload);
  printf("%08X", payload); // print payload in HEX
}

