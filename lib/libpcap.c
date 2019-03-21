#include "libpcap.h"

struct packet_info packet_capture(char *FILTER,struct packet_info packet_info) {
  // int Packetcapture(char *FILTER) {
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
  if ((interfaceinfo = pcap_open_live(interface_list->name, BUFSIZ, 1, -1,errorbuffer)) == NULL) {
    printf("pcap_open_live(): %s\n", errorbuffer);
    exit(0);
  }

  if (pcap_compile(interfaceinfo, &fp, FILTER, 0, netp) != 0) {
  }

  if (pcap_setfilter(interfaceinfo, &fp) != 0) {
  }

  pcap_loop(interfaceinfo, -1, read_packet, (u_char *)&packet_info);
  return packet_info;
}

void read_packet(u_char *args, const struct pcap_pkthdr *pkthdr,const u_char *packet) {

  struct packet_info *packet_info = NULL;
  packet_info = (struct packet_info *)args;
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

  if(packet_info->protocol == TCP){
      if(ip->protocol == IPPROTO_TCP){
        parse_tcp(packet_info, pkthdr, packet);
    } else {
        //replay the packet if the receieved packet is incorrect
        /*print_time();
        printf(" No reply receieved, Resending last packet\n");
        replay = true;*/
    }
  } else if(packet_info->protocol == ICMP){
    if (ip->protocol == IPPROTO_ICMP) {
        parse_icmp(packet_info, pkthdr, packet);
    } else {
        //replay the packet if the receieved packet is incorrect
        print_time();
        printf(" No reply receieved, Resending last packet\n");
        replay = true;
    }
  }else if(packet_info->protocol == UDP){
      if(ip->protocol == IPPROTO_UDP){
        parse_udp(packet_info, pkthdr, packet);
    } else {
        //replay the packet if the receieved packet is incorrect
        print_time();
        printf(" No reply receieved, Resending last packet\n");
        replay = true;
    }
  } else {
  }
  pcap_breakloop(interfaceinfo);
}

void parse_udp(struct packet_info *packet_info,const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  struct iphdr *ip;
  struct udphdr *udphdr;
  const u_char *payload;
  int size_ip;
  int size_udp;
  int size_payload;
  ip = (struct iphdr *)(packet + SIZE_ETHERNET);
  size_ip = ip->ihl * 4;
  udphdr = (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);
  size_udp = UDP_HDRLEN;
  //if(ip->saddr == inet_addr(dst_ip) && ip->daddr == inet_addr(src_ip)){
      print_time();
      printf(" %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
      print_time();
      printf(" %i %i %i\n",src_port, dst_port,ntohs(udphdr->len));
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
      size_payload = ntohs(ip->tot_len) - (size_ip + size_udp);
      print_time();
      printf(" Payload: %s \n", payload);
      strcpy(reply_payload, (char *)payload);
  //}
  pcap_breakloop(interfaceinfo);
}
void parse_icmp(struct packet_info *packet_info,const struct pcap_pkthdr *pkthdr, const u_char *packet){
  struct iphdr *ip;
  struct icmp *icmp;
  const u_char *payload;
  int size_ip;
  int size_icmp;
  int size_payload;
  ip = (struct iphdr *)(packet + SIZE_ETHERNET);
  size_ip = ip->ihl * 4;
  icmp = (struct icmp *)(packet + SIZE_ETHERNET + size_ip);
  size_icmp = ICMP_HDRLEN;
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
  print_time();
  printf(" %i %i %i %i\n",icmp->icmp_type, icmp->icmp_code,ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
  print_time();
  printf(" %s\n", payload);
  udp_data = true;
  pcap_breakloop(interfaceinfo);
}
void parse_tcp(struct packet_info *packet_info,const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  time_t t = time(NULL);
  struct tm tm = * localtime( & t);
  struct iphdr *ip;
  struct tcphdr *tcp;
  const u_char *payload;
  int size_ip,size_payload, size_tcp;
  ip = (struct iphdr *)(packet + SIZE_ETHERNET);
  size_ip = ip->ihl * 4;
  tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = tcp->doff * 4;
  payload = (u_char *)(packet + 14 + size_ip + size_tcp);
  size_payload = ntohs(ip->tot_len) - (size_ip + size_tcp);
  if (!tcp->rst) {
    if (tcp->fin && tcp->ack) {
      if(fin_flag){
          send_raw_tcp_packet(build_ip_header(5,4,0,40,0,0,0,0,0,255,7),build_tcp_header((ntohl(tcp->ack_seq)),(ntohl(tcp->th_seq)+1),0,5,ACK,64240,0), NULL);
          fin_flag = false;
      }
    } else if (tcp->syn && tcp->ack) {
      if(!syn_flag){
          packet_info->seq = ntohl(tcp->ack_seq);
          packet_info->ack = ntohl(tcp->th_seq) + 1;
          send_raw_tcp_packet(build_ip_header(5,4,0,40,0,0,0,0,0,255,7),build_tcp_header((ntohl(tcp->ack_seq)),(ntohl(tcp->th_seq)+1),0,5,ACK,64240,0), NULL);
          syn_flag = true;
      }
    } else if (tcp->psh && tcp->ack) {
          packet_info->seq = ntohl(tcp->th_seq) + ((ntohs(ip->tot_len)-(TCP_HDRLEN+IP4_HDRLEN)));
          packet_info->ack = ntohl(tcp->ack_seq);
          send_raw_tcp_packet(build_ip_header(5,4,0,40,0,0,0,0,0,255,7),build_tcp_header((ntohl(tcp->ack_seq)),(ntohl(tcp->th_seq)+((ntohs(ip->tot_len)-(TCP_HDRLEN+IP4_HDRLEN)))),0,5,ACK,64240,0), NULL);
          print_time();
          printf(" %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
          fprintf(log_file,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
          fprintf(log_file," %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
          print_time();
          printf("  %i %i %02x %i %02x %02x %02x %i %02x\n",src_port, dst_port,ntohl(tcp->th_seq), ntohl(tcp->th_ack),tcp->th_x2,tcp->th_off,tcp->th_flags, ntohs(tcp->th_win), ntohs(tcp->th_urp));
          fprintf(log_file,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
          fprintf(log_file,"  %i %i %02x %i %02x %02x %02x %i %02x\n",src_port, dst_port,ntohl(tcp->th_seq), ntohl(tcp->th_ack),tcp->th_x2,tcp->th_off,tcp->th_flags, ntohs(tcp->th_win), ntohs(tcp->th_urp));
          strcpy(reply_payload, (char *)payload);
          print_time();
          printf(" Payload: %s \n", payload);
          fprintf(log_file,"[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
          fprintf(log_file," Payload: %s \n", payload);
          pshack_flag = true;
    } else if (tcp->syn) {
    } else if (tcp->fin) {
    } else if (tcp->rst) {
    } else if (tcp->ack) {
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

void parse_payload(struct packet_info *packet_info, const u_char *payload,int len) {
  printf("Payload: \n");
  printf("%s", payload);
  printf("%08X", payload); // print payload in HEX
}

void create_filter(char *FILTER){
    memset(FILTER, '\0', BUFSIZ);
    if(packet_info.protocol == TCP){
        strcat(FILTER, "src ");
        strcat(FILTER, src_ip);
        strcat(FILTER," dst ");
        strcat(FILTER, target);
        strcat(FILTER," and tcp");
    } else if(packet_info.protocol == UDP){
        strcat(FILTER, "src ");
        strcat(FILTER, src_ip);
        strcat(FILTER," dst ");
        strcat(FILTER, target);
        strcat(FILTER," and udp");
    }else if(packet_info.protocol == ICMP){
        strcat(FILTER, "src ");
        strcat(FILTER, src_ip);
        strcat(FILTER," dst ");
        strcat(FILTER, target);
        strcat(FILTER," and icmp");
    }
    printf("Filter: %s\n",FILTER);
}
