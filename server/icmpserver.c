#include "../lib/raw_socket_wrappers.h"
char *recv_icmp(void *packet);
int start_icmp_client();
void print_time();

// echo "1" >  /proc/sys/net/ipv4/icmp_echo_ignore_all

int main(int argc, char **argv){
    int sending_socket = start_icmp_client();
    char receieved_data[IP_MAXPACKET];
    struct sockaddr_in rawclient; //for receiving icmp packets
    socklen_t client_addr_len; //for sending normal udp packets
    while(1){
        memset(receieved_data,'\0', sizeof(receieved_data));
        if(recvfrom(sending_socket, receieved_data, sizeof(receieved_data), 0, (struct sockaddr*)&rawclient, &client_addr_len) < 0){
              perror("recvfrom");
        } else {
              strcpy(receieved_data,recv_icmp(receieved_data));
        }
    }
    return 0;
}

char *recv_icmp(void *packet){
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
  if(ip->saddr == inet_addr("192.168.1.73") && ip->daddr == inet_addr("192.168.1.75")){
      print_time();
      printf(" %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",ip->ihl,ip->version,ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol, ip->check, ip->saddr, ip->daddr);
      print_time();
      printf(" %i %i %i %i\n",icmp->icmp_type, icmp->icmp_code,ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
      print_time();
      printf(" Payload: %s\n", payload);
      /*icmp_packets[current].iphdr = build_ip_header(5,4,0,28,0,0,0,0,0,255,9);
      icmp_packets[current].icmphdr = build_icmp_header(8,0,1000,0);
      strcpy(icmp_packets[current].payload, "hello");*/
      return (char *)payload;
  }
  return NULL;
}

int start_icmp_client(){
    int sending_socket;

	if((sending_socket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP))<0){
		perror("socket");
		exit(0);
	}
	return sending_socket;
}


void print_time() {
    time_t t = time(NULL);
    struct tm tm = * localtime( & t);
    printf("[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}
