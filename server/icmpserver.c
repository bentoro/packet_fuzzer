//#include "../lib/raw_socket_wrappers.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>      //iphdr
#include <netinet/ip_icmp.h> //icmp
#include <netinet/tcp.h>     //tcphdr
#include <netinet/udp.h>     //udphdr
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#define ICMP_HDRLEN 8 // Length of ICMP Header
char *recv_icmp(void *packet);
int start_icmp_client();
void print_time();

int main(int argc, char **argv){
    int sending_socket = start_icmp_client();
    char receieved_data[65535];
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
