#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#define SIZE_ETHERNET 14
#define ICMP_HDRLEN 8


void listener();
void display(void *packet);

int main(int argc, char **argv){
    listener();
}

void display(void *packet){
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
  printf("src: %u\n", ip->saddr);
  printf("dst: %u\n", ip->daddr);
  printf("src: %u\n", htonl(ip->saddr));
  printf("dst: %u\n", htonl(ip->daddr));
  printf(" %i %i %i %i\n",icmp->icmp_type, icmp->icmp_code,ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
  payload = (char *)(packet + size_ip + size_icmp);
  size_payload = ntohs(ip->tot_len) - (size_ip + size_icmp);
  printf("Sizeof payload: %i\n",size_payload);
  printf("payload: %s\n", payload);
}

void listener(){	int sd;
	struct sockaddr_in addr;
	unsigned char buf[1024];

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if ( sd < 0 )
	{
		perror("socket");
		exit(0);
	}
	for (;;)
	{	int bytes, len=sizeof(addr);

		bzero(buf, sizeof(buf));
		bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &len);
		if ( bytes > 0 )
			display(buf);
		else
			perror("recvfrom");
	}
	exit(0);
}
