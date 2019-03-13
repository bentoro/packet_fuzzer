#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
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
  const u_char *payload;
  int size_ip;
  int size_icmp;
  int size_payload;
  ip = (struct iphdr *)(packet);
  size_ip = ip->ihl * 4;
  icmp = (struct icmp *)(packet + size_ip);
  size_icmp = ICMP_HDRLEN;
  printf(" %i %i %i %i\n",icmp->icmp_type, icmp->icmp_code,ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
  size_payload = ntohs(ip->tot_len) - (size_ip + size_icmp);
  printf("payload: %s\n", payload);
}
/*void display(void *buf, int bytes)
{	int i;
	struct iphdr *ip = buf;
	struct icmphdr *icmp = buf+ip->ihl*4;

	printf("\n");
	printf("IPv%d: hdr-size=%d pkt-size=%d protocol=%d TTL=%d",
		ip->version, ip->ihl*4, ntohs(ip->tot_len), ip->protocol,
		ip->ttl);
		printf("ICMP: type[%d/%d] checksum[%d] id[%d] seq[%d]\n",
			icmp->type, icmp->code, ntohs(icmp->checksum),
			icmp->un.echo.id, icmp->un.echo.sequence);
}*/

/*--------------------------------------------------------------------*/
/*--- listener - separate process to listen for and collect messages--*/
/*--------------------------------------------------------------------*/
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
