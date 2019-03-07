#include "../lib/normal_socket_wrappers.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT "8045"
#define BUFSIZE 1024

int main(int argc, char *argv[]) {
  int sockfd;
  struct addrinfo hints, servinfo;
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  char buf[BUFSIZE];

  if (argc != 2) {
    fprintf(stderr, "usage: client hostname\n");
    exit(1);
  }

  hints = set_hints(AF_UNSPEC,SOCK_DGRAM, 0);
  servinfo = set_addr_info(argv[1], PORT, hints);

  sockfd = start_udp_client(argv[1], PORT);

  /*memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("client: connect");
      continue;
    }
    break;
  }

  if (p == NULL) {
    fprintf(stderr, "client: failed to connect\n");
    return 2;
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s,sizeof s);
  printf("client: connecting to %s\n", s);*/
  while (1) {
    printf("Enter message to send: ");
    scanf("%s", buf);
    send_normal_udp_packet(sockfd, buf, sizeof(buf), servinfo.ai_addr, servinfo.ai_addrlen);
    addr_len = sizeof(their_addr);
    recv_normal_udp_packet(sockfd, buf, sizeof(buf),(struct sockaddr *)&their_addr, addr_len);

    printf("client: received '%s'\n", buf);
  }
  close(sockfd);

  return 0;
}
