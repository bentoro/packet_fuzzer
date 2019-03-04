#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_TCP_PORT 8040
#define BUFSIZE 1024

int main(int argc, char **argv) {
  int n, bytes_to_read;
  int sd, new_sd, port;
  socklen_t client_len;
  struct sockaddr_in server, client;
  char *bp, buf[BUFSIZE];

  port = SERVER_TCP_PORT;

  sd = socket(AF_INET, SOCK_STREAM, 0);

  bzero((char *)&server, sizeof(struct sockaddr_in));
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = htonl(INADDR_ANY);

  bind(sd, (struct sockaddr *)&server, sizeof(server));
  listen(sd, 1);

  client_len = sizeof(client);
  new_sd = accept(sd, (struct sockaddr *)&client, &client_len);

  bp = buf;
  bytes_to_read = BUFSIZE;
  while ((n = recv(new_sd, bp, bytes_to_read, 0)) < BUFSIZE) {
    bp += n;
    bytes_to_read -= n;
  }

  printf("sending: %s\n", buf);

  send(new_sd, buf, BUFSIZE, 0);
  close(new_sd);
  close(sd);

  return 0;
}
