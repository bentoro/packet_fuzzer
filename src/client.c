#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
//#include <linux/ip.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <time.h>

#define PORT 8040
#define BUFSIZE 1024

int main (int argc, char** argv){
    int n = 0, bytes_to_read;
    int sd, port;
    struct hostent *hp;
    struct sockaddr_in server;
    char *host, *bp, rbuf[BUFSIZE], sbuf[BUFSIZE];

    host = "192.168.1.72";
    port = PORT;

    sd = socket(AF_INET, SOCK_STREAM,0);

    bzero((char *)&server, sizeof(struct sockaddr_in));

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    hp = gethostbyname(host);

    bcopy(hp->h_addr, (char *)&server.sin_addr, hp->h_length);

    connect(sd, (struct sockaddr *)&server, sizeof(server));

    strncpy(sbuf, "hi", BUFSIZE);
    send(sd, sbuf, BUFSIZE, 0);

    printf("Receive:\n");
    bp = rbuf;
    bytes_to_read = BUFSIZE;

    while((n = recv(sd, bp, bytes_to_read, 0)) < BUFSIZE){
        bp+=n;
        bytes_to_read-=n;
    }

    return 0;
}
