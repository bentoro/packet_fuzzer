#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_TCP_PORT 7000
#define BUFLEN 80

int main(int argc, char** argv){
    int n, bytes_to_read;
    int sd, new_sd, port;
    socklen_t client_len;
    struct sockaddr_in server, client;
    char *bp, buf[BUFLEN];

    port = SERVER_TCP_PORT;

    sd = socket(AF_INET, SOCK_STREAM, 0);

    bzero((char *)&server, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(sd, (struct sockaddr *)&server, sizeof(server));
    listen(sd,1);

    client_len = sizeof(client);
    new_sd = accept(sd, (struct sockaddr *)&client, &client_len);

    bp = buf;
    bytes_to_read = BUFLEN;
    while ((n = recv(new_sd, bp, bytes_to_read, 0)) < BUFLEN){
        bp += n;
        bytes_to_read -= n;
    }

    printf("sending: %s\n", buf);

    send(new_sd, buf, BUFLEN, 0);
    close(new_sd);
    close(sd);

    return 0;
}
