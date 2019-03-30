#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "../lib/normal_socket_wrappers.h"
#include "../lib/fuzz.h"

#define MAXCONNECTIONS 1024


int main(int argc, char **argv){
    int sockfd, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    if(argc < 3){
        printf("./tcp [port to listen on] [string to search for]");
        exit(0);
    }

    hints = set_hints(AF_UNSPEC, SOCK_STREAM, AI_PASSIVE);

    if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (listen(sockfd, MAXCONNECTIONS) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");
    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
        perror("accept");
    }
    char right[50] = "The input that you have entered is correct";
    char wrong[50] = "The input that you have entered is wrong";
    inet_ntop(their_addr.ss_family,get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
    printf("server: got connection from %s\n", s);
    while(1) {
        int bytes_receieved;
        char data[1024];
        memset(data,'\0',sizeof(data));
        bytes_receieved = 0;
        bytes_receieved = recv(new_fd, data, sizeof(data),0);
        //recv_normal_tcp_packet(new_fd, data, sizeof(data));
        if(bytes_receieved == 0){
            break;
        }
        if(bytes_receieved > 0){
            printf("Received: %s from %s\n",data, s);
            if(search(data, argv[2],sizeof(bytes_receieved))){
                send_normal_tcp_packet(new_fd, right, 42);
                printf("Sent: %s\n",right);
            }else{
                send_normal_tcp_packet(new_fd, wrong, 40);
                printf("Sent: %s\n",wrong);
            }
        }
    }
    close(new_fd);
    close(sockfd);

    return 0;
}
