#include "normal_socket_wrappers.h"

void send_normal_tcp_packet(int sending_socket, char *data, int length) {
    int total = 0;
    int bytes_left = length;
    int bytes_sent;
    while(total < length){
        if((bytes_sent = send(sending_socket, data + total, bytes_left, 0)) == -1){
            printf("Failed to send data\n");
        }
        total += bytes_sent;
        bytes_left=-bytes_sent;
    }
}


void send_normal_udp_packet(int sending_socket, char *data, int length, const struct sockaddr *dest_addr, socklen_t dest_len) {
    int total = 0;
    int bytes_left = length;
    int bytes_sent;
    while(total < length){
        if((bytes_sent = sendto(sending_socket, data + total, bytes_left, 0, dest_addr, dest_len)) == -1){
            printf("Failed to send data\n");
        }
        total += bytes_sent;
        bytes_left=-bytes_sent;
    }
}

void recv_normal_tcp_packet(int socket, char *buf, size_t bufsize){
    int bytes_receieved, bytes_to_read;
    bytes_to_read = bufsize;

    while((bytes_receieved = recv(socket, buf, bytes_to_read, 0)) < (int)bufsize){
        buf += bytes_receieved;
        bytes_to_read -= bytes_receieved;
    }
}


void recv_normal_udp_packet(int socket, char *buf, size_t bufsize, struct sockaddr_in client, socklen_t client_addr_len){
    int bytes_receieved, bytes_to_read;
    bytes_to_read = bufsize;

    while((bytes_receieved = recvfrom(socket, buf, bytes_to_read, 0, (struct sockaddr *)&client, &client_addr_len)) < (int)bufsize){
        buf += bytes_receieved;
        bytes_to_read -= bytes_receieved;
    }
}
