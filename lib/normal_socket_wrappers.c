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
