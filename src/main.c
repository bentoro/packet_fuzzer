#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include "../lib/libpcap.h"
#include "../lib/raw_socket_wrappers.h"

#define FILENAME "config"

static void print_usage(void) {
    puts ("Usage options: \n"
            "\t-h  -   Host machine ip \n"
            "\t-t  -   Target machine ip\n"
            "\t-s  -   Source port\n"
            "\t-d  -   Destination port\n"
            "\t-p  -   Protocol type, 0 = TCP, 1 = UDP, 2 = ICMP \n"
            "\t-r  -   Raw sockets\n"
            "\t-i  -   Interface\n");
}


int main(int argc, char **argv) {
    FILE *config_file;
    char buffer[BUFSIZ];
    int opt;
    bool raw = false;
    char interface[BUFSIZ];
    int src_port;
    int dst_port;
    char ch;
    char *token = 0;
    char value[BUFSIZ];
    char tmp[BUFSIZ];
    int line_count = 0;
    target = (char *) calloc (40, sizeof(char));
    src_ip = (char *) calloc (INET_ADDRSTRLEN, sizeof(char));
    dst_ip = (char *) calloc (INET_ADDRSTRLEN, sizeof(char));
    //check if root
    if(geteuid() != 0) {
        printf("Must run as root\n");
        exit(1);
    }
    config_file = fopen("config", "r");
    //count how many structs to create
    //TODO: add validation
    while(fgets(buffer, sizeof(buffer), config_file) != NULL){
        line_count++;
    }
    if(line_count%3 == 0){
        printf("# test cases: %i\n",(line_count/3));
        rewind(config_file);
    } else {
        printf("Incorrect information too many lines in config file\n");
        exit(1);
    }
    testcases = calloc((line_count/3),sizeof(tcp_packet));
    while(fgets(buffer, sizeof(buffer), config_file) != NULL){
        buffer[strlen(buffer) -1] = ' ';
        for(int i = 0; i < (int)strlen(buffer); i++){
            if(buffer[i] == ' '){
                //store the string before a space
                printf("%s\n", value);
                memset(value, '\0',sizeof(value));
            }else {
                //concat the value in buffer to char
                strncat(value, &buffer[i], sizeof(buffer[i]));
            }
        }
            printf("\n");
    }
    fclose(config_file);

    while((opt = getopt(argc, argv, "h:t:s:d:p:r:")) != -1){
        switch(opt){
            case 'h':
                strncpy (src_ip, optarg, sizeof(INET_ADDRSTRLEN));
                break;
            case 't':
                strncpy (dst_ip, optarg, sizeof(INET_ADDRSTRLEN));
                break;
            case 's':
                src_port = atoi(optarg);
                break;
            case 'd':
                dst_port = atoi(optarg);
                break;
            case 'p':
                packet_info.protocol = atoi(optarg);
                break;
            case 'r':
                raw = true;
                break;
            case 'i':
                strncpy(interface,optarg,sizeof(interface));
                ifr = search_interface("wlp2s0");
                break;
            default: /* ? */
                print_usage();
                exit(1);
        }
    }
/*
    // Interface to send packet through.
    ifr = search_interface("wlp2s0");
    strcpy (src_ip, "192.168.1.86");
    strcpy (target, "192.168.1.72");
    hints = set_hints(AF_INET, SOCK_STREAM, hints.ai_flags | AI_CANONNAME);

    // Resolve target using getaddrinfo().
    dst_ip = resolve_host(target, hints);
    send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 0, 0, SYN);
    //TODO: Make the filter more specific
    packet_info = packet_capture("src 192.168.1.72 and dst 192.168.1.86 and tcp", packet_info);
    send_raw_tcp_packet(100, 8040, ifr, src_ip,dst_ip, 0, 0, ACK);*/
    return (0);
}

