#ifndef FUZZ_H
#define FUZZ_H

#include "raw_socket_wrappers.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <math.h>

struct Queue{
    int front, rear, size;
    struct tcp_packet *tcp_packets;
    struct udp_packet *udp_packets;
    struct icmp_packet *icmp_packets;
    unsigned capacity;
};

struct Data{
    char* data;
};

double fuzz_ratio;
time_t t;

bool search(char *data, char *query,int length);
int set_fuzz_ratio(double ratio);
char *fuzz_payload(char *data, int length);
char *replace_char(char *data, int length);
char *delete_char(char *data, int length);
struct Queue* create_queue(unsigned capacity);
void enqueue(struct Queue* queue, struct tcp_packet tcp);
struct tcp_packet dequeue(struct Queue* queue);
int is_full(struct Queue* queue);
int is_empty(struct Queue* queue);
int sizeofstring(char *data);
/*struct tcp_packet front(struct Queue* queue);
struct tcp_packet rear(struct Queue* queue);*/

#endif
