#ifndef FUZZ_H
#define FUZZ_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <math.h>
#include "fuzz.h"

struct Queue{
    int front, rear, size;
    struct Data *array;
    unsigned capacity;
};

struct Data{
    char* data;
};

double fuzz_ratio = 0.50;

int fuzz();
bool search(char *data, char *query,int length);
int set_fuzz_ratio(double ratio);
void fuzz_payload(char *data, int length);
int generate_rand(double value);
struct Queue* create_queue(unsigned capacity);
void enqueue(struct Queue* queue, char* item);;
char* dequeue(struct Queue* queue);
int is_full(struct Queue* queue);
int is_empty(struct Queue* queue);
char* front(struct Queue* queue);
char* rear(struct Queue* queue);

#endif
