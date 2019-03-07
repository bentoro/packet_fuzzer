#ifndef FUZZ_H
#define FUZZ_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct Queue{
    int front, rear, size;
    struct Data *array;
    unsigned capacity;
};

struct Data{
    char* data;
};

double fuzz_ratio = 0.35;

int fuzz();
int fuzz_payload();
struct Queue* create_queue(unsigned capacity);
void enqueue(struct Queue* queue, char* item);;
char* dequeue(struct Queue* queue);
int is_full(struct Queue* queue);
int is_empty(struct Queue* queue);
char* front(struct Queue* queue);
char* rear(struct Queue* queue);

#endif
