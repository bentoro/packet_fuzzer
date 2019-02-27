#ifndef FUZZ_H
#define FUZZ_H

#include <stdlib.h>
#include <stdio.h>

struct Queue{
    int front, rear, size;
    char **array;
    unsigned capacity;
};

int fuzz();
int fuzz_payload();
struct Queue* create_queue(unsigned capacity);
void enqueue();
char* dequeue();
int is_full(struct Queue* queue);
int is_empty(struct Queue* queue);
char* front(struct Queue* queue);
char* rear(struct Queue* queue);

#endif
