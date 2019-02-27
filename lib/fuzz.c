#include "fuzz.h"


int fuzz(){

}
int fuzz_payload(){
}
struct Queue* create_queue(unsigned capacity){
    struct Queue* queue = (struct Queue*) malloc(sizeof(struct Queue));

    queue->capacity = capacity;
    queue->front = 0;
    queue->size = 0;
    queue->rear = capacity -1;
    queue->array = (char **) calloc(queue->capacity, sizeof(char));

    return queue;
}

void enqueue(struct Queue* queue, char* item){
    if(is_full(queue)){
        return;
    }
    queue->rear = (queue->rear + 1);
    queue->array[queue->rear] = item;
    queue->size = queue->size +1;
    printf("%s added to queue",item);
}
char* dequeue(struct Queue* queue){
    if(is_empty(queue)){
        return NULL;
    }
    char* item = queue->array[queue->front];
    queue->front = (queue->front +1);
    queue->size = queue->size-1;
    return item;
}
int is_full(struct Queue* queue){
    return(queue->size == (int)queue->capacity);
}
int is_empty(struct Queue* queue){
    return(queue->size == 0);
}

char* front(struct Queue* queue){
    if(is_empty(queue)){
        printf("Queue is empty");
    }
    return queue->array[queue->front];
}
char* rear(struct Queue* queue){
    if(is_empty(queue)){
        printf("Queue is empty");
    }
    return queue->array[queue->rear];
}

