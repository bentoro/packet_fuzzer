#include "fuzz.h"


int main(int argc, char **argv){
    struct Queue* queue = create_queue(10);
    enqueue(queue, "one");
    enqueue(queue, "two");
    enqueue(queue, "three");
    printf("Front: %s\n", front(queue));
    printf("Rear: %s\n", rear(queue));
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);
}

int fuzz(){

}
int fuzz_payload(){
}

void print_queue(struct Queue* queue){
}

struct Queue* create_queue(unsigned capacity){
    struct Queue* queue = (struct Queue*) malloc(sizeof(struct Queue));

    queue->capacity = capacity;
    queue->front = 0;
    queue->size = 0;
    queue->rear = capacity - 1;
    queue->array = (struct Data*)malloc((queue->capacity) * sizeof(struct Data));

    return queue;
}

void enqueue(struct Queue* queue, char* item){
    if(is_full(queue)){
        return;
    }
    queue->rear = (queue->rear + 1)%queue->capacity;
    queue->array[queue->rear].data = malloc(sizeof(struct Data));
    strcpy(queue->array[queue->rear].data, item);
    queue->size = queue->size +1;
    printf("%s added to queue\n",item);
}
char* dequeue(struct Queue* queue){
    if(is_empty(queue)){
        printf("Queue is empty\n");
        return NULL;
    }
    char* item = queue->array[queue->front].data;
    queue->front = (queue->front +1)%queue->capacity;
    queue->size = queue->size - 1;
    printf("%s removed from the queue\n",item);
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
        printf("Queue is empty\n");
    }
    return queue->array[queue->front].data;
}
char* rear(struct Queue* queue){
    if(is_empty(queue)){
        printf("Queue is empty\n");
    }
    return queue->array[queue->rear].data;
}

