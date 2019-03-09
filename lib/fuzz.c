#include "fuzz.h"


int main(int argc, char **argv){
    /*struct Queue* queue = create_queue(10);
    enqueue(queue, "one");
    enqueue(queue, "two");
    enqueue(queue, "three");
    printf("Front: %s\n", front(queue));
    printf("Rear: %s\n", rear(queue));
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);*/
    initilize_rand();
    char data[BUFSIZ] = "asdfhellhellhello";
    //fuzz_payload(data, strlen(data));
    printf("found: %d\n", search(data, "hello",strlen(data)));
    printf("payload: %s\n",data);

}

bool search(char *data, char *query,int length){
    int size = strlen(query);
    bool found = false;
    char substring[BUFSIZ];
    int counter= 0;
    for(int i = 0; i <= length; i++){
        //printf("i = %i\n", i);
        //if the character is the same as the first character of the query
        if(data[i] == query[0]){
            //printf("Length: %i\n", length);
            //printf("found first letter\n");
            while(counter < size){
                substring[counter] = data[i+counter];
                //printf("Substring[%i]: %c\n", counter,data[i+counter]);
                counter++;
            }
            counter = 0;
            //printf("substring: %s\n", substring);
            if(strcmp(query, substring) == 0){
                found = true;
            }
        }
    }
    return found;
}

int set_fuzz_ratio(double ratio){
    fuzz_ratio = ratio;
    return ratio;
}

void initilize_rand(){
    srand(time(NULL));
}

int fuzz(){

}
void fuzz_payload(char *data, int length){
    int bytes_to_fuzz = length * fuzz_ratio;
    for(int i = 0; i<= bytes_to_fuzz; i++){
        data[rand() % length] = rand() % 256;
    }
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

