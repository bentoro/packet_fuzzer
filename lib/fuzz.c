#include "fuzz.h"

/*
int main(int argc, char **argv){
    enqueue(queue, "one");
    printf("Front: %s\n", front(queue));
    printf("Rear: %s\n", rear(queue));
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);
    dequeue(queue);

}*/

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

char *fuzz_payload(char *data, int length){
    int bytes_to_fuzz = length * fuzz_ratio;
    for(int i = 0; i<= bytes_to_fuzz; i++){
        data[rand() % length] = rand() % 256;
    }
    return data;
}

void print_queue(struct Queue* queue){
}

struct Queue* create_queue(unsigned capacity){
    struct Queue* queue = (struct Queue*) malloc(sizeof(struct Queue));

    queue->capacity = capacity;
    queue->front = 0;
    queue->size = 0;
    queue->rear = capacity - 1;
    if(packet_info.protocol == TCP){
        queue->tcp_packets = (struct tcp_packet*)malloc((queue->capacity) * sizeof(struct tcp_packet));
    } /*else if(packet_info.protocol == UDP){
        queue->udp_packets = (struct udp_packet*)malloc((queue->capacity) * sizeof(struct udp_packet));
    } else if(packet_info.protocol == ICMP){
        queue->icmp_packets = (struct icmp_packet*)malloc((queue->capacity) * sizeof(struct icmp_packet));
    }*/
    return queue;
}



void enqueue(struct Queue* queue, struct tcp_packet tcp){
    if(is_full(queue)){
        return;
    }
    queue->rear = (queue->rear + 1)%queue->capacity;
    printf("REAR: %i\n",queue->rear);
    if(packet_info.protocol == TCP){
        queue->tcp_packets[queue->rear] = tcp;
    } /*else if(packet_info.protocol == UDP){
        queue->udp_packets[queue->rear] = tcp;
    }else if(packet_info.protocol == ICMP){
        queue->tcp_packets[queue->rear] = tcp;
    }*/
    queue->size = queue->size +1;
    printf("added to queue\n");
    print_tcp_packet(tcp);
}
struct tcp_packet dequeue(struct Queue* queue){
        printf("REAR: %i\n",queue->rear);
        printf("FRONT: %i\n",queue->front);
        struct tcp_packet tcp = queue->tcp_packets[queue->front];
        queue->front = (queue->front +1)%queue->capacity;
        queue->size = queue->size - 1;
        return tcp;
}

int is_full(struct Queue* queue){
    return(queue->size == (int)queue->capacity);
}
int is_empty(struct Queue* queue){
    return(queue->size == 0);
}
/*
struct tcp_packet front(struct Queue* queue){
    if(is_empty(queue)){
        printf("Queue is empty\n");
    }
    return queue->tcp_packets[queue->front];
}
struct tcp_packet rear(struct Queue* queue){
    if(is_empty(queue)){
        printf("Queue is empty\n");
    }
    return queue->tcp_packets[queue->rear];
}*/

