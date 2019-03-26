#include "fuzz.h"
/* =====================================================================================
 *
 *       function: sizeofstring()
 *
 *         return: int
 *
 *       Parameters:
 *               char *data - data to count
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Find the size of the string
 *
 * ====================================================================================*/

int sizeofstring(char *data){
    int size = 0;
    while (data[size] != '\0'){
        size++;
    }
    return size;
}


/* =====================================================================================
 *
 *       function: search()
 *
 *         return: bool
 *
 *       Parameters:
 *               char *data - data
 *               char *query - string to look for
 *               int length - length of the data
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Search for a specific string in the payload
 *
 * ====================================================================================*/
bool search(char *data, char *query,int length){
    int size;
    bool found = false;
    char substring[BUFSIZ];
    int counter= 0;
    size = sizeofstring(query);
    for(int i = 0; i <= length; i++){
        //if the character is the same as the first character of the query
        if(data[i] == query[0]){
            while(counter <= size){
                substring[counter] = data[i+counter];
                counter++;
            }
            counter = 0;
            //printf("Substring: %s\n",substring);
            if(strcmp(query, substring) == 0){
                found = true;
            }
        }
    }
    return found;
}


/* =====================================================================================
 *
 *       function: set_fuzz_ratio()
 *
 *         return: int
 *
 *       Parameters:
 *               double ratio - value to fuzz
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Set the fuzzing ratio
 *
 * ====================================================================================*/
int set_fuzz_ratio(double ratio){
    fuzz_ratio = ratio;
    return ratio;
}
/*char *fuzz_payload(char *data, int length){
    int bytes_to_fuzz = length * fuzz_ratio;
    for(int i = 0; i<= bytes_to_fuzz; i++){
        data[rand() % bytes_to_fuzz] = (int)(rand() % 126) + 25;
    }
    return data;
}*/


/* =====================================================================================
 *
 *       function: fuzz_payload()
 *
 *         return: char *
 *
 *       Parameters:
 *               cahr * data - data
 *               int length - length of data
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Fuzz the payload
 *
 * ====================================================================================*/
char *fuzz_payload(char *data, int length){
    int random;
    int size = sizeofstring(data);
    int bytes_to_fuzz = size * fuzz_ratio;
    for(int i = 0; i<= size; i++){
        random = rand() % size;
        if(random% 2 == 0){
            data[rand() % size] =  ' ';
        } else if(random%2 == 1){
            data[rand() % size] = ((int)((rand() % 128)) + 32);
        }
    }
    return data;
}

char *delete_char(char *data, int length){
    int bytes_to_fuzz = length * fuzz_ratio;
    for(int i = 0; i<= bytes_to_fuzz; i++){
        data[rand() % bytes_to_fuzz] =  ' ';
    }
    return data;
}

char *replace_char(char *data, int length){
    srand ( time(NULL) );
    int bytes_to_fuzz = length * fuzz_ratio;
    for(int i = 0; i<= bytes_to_fuzz; i++){
        data[rand() % bytes_to_fuzz] = (int)((rand() % 128) + 32);
    }
    return data;
}

struct Queue* create_queue(unsigned capacity){
    struct Queue* queue = (struct Queue*) malloc(sizeof(struct Queue));

    queue->capacity = capacity;
    queue->front = 0;
    queue->size = 0;
    queue->rear = capacity - 1;
    if(packet_info.protocol == TCP){
        queue->tcp_packets = (struct tcp_packet*)malloc((queue->capacity) * sizeof(struct tcp_packet));
    }
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
    }
    queue->size = queue->size +1;
    printf("added to queue\n");
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
