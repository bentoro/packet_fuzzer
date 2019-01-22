#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <time.h>

#define PORT 8045
#define SYN 0
#define SYNACK 1
#define FIN 2

unsigned short checksum(unsigned short *ptr, int nbytes);
int generate_rand();
void tcp_send(char *src_ip, char *dst_ip, unsigned short src_port, unsigned short dst_port, unsigned char* data, int seq, int flag);


struct send_tcp {
    struct iphdr ip;
    struct tcphdr tcp;
    unsigned char buffer[BUFSIZE + 16];     //payload size plus 16 bytes for encryption
} send_tcp;

struct recv_tcp {
    struct iphdr ip;
    struct tcphdr tcp;
    char buffer[BUFSIZE];
} recv_tcp;

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
} pseudo_header;

int main (int argc, char** argv){

    char targetip[BUFSIZ];
    char localip[BUFSIZ];

    if(geteuid() != 0) {
        printf("Must run as root\n");
        exit(1);
    }
    strncpy(targetip, "192.168.0.0", BUFSIZ);
    strncpy(localip, "192.168.0.0", BUFSIZ);
    tcp_send(localtip, targetip, PORT, PORT, 0, 10000, SYN);

    return 0;
}


void tcp_send(char *src_ip, char *dst_ip, unsigned short src_port, unsigned short dst_port, unsigned char* data, int seq, int flag) {
    int bytes_sent;
    int sending_socket;
    struct sockaddr_in sin;
    unsigned int sip_binary, dip_binary;
    struct send_tcp packet;
    struct timespec delay, resume_delay;

    sip_binary = inet_addr(src_ip);
    dip_binary = inet_addr(dst_ip);
    //sip_binary = host_convert(src_ip);
    //dip_binary = host_convert(dst_ip);

    //suspend so sends can keep up with loop
    delay.tv_sec = 0;
    delay.tv_nsec = 500000000L; //delay 1 sec
    if(nanosleep(&delay, &resume_delay) < 0) {
        perror("covert_send: nanosleep");
        return;
    }

    //create IP header
    packet.ip.ihl = 5;
    packet.ip.version = 4;
    packet.ip.tot_len = htons(40);
    packet.ip.id = 0;
    packet.ip.tos = 0;
    packet.ip.ttl = 0;
    packet.ip.frag_off = 0;
    packet.ip.protocol = IPPROTO_TCP;
    packet.ip.check = 0;
    packet.ip.saddr = sip_binary;
    packet.ip.daddr = dip_binary;

    //create TCP header
    //check if source port was set
    if(src_port == 0) {
        packet.tcp.source = generate_rand(10000.0);
    } else {
        packet.tcp.source = htons(src_port);
    }
    packet.tcp.seq = seq;
    //packet.tcp.seq = generate_rand(10000.0);
    packet.tcp.dest = htons(dst_port);
    packet.tcp.ack_seq = 0;
    packet.tcp.res1 = 0;
    packet.tcp.doff = 5;
    if( flag == FIN){
        packet.tcp.fin = 1;
    } else {
        packet.tcp.fin = 0;
    }
    packet.tcp.fin = 0;
    if(flag == SYN || flag == SYNACK){
        packet.tcp.syn = 1;
    } else {
        packet.tcp.syn = 0;
    }
    packet.tcp.rst = 0;
    packet.tcp.psh = 0;
    if(flag == ACK || flag == SYNACK){
        packet.tcp.ack = 1;
    } else {
        packet.tcp.ack = 0;
      }
    packet.tcp.urg = 0;
    packet.tcp.res2 = 0;
    packet.tcp.window = htons(512);
    packet.tcp.check = 0;
    packet.tcp.urg_ptr = 0;

    memset(packet.buffer, 0, sizeof(packet.buffer));

    //create socket struct
    sin.sin_family = AF_INET;
    sin.sin_port = packet.tcp.source;
    sin.sin_addr.s_addr = packet.ip.daddr;

    //open socket for sending
    sending_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(sending_socket < 0) {
        perror("sending socket failed to open (root maybe required)");
        exit(1);
    }

    //create an IP checksum value
    packet.ip.check = checksum((unsigned short *) &send_tcp.ip, 20);

    pseudo_header.source_address = packet.ip.saddr;
    pseudo_header.dest_address = packet.ip.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(20);

    //copy packet's tcp into pseudo header tcp
    bcopy((char *) &packet.tcp, (char *) &pseudo_header.tcp, 20);

    //create a TCP checksum value
    packet.tcp.check = checksum((unsigned short *) &pseudo_header, 32);

    //send the packet
    if((bytes_sent = sendto(sending_socket, &packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
        //if((bytes_sent = send(sending_socket, &packet, 40, 0, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
        perror("sendto");
    }
    close(sending_socket);
}


unsigned short checksum(unsigned short *ptr, int nbytes){
    register long		sum;		/* assumes long == 32 bits */
    u_short			oddbyte;
    register u_short	answer;		/* assumes u_short == 16 bits */

    /*
     * Our algorithm is simple, using a 32-bit accumulator (sum),
     * we add sequential 16-bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits.
     */

    sum = 0;
    while (nbytes > 1)  {
        sum += *ptr++;
        nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1) {
        oddbyte = 0;		/* make sure top half is zero */
        *((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
        sum += oddbyte;
    }

    /*
     * Add back carry outs from top 16 bits to low 16 bits.
     */

    sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;		/* ones-complement, then truncate to 16 bits */
    return(answer);
} /* end in_cksm() */


int generate_rand() {
    return 1 + (int)(10000.0 * rand() / RAND_MAX + 1.0);
}
