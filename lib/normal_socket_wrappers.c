#include "normal_socket_wrappers.h"


/* =====================================================================================
 *
 *       function: *get_in_addr()
 *
 *         return: void
 *
 *       Parameters:
 *               struct sockaddr *sa - source
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Get in_addr
 *
 * ====================================================================================*/
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}


void sig_handler(int s) {
  int saved_errno = errno;

  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;

  errno = saved_errno;
}

/*
 * =====================================================================================
 *
 *       function: setHints
 *
 *         return: struct addrinfo
 *
 *       Parameters:
 *                    int family - set the family
 *                    int socktype - set the socktype
 *                    int flags - set the flags
 *
 *       Notes:
 *              starts the timer
 * =====================================================================================
 */
struct addrinfo set_hints(int family, int socktype, int flags) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;     // IPV4
  hints.ai_socktype = socktype; // TCP
  if(flags == 0){
  }else {
      hints.ai_flags = flags;
  }
  return hints;
}

/* =====================================================================================
 *
 *       function: set_addr_info()
 *
 *         return: void
 *
 *       Parameters:
 *               const char *address - address
 *               const char *port - port
 *               struct addrinfo hints - hints
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Get the address info
 *
 * ====================================================================================*/
struct addrinfo set_addr_info(const char *address, const char *port,struct addrinfo hints) {
  int status;
  struct addrinfo *servinfo;

  if ((status = getaddrinfo(address, port, &hints, &servinfo)) != 0) {
    perror("getaddrinfo");
    exit(1);
  }
  return (*servinfo);
  // freeaddrinfo(servinfo);
}

int set_bind(int fd, struct addrinfo *p) {
  int r;
  if ((r = bind(fd, p->ai_addr, p->ai_addrlen)) == -1) {
    perror("bind");
    exit(1);
    return -1;
  }
  return r;
}


/* =====================================================================================
 *
 *       function: set_listen()
 *
 *         return: void
 *
 *       Parameters:
 *               int fd - file descriptor
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              set socket to listen
 *
 * ====================================================================================*/
void set_listen(int fd) {
  if ((listen(fd, MAXCONNECTION)) == -1) {
    perror("listen");
    exit(1);
  }
}


/* =====================================================================================
 *
 *       function: start_udp_server()
 *
 *         return: int
 *
 *       Parameters:
 *               int PORT- port
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Start the udp server
 *
 * ====================================================================================*/
int start_udp_server(int PORT){
	int sock, optval = 1;
	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(PORT);
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("could not create socket\n");
		return 1;
	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

	if ((bind(sock, (struct sockaddr *)&server_address, sizeof(server_address))) < 0) {
		printf("could not bind socket\n");
		return 1;
	}
	return sock;
}


/* =====================================================================================
 *
 *       function: start_tcp_server()
 *
 *         return: int
 *
 *       Parameters:
 *               char *address - address
 *               char *PORT- port
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Start the tcp server
 *
 * ====================================================================================*/
int start_tcp_client(char *address, char *port){
  int sockfd;
  struct addrinfo *servinfo, *p, hints;
  int rv;
  char s[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((rv = getaddrinfo(address, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("client: connect");
      continue;
    }
    break;
  }

  if (p == NULL) {
      perror("failed to connect\n\n");
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s,sizeof s);
  printf(" Connected to %s\n", s);
  return(sockfd);
}


/* =====================================================================================
 *
 *       function: start_udp_server()
 *
 *         return: int
 *
 *       Parameters:
 *               char *address - address
 *               char *PORT- port
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              Start the udp server
 *
 * ====================================================================================*/
int start_udp_client(char *address, char *port){
  int sockfd;
  struct addrinfo *servinfo, *p, hints;
  int rv;
  char s[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  if ((rv = getaddrinfo(address, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }
    break;
  }

  if (p == NULL) {
      perror("failed to connect\n");
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s,sizeof s);
  printf(" Connected to %s\n\n", s);
  return(sockfd);
}


/* =====================================================================================
 *
 *       function: make_connect()
 *
 *         return: int
 *
 *       Parameters:
 *               char *address - address
 *               char *PORT- port
 *               int family - family
 *               int socktype - socktype
 *               int flags -flas
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              make and connect to the server
 *
 * ====================================================================================*/
int make_connect(const char *address, const char *port, int family, int socktype, int flags) {
  struct addrinfo hints;
  struct addrinfo *servinfo;
  struct addrinfo *p;
  int fd;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = family;
  hints.ai_socktype = socktype;
  if(flags == 0){

  } else {
      hints.ai_flags = flags;
  }

  if ((getaddrinfo(address, port, &hints, &servinfo)) != 0) {
    perror("getaddrinfo");
    exit(1);
  }

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("socket");
      continue;
    }
    if ((connect(fd, p->ai_addr, p->ai_addrlen)) == -1) {
      close(fd);
      perror("bind");
      continue;
    }
    break;
  }

  if(p == NULL){
        perror("failed to create socket\n");
  }

  freeaddrinfo(servinfo);

  // set_non_blocking(fd);

  return fd;
}

/* =====================================================================================
 *
 *       function: make_bind()
 *
 *         return: int
 *
 *       Parameters:
 *               char *PORT- port
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              make and bind to the server
 *
 * ====================================================================================*/
int make_bind(const char *port) {
  struct addrinfo hints;
  struct addrinfo *servinfo;
  struct addrinfo *p;
  int fd;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
    perror("getaddrinfo");
    exit(1);
  }

  for (p = servinfo; p != NULL; p->ai_next) {
    if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("server: socket");
      continue;
    }
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("setsockopt");
    }
    if ((bind(fd, p->ai_addr, p->ai_addrlen)) == -1) {
      close(fd);
      perror("server:bind");
      continue;
    }
    break;
  }
  if (p == NULL) {
    perror("Could not bind");
  }
  freeaddrinfo(servinfo);

  // set_non_blocking(fd);

  return fd;
}

int Accept(int fd, struct sockaddr_storage *addr) {
  int r;
  socklen_t len = sizeof(struct sockaddr_storage);
  if ((r = accept(fd, (struct sockaddr *)addr, &len)) != -1) {
    perror("accept");
  }
  return r;
}


/* =====================================================================================
 *
 *       function: send_normal_tcp_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               int sending_socket - sending socket
 *               char *data - data
 *               int length length
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *               send a normal tcp packet
 *
 * ====================================================================================*/
void send_normal_tcp_packet(int sending_socket, char *data, int length) {
  int total = 0;
  int bytes_left = length;
  int bytes_sent;
  while (total < length) {
    if ((bytes_sent = send(sending_socket, data + total, bytes_left, 0)) ==
        -1) {
      printf("Failed to send data\n");
    }
    total += bytes_sent;
    bytes_left = -bytes_sent;
  }
}


/* =====================================================================================
 *
 *       function: send_normal_udp_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               int sending_socket - sending socket
 *               char *data - data
 *               int length length
 *               const struct sockaddr *dest_addr - sockaddr
 *               socklen_t dest_len - length of the address
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *               send a normal udp packet
 *
 * ====================================================================================*/
void send_normal_udp_packet(int sending_socket, char *data, int length,const struct sockaddr *dest_addr,socklen_t dest_len) {
  int total = 0;
  int bytes_left = length;
  int bytes_sent;
  while (total < length) {
    if ((bytes_sent = sendto(sending_socket, data + total, bytes_left, 0,
                             dest_addr, dest_len)) == -1) {
      printf("Failed to send data\n");
    }
    total += bytes_sent;
    bytes_left = -bytes_sent;
  }
}


/* =====================================================================================
 *
 *       function: recv_normal_tcp_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               int socket - sending socket
 *               char *buf - data
 *               size_t bufsize - size of the buffer
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *               receive normal tcp packet
 *
 * ====================================================================================*/
void recv_normal_tcp_packet(int socket, char *buf, size_t bufsize) {
  int bytes_receieved, bytes_to_read;
  bytes_to_read = bufsize;

  while ((bytes_receieved = recv(socket, buf, bytes_to_read, 0)) <
         (int)bufsize) {
    buf += bytes_receieved;
    bytes_to_read -= bytes_receieved;
  }
}


/* =====================================================================================
 *
 *       function: recv_normal_udp_packet()
 *
 *         return: void
 *
 *       Parameters:
 *               int socket - sending socket
 *               char *buf - data
 *               size_t bufsize - size of the buffer
 *               struct sockaddr *client - client
 *               socklen_t client_addr_len - length of the client adddress
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *               receive normal udp packet
 *
 * ====================================================================================*/
void recv_normal_udp_packet(int socket, char *buf, size_t bufsize,struct sockaddr *client,socklen_t client_addr_len) {
  int bytes_receieved, bytes_to_read;
  bytes_to_read = bufsize;

  while ((bytes_receieved = recvfrom(socket, buf, bytes_to_read, 0,client,&client_addr_len)) < (int)bufsize) {
    buf += bytes_receieved;
    bytes_to_read -= bytes_receieved;
  }
}
