#include "normal_socket_wrappers.h"

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
  hints.ai_flags = flags;

  return hints;
}

// node is the hostname to connect to
// service is the port number
// hints points to a addrinfo struct
struct addrinfo set_addr_info(const char *address, const char *port,
                              struct addrinfo hints) {
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

void set_listen(int fd) {
  if ((listen(fd, MAXCONNECTION)) == -1) {
    perror("listen");
    exit(1);
  }
}

int make_connect(const char *address, const char *port) {
  struct addrinfo hints;
  struct addrinfo *servinfo;
  struct addrinfo *p;
  int fd;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((getaddrinfo(address, port, &hints, &servinfo)) != 0) {
    perror("getaddrinfo");
    exit(1);
  }

  for (p = servinfo; p != NULL; p->ai_next) {
    if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }
    if ((connect(fd, p->ai_addr, p->ai_addrlen)) == -1) {
      close(fd);
      perror("client:bind");
      continue;
    }
    break;
  }

  freeaddrinfo(servinfo);

  // set_non_blocking(fd);

  return fd;
}

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

void send_normal_udp_packet(int sending_socket, char *data, int length,
                            const struct sockaddr *dest_addr,
                            socklen_t dest_len) {
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

void recv_normal_tcp_packet(int socket, char *buf, size_t bufsize) {
  int bytes_receieved, bytes_to_read;
  bytes_to_read = bufsize;

  while ((bytes_receieved = recv(socket, buf, bytes_to_read, 0)) <
         (int)bufsize) {
    buf += bytes_receieved;
    bytes_to_read -= bytes_receieved;
  }
}

void recv_normal_udp_packet(int socket, char *buf, size_t bufsize,
                            struct sockaddr_in client,
                            socklen_t client_addr_len) {
  int bytes_receieved, bytes_to_read;
  bytes_to_read = bufsize;

  while ((bytes_receieved = recvfrom(socket, buf, bytes_to_read, 0,
                                     (struct sockaddr *)&client,
                                     &client_addr_len)) < (int)bufsize) {
    buf += bytes_receieved;
    bytes_to_read -= bytes_receieved;
  }
}
