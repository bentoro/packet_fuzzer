#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
	int sock, optval = 1, SERVER_PORT = 8045;
	struct sockaddr_in server_address, client_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(SERVER_PORT);
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

	socklen_t client_address_len = sizeof(client_address);
	while (true) {
		char buffer[500];
		int len = recvfrom(sock, buffer, sizeof(buffer), 0,(struct sockaddr *)&client_address, &client_address_len);

		buffer[len] = '\0';
		printf("DATA: '%s' from client %s\n", buffer, inet_ntoa(client_address.sin_addr));

		//sendto(sock, buffer, len, 0, (struct sockaddr *)&client_address, sizeof(client_address));
	}

	return 0;
}
