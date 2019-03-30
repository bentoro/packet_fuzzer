tcp: ../lib/normal_socket_wrappers.c ../lib/fuzz.c
	gcc -g -o tcp tcpserver.c ../lib/normal_socket_wrappers.c ../lib/fuzz.c
	gcc -g -o udp udpserver.c ../lib/fuzz.c
clean:
	rm -f *.o tcp udp icmp
