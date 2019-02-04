main: main.c ../lib/libpcap.c ../lib/raw_socket_wrappers.c
	gcc -g -o main main.c ../lib/libpcap.c ../lib/raw_socket_wrappers.c -lpcap
	gcc -g -o svr server.c
	gcc -g -o clt client.c
clean:
	rm -f *.o main svr clt
