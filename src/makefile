main: main.c ../lib/libpcap.c ../lib/raw_socket_wrappers.c ../lib/normal_socket_wrappers.c ../lib/logging.c ../lib/fuzz.c
	gcc -g -o main main.c ../lib/libpcap.c ../lib/raw_socket_wrappers.c ../lib/logging.c ../lib/fuzz.c -lpcap -pthread
	gcc -g -o svr server.c
	gcc -g -o clt client.c ../lib/normal_socket_wrappers.c
clean:
	rm -f *.o main svr clt
