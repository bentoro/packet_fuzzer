main: main.c ../lib/libpcap.c ../lib/raw_socket_wrappers.c ../lib/normal_socket_wrappers.c ../lib/logging.c ../lib/fuzz.c
	gcc -g -o main main.c ../lib/libpcap.c ../lib/raw_socket_wrappers.c ../lib/logging.c  ../lib/normal_socket_wrappers.c ../lib/fuzz.c -lpcap -pthread
clean:
	rm -f *.o main log replys
