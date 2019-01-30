main: 3_way_handshake.c
	gcc -g -o main 3_way_handshake.c -lpcap
	gcc -g -o svr server.c
	gcc -g -o clt client.c
clean:
	rm -f *.o main svr clt
