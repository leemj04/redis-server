all: redis server client
	gcc -o server server.o redis.o
	gcc -o client client.o

redis: redis.o
	gcc -c -o redis.o redis.c

server: server.o
	gcc -c -o server.o server.c -lpthread

client: client.o
	gcc -c -o client.o client.c

clean:
	rm -f *.o
	rm -f server
	rm -f client