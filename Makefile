# Makefile for socket programs

server:	
	gcc -Wall -o server server.c
client: 	
	gcc -Wall -o client client.c	

gcc all: server client
	
#clean function
clean:
	rm server
	rm client
