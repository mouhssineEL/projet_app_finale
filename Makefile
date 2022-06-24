# Makefile for socket programs

serveur:	
	gcc -Wall -o serveur serveur.c
client: 	
	gcc -Wall -o client client.c	

gcc all: serveur client
	
#clean function
clean:
	rm serveur
	rm client
