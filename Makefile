CC=gcc
CFLAGS=-lpcap

sniffy: 
	$(CC) -o Sniffy $(CFLAGS) sniffy.c
