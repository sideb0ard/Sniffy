CC=gcc
CFLAGS=-lpcap

all: 
	make clean
	$(CC) -o Sniffy $(CFLAGS) sniffy.c

clean:
	rm Sniffy
