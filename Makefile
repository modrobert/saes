HEADERS = aes.h
CC = gcc
CFLAGS = -O2 -Wpedantic

default: saes

debug: CFLAGS = -g -Wpedantic
debug: saes

saes.o: saes.c
	$(CC) $(CFLAGS) -c saes.c -o saes.o

aes.o: aes.c $(HEADERS)
	$(CC) $(CFLAGS) -c aes.c -o aes.o

saes: saes.o aes.o
	$(CC) $(CFLAGS) saes.o aes.o -o saes

clean:
	-rm -f saes.o
	-rm -f aes.o
	-rm -f saes
	
