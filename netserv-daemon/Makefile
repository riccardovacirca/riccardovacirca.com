CC=gcc
CFLAGS=-std=gnu99
INCLUDES=-I. -I../netserv -I/usr/include -I/usr/include/apr-1.0
LD_FLAGS=-lapr-1 -laprutil-1

all: 
	$(CC) $(CFLAGS) -o netservd mongoose.c ../netserv/netserv.c main.c $(INCLUDES) $(LD_FLAGS)

test:
	./netservd -h 0.0.0.0 -p 8088 -l ./netservd.log

clean:
	rm -rf netservd *.log

.PHONY: all test