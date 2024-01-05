
CC=gcc
CFLAGS=-std=gnu99
INCLUDES=-I. -I/usr/include/apr-1.0
LD_FLAGS=-lapr-1 -laprutil-1

all:
	$(CC) $(CFLAGS) -o daemon mongoose.c daemon.c $(INCLUDES) $(LD_FLAGS)

test:
	./daemon -h 0.0.0.0 -p 8088 -l ./daemon.log

.PHONY: all test