
CC=gcc
CFLAGS=-std=gnu99
INCLUDES=-I. -I/usr/include -I/usr/include/apr-1.0
LD_FLAGS=-lapr-1 -laprutil-1

all: daemon invoice

daemon:
	$(CC) $(CFLAGS) -o daemon mongoose.c daemon.c $(INCLUDES) $(LD_FLAGS)

invoice:
	$(CC) $(CFLAGS) -o invoice invoice.c $(INCLUDES) $(LD_FLAGS) -lhpdf

test:
	./daemon -h 0.0.0.0 -p 8088 -l ./daemon.log

clean:
	rm -rf daemon invoice *.log

.PHONY: all test