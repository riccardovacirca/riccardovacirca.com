
daemon:
	gcc -std=gnu99 -o daemon mongoose.c daemon.c -I. -I/usr/include/apr-1.0 -lapr-1 -laprutil-1
	./daemon -h 0.0.0.0 -p 8088 -l ./daemon.log

.PHONY: daemon