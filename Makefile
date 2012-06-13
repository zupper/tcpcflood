prog = tcpcflood.c
exec = tcpcflood

all:
	gcc $(prog) -o $(exec) -lpcap

clean:
	rm -f a.out $(exec)
