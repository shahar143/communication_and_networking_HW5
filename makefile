makefile:

all: sniffer spoofer gateway snoofer sender

sniffer : Sniffer.c
	gcc -o sniffer Sniffer.c -lpcap

snoofer : snoofer.c
	gcc -o snoofer snoofer.c -lpcap

spoofer : Spoofer.c
	gcc Spoofer.c -o spoofer

sender : sender.c
	gcc sender.c -o sender

gateway : Gateway.c
	gcc Gateway.c -o gateway

clean:
	rm -f *.o sniffer spoofer snoofer sender gateway 
