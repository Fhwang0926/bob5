all : arp_poison

arp_poison :
	gcc -o arp_poison main.c -lpcap -lnet

clean :
	rm -f *.o
	rm -f arp_poison
