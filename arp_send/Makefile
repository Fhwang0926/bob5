all : arp_send

arp_send : main.o
	g++ -g -o arp_send main.o -lnet -lpcap

main.o : main.cpp
	g++ -g -c -o main.o main.cpp -lnet -lpcap

clean :
	rm -f *.o
	rm -f arp_send
