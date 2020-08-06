pcap_Fhwang : main.o
	gcc -o pcap_Fhwang main.o -lpcap
	clear

main.o : main.c
	gcc -c -o main.o main.c -lpcap

clean :
	rm -f *.o
	rm -f pcap_Fhwang
