all: arp-spoof

arp-spoof: arp-spoof.o ip.o mac.o main.o
	g++ -g -o arp-spoof arp-spoof.o ip.o mac.o main.o -lpcap

arp-spoof.o: arp-spoof.h arp-spoof.cpp
	g++ -c -o arp-spoof.o arp-spoof.cpp

ip.o: ip.h ip.cpp
	g++ -c -o ip.o ip.cpp

mac.o: mac.h mac.cpp
	g++ -c -o mac.o mac.cpp

main.o: arp-spoof.h main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f arp-spoof
	rm -f *.o
