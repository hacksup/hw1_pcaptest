this program is for sniffing packet 

we will capture 10 packets and we will get information about
-srcMAC, dstMAC
-srcIP, dstIP(it is optional. only for IP packet)
-srcPort, dstPort(it is optional, too. only for TCP packet)
-payload hex data(optional)

I studied for ip header and tcp header and understood how it works,
but print_payload code is referenced from tcpdump.org(which is site
that professor told). I used <netinet/ether.h> <netinet/ip.h>, and so on,
and I regret not using libnet library. 

I added a capture file that shows how payload is going to show up
when I login for naver. thank you




I compiled with gcc by

gcc -o test hw1.c -lpcap
