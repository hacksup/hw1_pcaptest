/*
It is a program for packet sniffing(only for eth, ip, tcp)
If there is s payload, we can get heximal values (I tested naver login)

I referenced codes for print_payload from tcpdump.org 
*/




#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


void print_payload(const u_char *payload, int len);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

int main(int argc, char *argv[])
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int packetnum = 10; //number of packets to sniff on

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		printf("error occurred : %s \n", errbuf);
		return(2);
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //1000 means 1second
	if(handle == NULL){
		printf("error occurred : %s \n", errbuf);
		return(2);
	}

	printf("####We will capture 10 packets!####\n");
	pcap_loop(handle, packetnum, got_packet, NULL);
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1; //packet counter

//	u_char *srcMAC, *dstMAC;
	struct ether_addr* srcMAC, *dstMAC;
	u_char *srcIP, *dstIP;
	int srcPort, dstPort;
	const char* payload;

	int size_ether=14; //we already know size of ethernet header is 14 byte
	int size_payload;
	int size_ip;
	int size_tcp;

	struct ether_header* ethHdr;
	struct ip* ipHdr;
	struct tcphdr *tcpHdr;

	printf("\nPacket number : %d \n", count++);

	//start from ethernet
	//ether_hdr size = dstMAC(6)+srcMAC(6)+ethertype(2) = 14byte
	ethHdr = (struct ether_header *)packet;

	/*dstMAC = (struct ether_addr *)ethHdr;
	srcMAC = (struct ether_addr *)(ethHdr+6);*/ //for testing

	dstMAC = (struct ether_addr *)(ethHdr->ether_dhost);
	srcMAC = (struct ether_addr *)(ethHdr->ether_shost);
	printf("Source MAC : %s\n", ether_ntoa(srcMAC));
	printf("Destination MAC : %s\n", ether_ntoa(dstMAC));


	//check wheter it is IP
	if(ntohs(ethHdr->ether_type) != ETHERTYPE_IP){
		printf("This packet is not an IP!\n");
		return;
	}

	//now we know this packet is IP
	ipHdr = (struct ip*)(packet + size_ether); //14 means size of ethHdr
	printf("Source IP : %s\n", inet_ntoa(ipHdr->ip_src));
	printf("Destination IP : %s\n", inet_ntoa(ipHdr->ip_dst));

	size_ip = 4*ipHdr->ip_hl; //ip and tcp must mulpiply 4


	//check whether it is TCP
	if(ipHdr->ip_p != IPPROTO_TCP){
		printf("This packet is not an TCP!\n");
		return;
	}

	//now we know this packet is TCP
	tcpHdr = (struct tcphdr*)(packet + size_ether + size_ip);
	printf("Source Port : %d\n", ntohs(tcpHdr->th_sport));
	printf("Destination Port : %d\n", ntohs(tcpHdr->th_dport));

	size_tcp = 4*tcpHdr->th_off;

	//now we will print payload
	payload = (u_char *)(packet + size_ether + size_ip + size_tcp);

	//compute tcp payload size
	size_payload = ntohs(ipHdr->ip_len) - (size_ip + size_tcp);

	//if there is payload
	if(size_payload>0){
		printf("Payload(%d bytes): \n", size_payload);
		print_payload(payload, size_payload);
	}
	return;
}


