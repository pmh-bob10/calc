#include <pcap.h>
#include <stdio.h>
#include "ethhdr.h"
#include "arphdr.h"     
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>

#define IFNAMSIZ 16

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

uint8_t* _pcap_next(pcap_t* pcap) {
  pcap_pkthdr *pkt_header;
  const uint8_t *pkt_data;
  int res = pcap_next_ex(pcap, &pkt_header, &pkt_data);

  if (res == 0) return NULL;
  if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
    fprintf(stderr, "pcap_next_ex return %d - %s\n", res, pcap_geterr(pcap));
    exit(-1);
  }

  return (uint8_t*) pkt_data;
}

EthArpPacket* pcap_next_arp(pcap_t* pcap, Ip target_ip) {
	for (;;) {
		EthArpPacket *pkt = (EthArpPacket*) _pcap_next(pcap);
		if (pkt == NULL) continue;

		if (pkt->eth_.type_ != pkt->eth_.Arp)
			continue;

		if (pkt->arp_.op_ != pkt->arp_.Reply)
			continue;

		if (pkt->arp_.sip_ != target_ip)
			continue;

		return pkt;
	}
}


Mac get_my_mac (char* dev) {
    ifaddrs *ifAddrStruct = NULL;
    ifaddrs *ifa = NULL;

    void *tmpAddrPtr=NULL;
    getifaddrs(&ifAddrStruct);

	Ip ip = NULL;
	Mac mac = NULL;

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_name != dev)
			continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            ip = Ip(addressBuffer);
        } else if (ifa->ifa_addr->sa_family == AF_PACKET) {
            tmpAddrPtr=&((struct sockaddr_ll *)ifa->ifa_addr)->;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
        } 
    }

    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);

	return Mac(mac_buffer);
}

Mac arp_query (pcap_t* handle, Mac source_mac, Ip target_ip) {
	EthArpPacket packet;
	
	packet.eth_.smac_ = source_mac;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = source_mac;
	packet.arp_.sip_ = htonl(Ip("192.168.0.33"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(target_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	EthArpPacket *pkt = pcap_next_arp(handle, target_ip);
	return pkt->arp_.smac_;
}

int main(int argc, char** argv) {
	if (argc < 4 || argc % 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Mac my_mac = get_my_mac(dev);


	for (int i = 1; i < argc - 1;) {
		Ip sender_ip = Ip(argv[++i]);
		Ip target_ip = Ip(argv[++i]);

		Mac sender_mac = arp_query(handle, my_mac, sender_ip);


		// EthArpPacket packet;

		// packet.eth_.dmac_ = Mac("b2:0f:68:1e:73:fd");
		// packet.eth_.smac_ = Mac("88:36:6c:c7:53:77");
		// packet.eth_.type_ = htons(EthHdr::Arp);

		// packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		// packet.arp_.pro_ = htons(EthHdr::Ip4);
		// packet.arp_.hln_ = Mac::SIZE;
		// packet.arp_.pln_ = Ip::SIZE;
		// packet.arp_.op_ = htons(ArpHdr::Reply);
		// packet.arp_.smac_ = Mac("04:56:e5:f8:0b:6f");
		// packet.arp_.sip_ = htonl(Ip("192.168.0.1"));
		// packet.arp_.tmac_ = Mac("88:36:6c:c7:53:77");
		// packet.arp_.tip_ = htonl(Ip("192.168.0.33"));

		// int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		// if (res != 0) {
		// 	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		// }
	}
	

//	EthArpPacket packet;

//	packet.eth_.dmac_ = Mac("b2:0f:68:1e:73:fd");
//	packet.eth_.smac_ = Mac("88:36:6c:c7:53:77");
//	packet.eth_.type_ = htons(EthHdr::Arp);
//
//	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
//	packet.arp_.pro_ = htons(EthHdr::Ip4);
//	packet.arp_.hln_ = Mac::SIZE;
//	packet.arp_.pln_ = Ip::SIZE;
//	packet.arp_.op_ = htons(ArpHdr::Reply);
//	packet.arp_.smac_ = Mac("04:56:e5:f8:0b:6f");
//	packet.arp_.sip_ = htonl(Ip("192.168.0.1"));
//	packet.arp_.tmac_ = Mac("88:36:6c:c7:53:77");
//	packet.arp_.tip_ = htonl(Ip("192.168.0.33"));
//
//	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
//	if (res != 0) {
//		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
//	}
//
	pcap_close(handle);
}
