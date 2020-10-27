#pragma once
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <time.h>
#include "mac.h"
#include "ip.h"

#define Ethhdr_Len 14
#define Arphdr_Len 28

void get_attacker_ip(char* ipaddr,  char* dev);
void get_attacker_mac(char* macaddr, char* dev);
void get_host_mac(char* senderip, char* sendermac, char* attip, char* attmac, pcap_t* handle);
void send_arp_pkt(char* destip, char* destmac, char* srcip, char* srcmac, pcap_t* handle, int opcode);
bool check_packet(char* ip, uint8_t* new_ip);

#pragma pack(push, 1)
struct EthHdr final {
	Mac      dmac_;
	Mac      smac_;
	uint16_t type_;

	Mac      dmac() { return dmac_; }
	Mac      smac() { return smac_; }
	uint16_t type() { return ntohs(type_); }

	typedef enum {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	} Type;
};
typedef EthHdr *PEthHdr;

struct ArpHdr final {
	uint16_t hrd_;
	uint16_t pro_;
	uint8_t  hln_;
	uint8_t  pln_;
	uint16_t op_;
	Mac      smac_;
	Ip       sip_;
	Mac      tmac_;
	Ip       tip_;

	uint16_t hrd()  { return ntohs(hrd_); }
	uint16_t pro()  { return ntohs(pro_); }
	uint8_t  hln()  { return hln_;        }
	uint8_t  pln()  { return pln_;        }
	uint16_t op()   { return ntohs(op_);  }
	Mac      smac() { return smac_;       }
	Ip       sip()  { return ntohl(sip_); }
	Mac      tmac() { return tmac_;       }
	Ip       tip()  { return ntohl(tip_); }

	typedef enum {
		NETROM   = 0,  // from KA9Q: NET/ROM pseudo
		ETHER    = 1,  // Ethernet 10Mbps
		EETHER   = 2,  // Experimental Ethernet
		AX25     = 3,  // AX.25 Level 2
		PRONET   = 4,  // PROnet token ring
		CHAOS    = 5,  // Chaosnet
		IEEE802  = 6,  // IEEE 802.2 Ethernet/TR/TB
		ARCNET   = 7,  // ARCnet
		APPLETLK = 8,  // APPLEtalk
		LANSTAR  = 9,  // Lanstar
		DLCI     = 15, // Frame Relay DLCI
		ATM      = 19, // ATM
		METRICOM = 23, // Metricom STRIP (new IANA id)
		IPSEC    = 31  // IPsec tunnel
	} HardwareType;

	typedef enum {
		Request    = 1, // req to resolve address
		Reply      = 2, // resp to previous request
		RevRequest = 3, // req protocol address given hardware
		RevReply   = 4, // resp giving protocol address
		InvRequest = 8, // req to identify peer
		InvReply   = 9  // resp identifying peer
	} Operation;
};
typedef ArpHdr *PArpHdr;
#pragma pack(pop)

