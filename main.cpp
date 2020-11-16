#include <pcap.h>
#include <stdio.h>
#include "radiotap.h"
#include "beacon.h"
#include <algorithm>
using namespace std;

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        //printf("%u bytes captured\n\n", header->caplen);

        struct radiotap* radio = (struct radiotap*)(packet);
        struct beacon* beacon_packet = (struct beacon*)(packet + radio->len);
        if (beacon_packet->fc != 0x80) continue;
        //printf("%x\n\n",beacon_packet->fc);
        printf("*********** Beacon frame information ***********\n\n\n");
        printf("Radiotap Header\n\n");
        printf("Header revision:\t %x\n", radio->ver);
        printf("Header pad:\t\t %x\n", radio->pad);
        printf("Header length:\t\t %d\n", radio->len);
        printf("Present flags:\t\t %x\n\n\n", radio->present);

        printf("Beacon frame\n\n");
        printf("Frame Control Field:\t %x\n", beacon_packet->fc);
        printf("Duration:\t\t %d\n", beacon_packet->dur);
        printf("Reciever address:\t %x\n", beacon_packet->da);
        printf("Destination address:\t %x\n", beacon_packet->da);
        printf("Transmitter address:\t %x\n", beacon_packet->sa);
        printf("Source address:\t\t %x\n", beacon_packet->sa);
        printf("BSSID:\t\t\t %x\n", beacon_packet->sa);
        printf("Fragment number:\t %d\n", beacon_packet->frag);
        printf("Sequence number:\t %d\n\n\n", beacon_packet->seq);

        printf("wireless LAN\n\n");
        printf("-Fixed parameter-\n");
        printf("Timestamp:\t\t %ld\n", beacon_packet->fix_.timestamp);
        printf("Beacon Interval:\t %f [Seconds]\n", beacon_packet->fix_.binterval);
        printf("Capabilities:\t\t 0x%x\n", beacon_packet->fix_.cap);
        printf("-tagged parameter-\n");
        printf("%x\n", beacon_packet->tag_.num);
        printf("%x\n", beacon_packet->tag_.length);

//#if
//#endif

    }
    pcap_close(handle);
}
