#include <iostream>
#include <pcap.h>
#include <map>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <cstring>
#include <unistd.h>
#include <thread>
#include "radiotap_header.h"

//adapter : AWUS036NH

using namespace std;

static map<int, data> m;
static map<int, data>::iterator iter;
static int map_key=1;

int savedata(char* argv){
    char* dev = argv;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        struct radiotap_header *rh = (struct radiotap_header *)packet;
        struct ieee80211_header *ih = (struct ieee80211_header *)(packet + rh->it_length);
        //printf("%u bytes captured \n", header->caplen);


        //Beacon frame
        if (ih->type_subtype == 0x80){
            uint8_t * wlh = (uint8_t *)ih + IEEE_LEN;               //wireless LAN header
            struct data info;
            info.beacons=1;
            //std::map<int, data> m;
            //std::map<int, data>::iterator iter;


            //BSSID
            for (int i=0;i<6;i++) info.bssid[i]=ih->bssid[i];
            //printf("BSSID : ");
            //for (int i=0;i<6;i++) printf("%02x:", info.bssid[i]); printf("\n");


            //PWR
            if (rh->it_antenna_signal<127)
                info.pwr = rh->it_antenna_signal -1;
            else
                info.pwr = rh->it_antenna_signal -255 -1;
            //printf("PWR : %d dBm \n", info.pwr);


            //CH
            info.channel = ((rh->it_channel_frequency)-2407)/5;
            //printf("Ch : %d \n", info.channel);


            //ENC
            info.encrypt = 0;    // OPN=1, WEP=2, WPA=3, WPA2=4
            if (!(info.encrypt & (OPN | WEP | WPA | WPA2))) {
                if ((*(wlh+10) & 0x10) >> 4){
                    info.encrypt = WEP;
                }
                else{
                    info.encrypt = OPN;
                }
            }

            uint8_t * p = wlh + FIXED_PARAMETERS_LEN;
            int caplen = header->caplen - rh->it_length;    //all_len - rh_len
            int Tag_type;
            int Tag_length;
            int offset;

            while (p < (uint8_t *)ih + caplen){
                Tag_type = p[0];
                Tag_length = p[1];
                // printf("type :%d 0x%02x, length : %d \n ", p[0], p[0], p[1]);

                if (p + 2 + Tag_length > (uint8_t *)ih + caplen){
                    /*                printf("error parsing tags! %p vs. %p (tag:
                            %i, length: %i,position: %i)\n", (p+2+Tag_length), (h80211+caplen),
                            Tag_type, Tag_length, (p-h80211));
                            exit(1);*/
                    break;
                }

                // Find WPA and RSN tags
                if ((Tag_type == 0xDD && (Tag_length >= 8)
                     && (memcmp(p + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0))
                        || (Tag_type == 0x30)) {

                    p += Tag_length + 2;
                    offset = 0;

                    if (Tag_type == 0xDD){          // WPA defined in vendor specific tag -> WPA1 support
                        info.encrypt = WPA;
                        offset = 4;
                    }

                    // RSN => WPA2
                    if (Tag_type == 0x30){
                        info.encrypt = WPA2;
                        offset = 0;
                    }

                    if (Tag_length < (18 + offset)){
                        //printf("Tag_length : %d,  18+offset : %d ", Tag_length, 18+offset );
                        continue;
                    }
                }
                else{
                    p += Tag_length + 2;
                }
            }


            //ESSID
            info.essid_len = *(wlh+FIXED_PARAMETERS_LEN+1);
            memcpy(info.essid, wlh+FIXED_PARAMETERS_LEN+2, info.essid_len);
            //printf("ESSID : ");
            //for(int i=0;i<*(wlh+F    IXED_PARAMETERS_LEN+1);i++) printf("%c", info.essid[i]);
            //printf("\n");


            //Beacons
            for (iter = m.begin(); iter != m.end(); iter++) {
                if( memcmp((*iter).second.bssid, info.bssid, 6) == 0 ){
                    (*iter).second.beacons ++;
                    (*iter).second.pwr = info.pwr;
                    //printf("beacons : %d \n", (*iter).second.beacons);
                    break;
                }
            }
            if (iter == m.end()){
                m[map_key]=info;
                map_key++;
            }
        }
    }
    pcap_close(handle);
    return 0;
}

void printdata(){
    while(1){
        printf("     BSSID \t\t PWR \t Beacons \t CH \t ENC \t ESSID \n\n");

        for( iter= m.begin(); iter != m.end(); iter++){
            for (int i=0;i<6;i++) {
                printf("%02X", (*iter).second.bssid[i]);
                if (i<5) printf(":");
            }

            printf("\t %d \t      %d \t %d \t ",(*iter).second.pwr
                   ,(*iter).second.beacons ,(*iter).second.channel);

            switch((*iter).second.encrypt){
            case OPN:{                          //1
                printf("OPN  \t");
                break;
            }
            case WEP:{                          //2
                printf("WEP  \t");
                break;
            }
            case WPA:{                          //3
                printf("WPA  \t");
                break;
            }
            case WPA2:{                         //4
                printf("WPA2 \t");
                break;
            }
            }

            for(int i=0;i<(*iter).second.essid_len;i++){
                printf("%c", (*iter).second.essid[i]);
            }
            printf("\n");
        }




        sleep(1);
        system("clear");

    }
}

void usage() {
    printf("syntax: airodump_test <interface>\n");
    printf("sample: airodump_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    thread t1(savedata,argv[1]);
    thread t2(printdata);

    t1.join();
    t2.join();

    return 0;
}
