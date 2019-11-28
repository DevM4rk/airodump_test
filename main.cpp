#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <map>
#include <stdlib.h>
#include <cstring>
#include <stdint.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <time.h>

#include "radiotap_header.h"

//adapter : AWUS036NH

using namespace std;

static map<mac_key, beacon_info> b;
static map<mac_key, beacon_info>::iterator b_iter;
static map<mac_key, data_info> d;
static map<mac_key, data_info>::iterator d_iter;
static int ch = 1;
static time_t start;
static time_t now;
uint8_t brodcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
uint8_t null_id[20] = { 0, };

int savedata(char* argv, std::mutex& mutex){
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
        uint8_t * wlh = (uint8_t *)ih + IEEE_LEN;               //wireless LAN header
        //printf("%u bytes captured \n", header->caplen);
        if(rh->it_length == 13 || rh->it_length == 14) continue;

        //Beacon frame
        if (ih->type_subtype == BEACON_FRAME /*|| ih->type_subtype == PROBE_RESPONSE
                                        || ih->type_subtype == DATA || ih->type_subtype == QOS_DATA
                                        ||ih->type_subtype == NULL_FUNCTION || ih->type_subtype == QOS_NULL_FUNCTION
                                        ||ih->type_subtype == AUTHENTICATION || ih->type_subtype == DEAUTHENTICATION
                                        ||ih->type_subtype == ACTION*/){

            mutex.lock();
            auto b_iter = b.find(ih->add3);             //BSSID
            if(b_iter ==b.end()){
                uint8_t * p = wlh + FIXED_PARAMETERS_LEN;
                int caplen = header->caplen - rh->it_length;            //all_len - rh_len
                int Tag_type;
                int Tag_length;
                int offset;
                beacon_info b_info;

                b_info.pwr = rh->it_antenna_signal;
                b_info.channel = ((rh->it_channel_frequency)-2407)/5;

                if (!(b_info.encrypt & (OPN | WEP | WPA | WPA2))) {
                    if ((*(wlh+10) & 0x10) >> 4){
                        b_info.encrypt = WEP;
                    }
                    else{
                        b_info.encrypt = OPN;
                    }
                }
                while (p < (uint8_t *)ih + caplen){
                    Tag_type = p[0];
                    Tag_length = p[1];

                    if (p + 2 + Tag_length > (uint8_t *)ih + caplen){
                        //printf("error parsing tags! \n");
                        break;
                    }
                    // Find WPA and RSN tags
                    if ((Tag_type == 0xDD && (Tag_length >= 8)
                         && (memcmp(p + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0))
                            || (Tag_type == 0x30)) {
                        p += Tag_length + 2;
                        offset = 0;

                        if (Tag_type == 0xDD){          // WPA defined in vendor specific tag -> WPA1 support
                            b_info.encrypt = WPA;
                            offset = 4;
                        }
                        // RSN => WPA2
                        if (Tag_type == 0x30){
                            b_info.encrypt = WPA2;
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

                if(ih->type_subtype == BEACON_FRAME || ih->type_subtype == PROBE_RESPONSE){
                    b_info.essid_len = *(wlh+FIXED_PARAMETERS_LEN+1);
                    memcpy(b_info.essid, wlh+FIXED_PARAMETERS_LEN+2, b_info.essid_len);
                }

                if (ih->type_subtype == BEACON_FRAME) b_info.beacons=1;
                if (ih->type_subtype == QOS_DATA || ih->type_subtype == DATA) b_info.data++;
                b[ih->add3] = b_info;
            }
            else{
                //if (ih->type_subtype == QOS_DATA || ih->type_subtype == DATA) (*b_iter).second.data ++;
                if (ih->type_subtype == BEACON_FRAME) (*b_iter).second.beacons ++;
                (*b_iter).second.pwr = rh->it_antenna_signal;
            }
            mutex.unlock();
        }

        //Data frame
        if (ih->type_subtype == PROBE_REQUEST /*|| ih->type_subtype == NULL_FUNCTION
                                                || ih->type_subtype == QOS_NULL_FUNCTION || ih->type_subtype == QOS_DATA
                                                || ih->type_subtype == AUTHENTICATION || ih->type_subtype == ACTION*/){
            mutex.lock();
            auto d_iter = d.find(ih->add2);             //station
            if(d_iter ==d.end()){
                data_info d_info;
                d_info.pwr = rh->it_antenna_signal;
                d_info.frames=1;
                d_info.type= ih->type_subtype;

                uint8_t *ptr = reinterpret_cast<uint8_t*>(&ih->add3);
                for (int i=0;i<6;i++) d_info.bssid[i]=ptr[i];

                if (ih->type_subtype == PROBE_REQUEST){
                    d_info.probe_len = *(wlh+1);
                    memcpy(d_info.probe, wlh+2, d_info.probe_len);
                }
printf("%02x" , d_info.probe_len);
                d[ih->add2] = d_info;
            }
            else{
                (*d_iter).second.frames ++;
                (*d_iter).second.pwr = rh->it_antenna_signal;
            }
            mutex.unlock();
        }

    }
    pcap_close(handle);
    return 0;
}

void print_mac(mac_key mac){
    uint8_t *ptr = reinterpret_cast<uint8_t*>(&mac);
    for (int i=0;i<6;i++) {
        printf("%02X", ptr[i]);
        if (i<5) printf(":");
    }
}

void printdata(std::mutex& mutex){
    while(1){
        mutex.lock();
        time(&now);
        printf("\n CH %d ][ Elapsed: %d s ][ %s\n\n",ch ,now-start ,ctime(&now));
        //Print Beacon frame
        printf("      BSSID \t   PWR \t Beacons     #Data, \tCH \tENC \tESSID \n\n");

        for( b_iter= b.begin(); b_iter != b.end(); b_iter++){
            print_mac(b_iter->first);

            printf("  %d \t      %d \t %d \t%d \t",(*b_iter).second.pwr
                   ,(*b_iter).second.beacons ,(*b_iter).second.data, (*b_iter).second.channel);

            switch((*b_iter).second.encrypt){
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

            if(memcmp((*b_iter).second.essid, null_id, (*b_iter).second.essid_len) == 0){
                printf("<length: %d>", (*b_iter).second.essid_len);
            }
            else {
                for(int i=0;i<(*b_iter).second.essid_len;i++){
                    printf("%c", (*b_iter).second.essid[i]);
                }
            }
            printf("\n");
        }

        //Print Data
        printf("\n      BSSID \t        STATION \tPWR    Frames\tProbe \n\n");

        for( d_iter= d.begin(); d_iter != d.end(); d_iter++){
            if(memcmp((*d_iter).second.bssid,brodcast,6) == 0){
                printf("(not associated)   ");
            }
            else{
                for (int i=0;i<6;i++) {
                    printf("%02X", (*d_iter).second.bssid[i]);
                    if (i<5) printf(":");
                }
                printf("  ");
            }

            print_mac(d_iter->first);

            printf("\t%d \t   %d\t",(*d_iter).second.pwr ,(*d_iter).second.frames);

            if((*d_iter).second.type == PROBE_REQUEST){
                for(int i=0;i<(*d_iter).second.probe_len;i++){
                    printf("%c", (*d_iter).second.probe[i]);
                }
            }
            printf("\n");
        }
        mutex.unlock();
        sleep(1);
        system("clear");
    }
}

void ch_hopping(char* dev){
    while (true) {
        char cmd[32] = "iwconfig ";
        strcat(cmd, dev);
        strcat(cmd, " channel ");
        sprintf(cmd + 23, "%d", ch);
        system(cmd);
        sleep(1);
        ch += 6;
        ch %= 13;
        if(!ch) ch = 13;
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

    char* dev = argv[1];
    time(&start);
    std::mutex mutex;
    thread t1(savedata,dev,ref(mutex));
    thread t2(ch_hopping,dev);
    thread t3(printdata,ref(mutex));

    t1.join();
    t2.join();
    t3.join();

    return 0;
}
