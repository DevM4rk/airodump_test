#include <iostream>
#include <pcap.h>
#include <map>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <cstring>
#include <unistd.h>
#include <thread>
#include <mutex>
#include "radiotap_header.h"

//adapter : AWUS036NH

using namespace std;

static map<int, beacon_info> b;
static map<int, beacon_info>::iterator b_iter;
static map<int, data_info> d;
static map<int, data_info>::iterator d_iter;
static int b_map_key=1;
static int d_map_key=1;
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


        //Beacon frame
        if (ih->type_subtype == BEACON_FRAME || ih->type_subtype == PROBE_RESPONSE
                || ih->type_subtype == DATA || ih->type_subtype == QOS_DATA){
            mutex.lock();
            uint8_t * p = wlh + FIXED_PARAMETERS_LEN;
            int caplen = header->caplen - rh->it_length;            //all_len - rh_len
            int Tag_type;
            int Tag_length;
            int offset;
            struct beacon_info b_info;
            b_info.beacons=1;
            b_info.data=0;
            b_info.type= ih->type_subtype;


            //BSSID
            //if (memcmp(ih->add3, ih->add2, 6)==0) goto beacon_end;
            if(ih->type_subtype == DATA){
                for (int i=0;i<6;i++) b_info.bssid[i]=ih->add2[i];      //Data add2 = BSSID
            }
            else{
                for (int i=0;i<6;i++) b_info.bssid[i]=ih->add3[i];      //add3 = BSSID
            }
            //printf("BSSID : ");
            //for (int i=0;i<6;i++) printf("%02x:", b_info.bssid[i]); printf("\n");


            //PWR
            b_info.pwr = rh->it_antenna_signal;
            //printf("PWR : %d dBm \n", b_info.pwr);


            //CH
            b_info.channel = ((rh->it_channel_frequency)-2407)/5;
            //printf("Ch : %d \n", b_info.channel);


            //ENC
            b_info.encrypt = 0;    // OPN=1, WEP=2, WPA=3, WPA2=4
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


            //ESSID
            b_info.essid_len = *(wlh+FIXED_PARAMETERS_LEN+1);
            memcpy(b_info.essid, wlh+FIXED_PARAMETERS_LEN+2, b_info.essid_len);
            //printf("ESSID : ");
            //for(int i=0;i<*(wlh+FIXED_PARAMETERS_LEN+1);i++) printf("%c", b_info.essid[i]);
            //printf("\n");


            //Beacons
            for (b_iter = b.begin(); b_iter != b.end(); b_iter++) {
                if( memcmp((*b_iter).second.bssid, b_info.bssid, 6) == 0 ){
                    if (ih->type_subtype == BEACON_FRAME){
                        (*b_iter).second.beacons ++;
                        (*b_iter).second.encrypt = b_info.encrypt;
                        (*b_iter).second.essid_len = b_info.essid_len;
                        memcpy((*b_iter).second.essid, b_info.essid, b_info.essid_len);
                    }
                    if ((*b_iter).second.pwr < b_info.pwr) (*b_iter).second.pwr = b_info.pwr;
                    if (ih->type_subtype == QOS_DATA || ih->type_subtype == DATA) (*b_iter).second.data ++;
                    //printf("beacons : %d \n", (*b_iter).second.beacons);
                    break;
                }
            }
            if (b_iter == b.end()){
                if (ih->type_subtype == PROBE_RESPONSE || ih->type_subtype == DATA) b_info.beacons=0;
                if (ih->type_subtype == QOS_DATA || ih->type_subtype == DATA) b_info.data++;
                b[b_map_key]=b_info;
                b_map_key++;
            }
            mutex.unlock();
        }

        //Data frame
        if (ih->type_subtype == PROBE_REQUEST || ih->type_subtype == NULL_FUNCTION
                || ih->type_subtype == QOS_NULL_FUNCTION || ih->type_subtype == QOS_DATA
                || ih->type_subtype == AUTHENTICATION || ih->type_subtype == ACTION){
            mutex.lock();
            struct data_info d_info;
            d_info.frames=1;
            d_info.type= ih->type_subtype;

            //BSSID, STATION
            if(ih->type_subtype == QOS_DATA){
                switch(ih->flags & 0x03){
                case 1:{     //flag = T, 0001
                    for (int i=0;i<6;i++) d_info.bssid[i]=ih->add1[i];      //BSSID,    add1 = BSSID
                    for (int i=0;i<6;i++) d_info.station[i]=ih->add2[i];    //STATION,  add2 = STA
                    break;
                }
                case 2:{     //flag = F, 0010
                    for (int i=0;i<6;i++) d_info.bssid[i]=ih->add2[i];      //BSSID,    add2 = BSSID
                    for (int i=0;i<6;i++) d_info.station[i]=ih->add1[i];    //STATION,  add1 = STA
                    break;
                }
                }
            }
            else{            //Request, Null f, Qos Null f, Authentication, Action
                if (memcmp(ih->add2, ih->add3, 6)==0) goto data_end;
                for (int i=0;i<6;i++) d_info.bssid[i]=ih->add3[i];      //Null f, Qos Null f add3 = Des = BSSID
                for (int i=0;i<6;i++) d_info.station[i]=ih->add2[i];    //add2 = Source
            }

            //PWR
            d_info.pwr = rh->it_antenna_signal;

            //Probe
            if (ih->type_subtype == PROBE_REQUEST){
                d_info.probe_len = *(wlh+1);
                memcpy(d_info.probe, wlh+2, d_info.probe_len);
            }

            //Frames
            for (d_iter = d.begin(); d_iter != d.end(); d_iter++) {
                if( memcmp((*d_iter).second.station, d_info.station, 6) == 0 ){
                    (*d_iter).second.frames ++;
                    if((*d_iter).second.pwr < d_info.pwr) (*d_iter).second.pwr = d_info.pwr;
                    if ((*d_iter).second.probe_len == 0){
                        (*d_iter).second.probe_len = d_info.probe_len;
                        memcpy((*d_iter).second.probe, d_info.probe, d_info.probe_len);
                    }
                    break;
                }
            }
            if (d_iter == d.end()){
                d[d_map_key]=d_info;
                d_map_key++;
            }
data_end:
            mutex.unlock();
        }
    }
    pcap_close(handle);
    return 0;
}

void printdata(std::mutex& mutex){
    while(1){
        mutex.lock();

        //Print Beacon frame
        printf("      BSSID \t   PWR \t Beacons     #Data, \tCH \tENC \tESSID \n\n");

        for( b_iter= b.begin(); b_iter != b.end(); b_iter++){
            for (int i=0;i<6;i++) {
                printf("%02X", (*b_iter).second.bssid[i]);
                if (i<5) printf(":");
            }

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
                if((*b_iter).second.beacons ==0) {
                    printf("<length:  0>");
                }
                else{
                    for(int i=0;i<(*b_iter).second.essid_len;i++){
                        printf("%c", (*b_iter).second.essid[i]);
                    }
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

            for (int i=0;i<6;i++) {
                printf("%02X", (*d_iter).second.station[i]);
                if (i<5) printf(":");
            }

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

void usage() {
    printf("syntax: airodump_test <interface>\n");
    printf("sample: airodump_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    std::mutex mutex;
    thread t1(savedata,argv[1],ref(mutex));
    thread t2(printdata,ref(mutex));

    t1.join();
    t2.join();

    return 0;
}
