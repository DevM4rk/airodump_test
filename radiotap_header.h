#include <stdint.h>
#pragma once

#define IEEE_LEN 24
#define FIXED_PARAMETERS_LEN 12
#define OPN 1
#define WEP 2
#define WPA 3
#define WPA2 4

#define DATA 0x08
#define PROBE_RESPONSE 0x50
#define BEACON_FRAME 0x80

#define AUTHENTICATION 0xb0
#define DEAUTHENTICATION 0xc0
#define ACTION 0xd0
#define NULL_FUNCTION 0x48
#define PROBE_REQUEST 0x40
#define QOS_DATA 0x88
#define QOS_NULL_FUNCTION 0xc8

struct mac_key{     //BSSID
    uint64_t mac:48;                                        //what : ?
} __attribute__((__packed__));

bool operator<(mac_key const& m1, mac_key const& m2){       //const o x ?
    return m1.mac < m2.mac;
}

struct radiotap_header {
        uint8_t        it_version;     /* set to 0 */
        uint8_t        it_pad;
        uint16_t       it_length;         /* entire length */
        uint32_t       it_present_flags;     /* fields present */
        uint8_t        it_flags;
        uint8_t        it_data_Rate;
        uint16_t       it_channel_frequency;
        uint16_t       it_channel_flags;
        uint8_t        it_antenna_signal;
        uint8_t        it_antenna;
        uint16_t       it_RX_flags;
};

struct ieee80211_header {
        uint8_t        type_subtype;
        uint8_t        flags;
        uint16_t       duration;
        /*
         Beacon Frame, Probe Request, Probe Response, Authentication, Deauthentication, Action
            add1 = Receiver, Destination
            add2 = Transmitter, Source
            add3 = BSSID

         Data
            add1 = Rec, Des, STA
            add2 = Trans, BSSID
            add3 = Source

         Qos Null function, Qos Data, Null function
            add1 = Receiver, BSSID
            add2 = Transmitter, Source, STA
            add3 = Destination
          */
        mac_key add1;           //6byte
        mac_key add2;
        mac_key add3;
        uint16_t       fragment_sequence;
};

#pragma pack(push, 1)

struct beacon_info {    //Beacon frame, Probe Response, Data, Qos Data
    char pwr=0;
    int beacons=0;
    int data=0;
    int channel=0;
    int encrypt=0;        // OPN=1, WEP=2, WPA=3, WPA2=4
    int essid_len=0;
    uint8_t essid[32];
};

struct data_info {
    uint8_t type=0;
    uint8_t bssid[6];
    char pwr=0;
    int frames=0;
    int probe_len=0;
    uint8_t probe[32];
};

#pragma pack(pop)
