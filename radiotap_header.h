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
         Beacon Frame, Probe Request, Probe Response, Authentication, Action
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
        uint8_t        add1[6];
        uint8_t        add2[6];
        uint8_t        add3[6];
        uint16_t       fragment_sequence;
};

struct beacon_info {    //Beacon frame, Probe Response, Data
    uint8_t type;
    uint8_t bssid[6];
    char pwr;
    int beacons;
    int data;
    int channel;
    int encrypt;
    int essid_len;
    uint8_t essid[32];
};

struct data_info {
    uint8_t type;
    uint8_t bssid[6];
    uint8_t station[6];
    char pwr;
    int frames;
    int probe_len;
    uint8_t probe[32];
};
