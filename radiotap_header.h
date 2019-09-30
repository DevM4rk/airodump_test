#include <stdint.h>
#pragma once

#define IEEE_LEN 24
#define FIXED_PARAMETERS_LEN 12
#define OPN 1
#define WEP 2
#define WPA 3
#define WPA2 4

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
        uint8_t        order_flag;
        uint16_t       duration;
        uint8_t        rec_des_add[6];
        uint8_t        trans_source_add[6];
        uint8_t        bssid[6];
        uint16_t       fragment_sequence;
};

struct data {
    uint8_t bssid[6];
    int pwr;
    int beacons;
    int channel;
    int encrypt;
    int essid_len;
    uint8_t essid[32];
};
