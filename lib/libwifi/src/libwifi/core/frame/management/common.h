/* Copyright 2021 The libwifi Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBWIFI_CORE_COMMON_H
#define LIBWIFI_CORE_COMMON_H

#include "../../misc/security.h"
#include "../tag.h"
#include <stdint.h>
#include <stdlib.h>

#define LIBWIFI_BSS 0
#define LIBWIFI_STA 1

/*
 * A libwifi_bss struct is used as a common model for BSS / APs, and can be derived
 * from parsed frames or used to generate new frames. Fields may be optional.
 *
 * transmitter     - The transmitter MAC address
 * receiver        - The receiver MAC address
 * bssid           - BSSID MAC address
 * ssid            - AP SSID
 * hidden          - Hidden state boolean
 * channel         - BSS Channel
 * wps             - WPS state boolean
 * encryption_info - Bitfield of encryption state, such as WPA version and ciphers
 * signal          - RSSI in dBm
 * wpa_info        - WPA1 information, present if encryption_info has the WPA1 bit set
 * rsn_info        - WPA2 and/or WPA3 information, present if encryption_info has WPA2 or WPA3 bit set
 * tags            - List of tagged parameters
 */
struct libwifi_bss {
    unsigned char transmitter[6];
    unsigned char receiver[6];
    unsigned char bssid[6];
    char ssid[33];
    int8_t hidden;
    uint8_t channel;
    uint8_t wps;
    uint64_t encryption_info;
    int signal;
    struct libwifi_wpa_info wpa_info;
    struct libwifi_rsn_info rsn_info;
    struct libwifi_tagged_parameters tags;
};

/*
 * A libwifi_bss can be populated with dynamically allocated tags, which must be free'd by
 * the user application to avoid memory leaks. This function provides an easy wrapper for any
 * libwifi allocations made.
 */
static inline void libwifi_free_bss(struct libwifi_bss *bss) {
    free(bss->tags.parameters);
}

/*
 * A libwifi_sta struct is used as a common model for stations, roaming or associated,
 * and can be derived from parsed frames or used to generate new frames. Fields may be optional.
 *
 * channel         - BSS Channel
 * randomized      - Client has a likely randomized MAC
 * transmitter     - The transmitter MAC address
 * receiver        - The receiver MAC address
 * bssid           - BSSID MAC address
 * ssid            - AP SSID
 * broadcast_ssid  - STA is broadcasting for SSID
 * tags            - List of tagged parameters
 */
struct libwifi_sta {
    uint8_t channel;
    uint8_t randomized;
    unsigned char transmitter[6];
    unsigned char receiver[6];
    unsigned char bssid[6];
    char ssid[33];
    uint8_t broadcast_ssid;
    struct libwifi_tagged_parameters tags;
};

/*
 * A libwifi_sta can be populated with dynamically allocated tags, which must be free'd by
 * the user application to avoid memory leaks. This function provides an easy wrapper for any
 * libwifi allocations made.
 */
static inline void libwifi_free_sta(struct libwifi_sta *sta) {
    free(sta->tags.parameters);
}

#endif /* LIBWIFI_CORE_COMMON_H */
