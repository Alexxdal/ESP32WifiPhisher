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

#ifndef LIBWIFI_CORE_SECURITY_H
#define LIBWIFI_CORE_SECURITY_H

#include <stdint.h>

/* 802.1X Key Information Field Values */
#define EAPOL_KEY_INFO_M1 0x008A
#define EAPOL_KEY_INFO_M2 0x010A
#define EAPOL_KEY_INFO_M3 0x13CA
#define EAPOL_KEY_INFO_M4 0x030A

/* Sane maximum value for Cipher Suite Count */
#define LIBWIFI_MAX_CIPHER_SUITES 6

/* Cipher Suite OUIs for WPA and RSN */
#define MICROSOFT_OUI "\x00\x50\xF2"
#define CIPHER_SUITE_OUI "\x00\x0F\xAC"

/* Common Microsoft Vendor Types */
#define MICROSOFT_OUI_TYPE_WPA 1
#define MICROSOFT_OUI_TYPE_WMM 2
#define MICROSOFT_OUI_TYPE_WPS 4

/* Cipher Suite Values */
#define CIPHER_SUITE_GROUP 0        /* WPA1/2 */
#define CIPHER_SUITE_WEP40 1        /* WEP */
#define CIPHER_SUITE_TKIP 2         /* WPA1/2 */
#define CIPHER_SUITE_RESERVED 3     /* WPA1/2 */
#define CIPHER_SUITE_CCMP128 4      /* WPA2 */
#define CIPHER_SUITE_WEP104 5       /* WEP */
#define CIPHER_SUITE_BIP_CMAC128 6  /* WPA2 */
#define CIPHER_SUITE_NOTALLOWED 7   /* WPA2 */
#define CIPHER_SUITE_GCMP128 8      /* WPA3 */
#define CIPHER_SUITE_GCMP256 9      /* WPA3 */
#define CIPHER_SUITE_CCMP256 10     /* WPA3 */
#define CIPHER_SUITE_BIP_GMAC128 11 /* WPA3 */
#define CIPHER_SUITE_BIP_GMAC256 12 /* WPA3 */
#define CIPHER_SUITE_BIP_CMAC256 13 /* WPA3 */

/* Auth Key Management Suite Values */
#define AKM_SUITE_RESERVED 0          /* WPA1/2 */
#define AKM_SUITE_1X 1                /* WPA1/2 */
#define AKM_SUITE_PSK 2               /* WPA1/2 */
#define AKM_SUITE_1X_FT 3             /* WPA1/2 */
#define AKM_SUITE_PSK_FT 4            /* WPA2 */
#define AKM_SUITE_1X_SHA256 5         /* WPA2 */
#define AKM_SUITE_PSK_SHA256 6        /* WPA2 */
#define AKM_SUITE_TDLS 7              /* WPA2 */
#define AKM_SUITE_SAE 8               /* WPA3 */
#define AKM_SUITE_SAE_FT 9            /* WPA3 */
#define AKM_SUITE_AP_PEER 10          /* WPA3 */
#define AKM_SUITE_1X_SUITEB_SHA256 11 /* WPA3 */
#define AKM_SUITE_1X_SUITEB_SHA384 12 /* WPA3 */
#define AKM_SUITE_1X_FT_SHA384 13     /* WPA3 */
#define AKM_SUITE_FILS_SHA256 14      /* WPA3 */
#define AKM_SUITE_FILS_SHA384 15      /* WPA3 */
#define AKM_SUITE_FILS_SHA256_FT 16   /* WPA3 */
#define AKM_SUITE_FILS_SHA384_FT 17   /* WPA3 */
#define AKM_SUITE_OWE 18              /* WPA3 */
#define AKM_PSK_SHA384_FT 19          /* WPA3 */
#define AKM_PSK_SHA384 20             /* WPA3 */

/* Authentication Scheme Values */
#define AUTH_OPEN 0
#define AUTH_SHARED_KEY 1
#define AUTH_FAST_BSS 2
#define AUTH_SAE 3
#define AUTH_VENDOR 65535

/* libwifi Security Type Values for libwifi_bss encryption_info */
#define WEP (1ULL << 1)
#define WPA (1ULL << 2)
#define WPA2 (1ULL << 3)
#define WPA3 (1ULL << 4)

/* libwifi Group or Multicast Cipher Values for libwifi_bss encryption_info */
#define LIBWIFI_GROUP_CIPHER_SUITE_WEP40 (1ULL << 5)
#define LIBWIFI_GROUP_CIPHER_SUITE_TKIP (1ULL << 6)
#define LIBWIFI_GROUP_CIPHER_SUITE_RESERVED (1ULL << 7)
#define LIBWIFI_GROUP_CIPHER_SUITE_CCMP128 (1ULL << 8)
#define LIBWIFI_GROUP_CIPHER_SUITE_WEP104 (1ULL << 9)
#define LIBWIFI_GROUP_CIPHER_SUITE_BIP_CMAC128 (1ULL << 10)
#define LIBWIFI_GROUP_CIPHER_SUITE_NOTALLOWED (1ULL << 11)
#define LIBWIFI_GROUP_CIPHER_SUITE_GCMP128 (1ULL << 12)
#define LIBWIFI_GROUP_CIPHER_SUITE_GCMP256 (1ULL << 13)
#define LIBWIFI_GROUP_CIPHER_SUITE_CCMP256 (1ULL << 14)
#define LIBWIFI_GROUP_CIPHER_SUITE_BIP_GMAC128 (1ULL << 15)
#define LIBWIFI_GROUP_CIPHER_SUITE_BIP_GMAC256 (1ULL << 16)
#define LIBWIFI_GROUP_CIPHER_SUITE_BIP_CMAC256 (1ULL << 17)

/* libwifi Pairwise or Unicast Cipher Values for libwifi_bss encryption_info */
#define LIBWIFI_PAIRWISE_SUITE_GROUP (1ULL << 18)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_WEP40 (1ULL << 19)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_TKIP (1ULL << 20)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_RESERVED (1ULL << 21)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP128 (1ULL << 22)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_WEP104 (1ULL << 23)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_CMAC128 (1ULL << 24)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_NOTALLOWED (1ULL << 25)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_GCMP128 (1ULL << 26)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_GCMP256 (1ULL << 27)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP256 (1ULL << 28)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_GMAC128 (1ULL << 29)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_GMAC256 (1ULL << 30)
#define LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_CMAC256 (1ULL << 31)

/* libwifi Auth Key Management Values for libwifi_bss encryption_info */
#define LIBWIFI_AKM_SUITE_RESERVED (1ULL << 32)
#define LIBWIFI_AKM_SUITE_1X (1ULL << 33)
#define LIBWIFI_AKM_SUITE_PSK (1ULL << 34)
#define LIBWIFI_AKM_SUITE_1X_FT (1ULL << 35)
#define LIBWIFI_AKM_SUITE_PSK_FT (1ULL << 36)
#define LIBWIFI_AKM_SUITE_1X_SHA256 (1ULL << 37)
#define LIBWIFI_AKM_SUITE_PSK_SHA256 (1ULL << 39)
#define LIBWIFI_AKM_SUITE_TDLS (1ULL << 40)
#define LIBWIFI_AKM_SUITE_SAE (1ULL << 41)
#define LIBWIFI_AKM_SUITE_SAE_FT (1ULL << 42)
#define LIBWIFI_AKM_SUITE_AP_PEER (1ULL << 43)
#define LIBWIFI_AKM_SUITE_1X_SUITEB_SHA256 (1ULL << 44)
#define LIBWIFI_AKM_SUITE_1X_SUITEB_SHA384 (1ULL << 45)
#define LIBWIFI_AKM_SUITE_1X_FT_SHA384 (1ULL << 46)
#define LIBWIFI_AKM_SUITE_FILS_SHA256 (1ULL << 47)
#define LIBWIFI_AKM_SUITE_FILS_SHA384 (1ULL << 48)
#define LIBWIFI_AKM_SUITE_FILS_SHA256_FT (1ULL << 49)
#define LIBWIFI_AKM_SUITE_FILS_SHA384_FT (1ULL << 50)
#define LIBWIFI_AKM_SUITE_OWE (1ULL << 51)
#define LIBWIFI_AKM_PSK_SHA384_FT (1ULL << 52)
#define LIBWIFI_AKM_PSK_SHA384 (1ULL << 53)

/* libwifi Authentication Scheme Values for libwifi_bss encryption_info */
#define LIBWIFI_AUTH_OPEN (1ULL << 54)
#define LIBWIFI_AUTH_SHARED_KEY (1ULL << 55)
#define LIBWIFI_AUTH_FAST_BSS (1ULL << 56)
#define LIBWIFI_AUTH_SAE (1ULL << 57)
#define LIBWIFI_AUTH_VENDOR (1ULL << 58)

/* libwifi RSN Capability flags */
#define LIBWIFI_RSN_CAPAB_PREAUTH (1 << 0)
#define LIBWIFI_RSN_CAPAB_PAIRWISE (1 << 1)
#define LIBWIFI_RSN_CAPAB_PTKSA_REPLAY (1 << 2 | 1 << 3)
#define LIBWIFI_RSN_CAPAB_GTKSA_REPLAY (1 << 4 | 1 << 5)
#define LIBWIFI_RSN_CAPAB_MFP_REQUIRED (1 << 6)
#define LIBWIFI_RSN_CAPAB_MFP_CAPABLE (1 << 7)
#define LIBWIFI_RSN_CAPAB_JOINT_RSNA (1 << 8)
#define LIBWIFI_RSN_CAPAB_PEERKEY (1 << 9)
#define LIBWIFI_RSN_CAPAB_EXT_KEY_ID (1 << 13)

/**
 * libwifi Representation of a WPA or RSN cipher suite
 * ┌────────────────────────┬────────────┐
 * │           OUI          │ Suite Type │
 * ├────────────────────────┼────────────┤
 * │         3 Bytes        │   1 Byte   │
 * └────────────────────────┴────────────┘
 *
 */
struct libwifi_cipher_suite {
    unsigned char oui[3];
    uint8_t suite_type;
} __attribute__((packed));

/**
 * libwifi Representation of a Microsoft WPA Information Element
 * ┌───────────────────────────────────┐
 * │              Version              │  ── 2 Bytes
 * ├───────────────────────────────────┤
 * │        Multicast Cipher Suite     │  ── 4 Bytes
 * ├───────────────────────────────────┤
 * │     Unicast Cipher Suite Count    │  ── 2 Bytes
 * ├───────────────────────────────────┤
 * │        Unicast Cipher Suites      │  ── 4 to 12 Bytes
 * ├───────────────────────────────────┤
 * │  Auth Key Management Suite Count  │  ── 2 Bytes
 * ├───────────────────────────────────┤
 * │     Auth Key Management Suites    │  ── 4 to 12 Bytes
 * └───────────────────────────────────┘
 */
struct libwifi_wpa_info {
    uint16_t wpa_version;
    struct libwifi_cipher_suite multicast_cipher_suite;
    uint16_t num_unicast_cipher_suites;
    struct libwifi_cipher_suite unicast_cipher_suites[LIBWIFI_MAX_CIPHER_SUITES];
    uint16_t num_auth_key_mgmt_suites;
    struct libwifi_cipher_suite auth_key_mgmt_suites[LIBWIFI_MAX_CIPHER_SUITES];
} __attribute__((packed));

/**
 * libwifi Representation of a 802.11 RSN Information Element
 * ┌───────────────────────────────────┐
 * │              Version              │  ── 2 Bytes
 * ├───────────────────────────────────┤
 * │         Group Cipher Suite        │  ── 4 Bytes
 * ├───────────────────────────────────┤
 * │    Pairwise Cipher Suite Count    │  ── 2 Bytes
 * ├───────────────────────────────────┤
 * │       Pairwise Cipher Suites      │  ── 4 to 12 Bytes
 * ├───────────────────────────────────┤
 * │  Auth Key Management Suite Count  │  ── 2 Bytes
 * ├───────────────────────────────────┤
 * │     Auth Key Management Suites    │  ── 4 to 12 Bytes
 * ├───────────────────────────────────┤
 * │          RSN Capabilities         │  ── 2 Bytes
 * └───────────────────────────────────┘
 */
struct libwifi_rsn_info {
    uint16_t rsn_version;
    struct libwifi_cipher_suite group_cipher_suite;
    int num_pairwise_cipher_suites;
    struct libwifi_cipher_suite pairwise_cipher_suites[LIBWIFI_MAX_CIPHER_SUITES];
    int num_auth_key_mgmt_suites;
    struct libwifi_cipher_suite auth_key_mgmt_suites[LIBWIFI_MAX_CIPHER_SUITES];
    uint16_t rsn_capabilities;
} __attribute__((packed));

/*
 * libwifi Representation of the 802.1X/EAPOL Key Information section
 * ┌───────────────────────────────────┐
 * │           Key Information         │  ── 2 Bytes
 * ├───────────────────────────────────┤
 * │             Key Length            │  ── 2 Bytes
 * ├───────────────────────────────────┤
 * │           Replay Counter          │  ── 8 Bytes
 * ├───────────────────────────────────┤
 * │            WPA Key Nonce          │  ── 32 Bytes
 * ├───────────────────────────────────┤
 * │             WPA Key IV            │  ── 16 Bytes
 * ├───────────────────────────────────┤
 * │             WPA Key RSC           │  ── 8 Bytes
 * ├───────────────────────────────────┤
 * │             WPA Key ID            │  ── 8 Bytes
 * ├───────────────────────────────────┤
 * │             WPA Key MIC           │  ── 16 Bytes
 * ├───────────────────────────────────┤
 * │         WPA Key Data Length       │  ── 4 Bytes
 * ├───────────────────────────────────┤
 * │            WPA Key Data           │  ── Variable
 * └───────────────────────────────────┘
 */
struct libwifi_wpa_key_info {
    uint16_t information;
    uint16_t key_length;
    uint64_t replay_counter;
    unsigned char nonce[32];
    unsigned char iv[16];
    unsigned char rsc[8];
    unsigned char id[8];
    unsigned char mic[16];
    uint16_t key_data_length;
    unsigned char *key_data;
} __attribute__((packed));

/**
 * libwifi Representation of the encapsulating 802.1X data in an EAPOL frame
 * ┌─────────────────┐
 * │      Version    │  ── 1 Byte
 * ├─────────────────┤
 * │       Type      │  ── 1 Byte
 * ├─────────────────┤
 * │      Length     │  ── 2 Bytes
 * ├─────────────────┤
 * │    Descriptor   │  ── 1 Byte
 * ├─────────────────┤
 * │ Key Information │  ── See libwifi_wpa_key_info
 * └─────────────────┘
 */
struct libwifi_wpa_auth_data {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint8_t descriptor;
    struct libwifi_wpa_key_info key_info;
} __attribute__((packed));

#endif /* LIBWIFI_CORE_SECURITY_H */
