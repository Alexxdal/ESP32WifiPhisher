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

#include "security.h"
#include "../../core/misc/byteswap.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * RSN Information is supplied via the raw tag data. The supplied data is then "walked"
 * through as a pointer to extract the details of the tag and write them into
 * a struct libwifi_rsn_info.
 *
 * libwifi supports a maximum of 3 Pairwise Cipher Suites and 3 Auth Key Management Suites.
 * The Version, Group Cipher Suite and Capabilities fields are all required.
 */
int libwifi_get_rsn_info(struct libwifi_rsn_info *info, const unsigned char *tag_data,
                         const unsigned char *tag_end) {
    memset(info, 0, sizeof(struct libwifi_rsn_info));

    // Create a pointer we can manipulate from the tag data
    unsigned char *data = (unsigned char *) tag_data;

    // Handle the RSN Version
    memcpy(&info->rsn_version, data, sizeof(info->rsn_version));
    data += sizeof(info->rsn_version);

    // Handle the RSN Group Cipher Suites
    memcpy(&info->group_cipher_suite, data, sizeof(struct libwifi_cipher_suite));
    data += sizeof(struct libwifi_cipher_suite);

    // Bounds check and handle the RSN Pairwise Ciphers
    if (data > tag_end) {
        return -EINVAL;
    }
    if ((data + sizeof(uint16_t)) > tag_end) {
        return -EINVAL;
    }
    uint16_t suite_count = *data;
    if (suite_count > LIBWIFI_MAX_CIPHER_SUITES) {
        suite_count = LIBWIFI_MAX_CIPHER_SUITES;
    }
    data += sizeof(suite_count);
    if ((((suite_count * sizeof(struct libwifi_cipher_suite)) + data)) > tag_end) {
        return -EINVAL;
    }
    info->num_pairwise_cipher_suites = suite_count;

    // Iterate through the found Pairwise Ciphers, adding them each time
    struct libwifi_cipher_suite *cur_cipher_suite = NULL;
    for (int i = 0; i < suite_count; ++i) {
        if (data > tag_end) {
            return -EINVAL;
        }
        cur_cipher_suite = (struct libwifi_cipher_suite *) data;
        memcpy(&info->pairwise_cipher_suites[i], cur_cipher_suite, sizeof(struct libwifi_cipher_suite));
        data += sizeof(struct libwifi_cipher_suite);
    }

    // Bounds check and handle the RSN Authentication Key Management Suites
    if ((data + sizeof(suite_count)) > tag_end) {
        return -EINVAL;
    }
    suite_count = *data;
    if (suite_count > LIBWIFI_MAX_CIPHER_SUITES) {
        suite_count = LIBWIFI_MAX_CIPHER_SUITES;
    }
    data += sizeof(suite_count);
    if ((((suite_count * sizeof(struct libwifi_cipher_suite)) + data)) > tag_end) {
        return -EINVAL;
    }
    info->num_auth_key_mgmt_suites = suite_count;

    // Iterate through the found Auth Key Management Suites, adding them each time
    for (int i = 0; i < suite_count; ++i) {
        if (data > tag_end) {
            return -EINVAL;
        }
        cur_cipher_suite = (struct libwifi_cipher_suite *) data;
        memcpy(&info->auth_key_mgmt_suites[i], cur_cipher_suite, sizeof(struct libwifi_cipher_suite));
        data += sizeof(struct libwifi_cipher_suite);
    }

    // Bounds check and handle the RSN Capabilities field
    if (data > tag_end) {
        return -EINVAL;
    }
    memcpy(&info->rsn_capabilities, data, sizeof(info->rsn_capabilities));

    return 0;
}

/**
 * This function will enumerate over a supplied struct libwifi_rsn_info and write
 * the following into a supplied struct libwifi_bss:
 *
 * - Group Cipher Suite
 * - Up to 3 Pairwise Cipher Suites
 * - Up to 3 Auth Key Management Suites
 * - The WPA Type (WPA2 or WPA3)
 *
 * The bss->encryption_info field is a 64-bit wide bitmask. The larger length is
 * required to accomodate the different types of cipher suites without having
 * any overlap between group cipher and pairwise cipher.
 */
void libwifi_enumerate_rsn_suites(struct libwifi_rsn_info *rsn_info, struct libwifi_bss *bss) {
    switch (rsn_info->group_cipher_suite.suite_type) {
        case CIPHER_SUITE_WEP40:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_WEP40;
            break;
        case CIPHER_SUITE_TKIP:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_TKIP;
            break;
        case CIPHER_SUITE_RESERVED:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_RESERVED;
            break;
        case CIPHER_SUITE_CCMP128:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_CCMP128;
            break;
        case CIPHER_SUITE_WEP104:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_WEP104;
            break;
        case CIPHER_SUITE_BIP_CMAC128:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_BIP_CMAC128;
            break;
        case CIPHER_SUITE_NOTALLOWED:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_NOTALLOWED;
            break;
        case CIPHER_SUITE_GCMP128:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_GCMP128;
            break;
        case CIPHER_SUITE_GCMP256:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_GCMP256;
            break;
        case CIPHER_SUITE_CCMP256:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_CCMP256;
            break;
        case CIPHER_SUITE_BIP_GMAC128:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_BIP_GMAC128;
            break;
        case CIPHER_SUITE_BIP_GMAC256:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_BIP_GMAC256;
            break;
        case CIPHER_SUITE_BIP_CMAC256:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_BIP_CMAC256;
            break;
        default:
            break;
    }

    for (int i = 0; i < rsn_info->num_pairwise_cipher_suites; ++i) {
        if ((memcmp(rsn_info->pairwise_cipher_suites[i].oui, CIPHER_SUITE_OUI, 3) == 0)) {
            switch (rsn_info->pairwise_cipher_suites[i].suite_type) {
                case CIPHER_SUITE_GROUP:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_SUITE_GROUP;
                    break;
                case CIPHER_SUITE_TKIP:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_TKIP;
                    break;
                case CIPHER_SUITE_RESERVED:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_RESERVED;
                    break;
                case CIPHER_SUITE_CCMP128:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP128;
                    break;
                case CIPHER_SUITE_BIP_CMAC128:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_CMAC128;
                    break;
                case CIPHER_SUITE_NOTALLOWED:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_NOTALLOWED;
                    break;
                case CIPHER_SUITE_GCMP128:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_GCMP128;
                    break;
                case CIPHER_SUITE_GCMP256:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_GCMP256;
                    break;
                case CIPHER_SUITE_CCMP256:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP256;
                    break;
                case CIPHER_SUITE_BIP_GMAC128:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_GMAC128;
                    break;
                case CIPHER_SUITE_BIP_GMAC256:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_GMAC256;
                    break;
                case CIPHER_SUITE_BIP_CMAC256:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_CMAC256;
                    break;
                default:
                    break;
            }
        }
    }

    for (int i = 0; i < rsn_info->num_auth_key_mgmt_suites; ++i) {
        if (memcmp(rsn_info->auth_key_mgmt_suites[i].oui, CIPHER_SUITE_OUI, 3) == 0) {
            switch (rsn_info->auth_key_mgmt_suites[i].suite_type) {
                case AKM_SUITE_RESERVED:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_RESERVED;
                    break;
                case AKM_SUITE_1X:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_1X;
                    break;
                case AKM_SUITE_PSK:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_PSK;
                    break;
                case AKM_SUITE_1X_FT:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_1X_FT;
                    break;
                case AKM_SUITE_PSK_FT:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_PSK_FT;
                    break;
                case AKM_SUITE_1X_SHA256:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_1X_SHA256;
                    break;
                case AKM_SUITE_PSK_SHA256:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_PSK_SHA256;
                    break;
                case AKM_SUITE_TDLS:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_TDLS;
                    break;
                case AKM_SUITE_SAE:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_SAE;
                    break;
                case AKM_SUITE_SAE_FT:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_SAE_FT;
                    break;
                case AKM_SUITE_AP_PEER:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_AP_PEER;
                    break;
                case AKM_SUITE_1X_SUITEB_SHA256:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_1X_SUITEB_SHA256;
                    break;
                case AKM_SUITE_1X_SUITEB_SHA384:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_1X_SUITEB_SHA384;
                    break;
                case AKM_SUITE_1X_FT_SHA384:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_1X_FT_SHA384;
                    break;
                case AKM_SUITE_FILS_SHA256:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_FILS_SHA256;
                    break;
                case AKM_SUITE_FILS_SHA384:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_FILS_SHA384;
                    break;
                case AKM_SUITE_FILS_SHA256_FT:
                    bss->encryption_info |= WPA2;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_FILS_SHA256_FT;
                    break;
                case AKM_SUITE_FILS_SHA384_FT:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_FILS_SHA384_FT;
                    break;
                case AKM_SUITE_OWE:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_OWE;
                    break;
                case AKM_PSK_SHA384_FT:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_PSK_SHA384_FT;
                    break;
                case AKM_PSK_SHA384:
                    bss->encryption_info |= WPA3;
                    bss->encryption_info |= LIBWIFI_AKM_PSK_SHA384;
                    break;
                default:
                    break;
            }
        }
    }
}

/**
 * Similar to libwifi_get_rsn_info, WPA Information is supplied via the raw tag data.
 * The supplied data is then "walked" through as a pointer to extract the details of
 * the tag and write them into a struct libwifi_wpa_info.
 *
 * libwifi supports a maximum of 3 Unicast Cipher Suites and 3 Auth Key Management Suites.
 * The Version and Multicast Cipher Suite fields are required.
 */
int libwifi_get_wpa_info(struct libwifi_wpa_info *info, const unsigned char *tag_data,
                         const unsigned char *tag_end) {
    memset(info, 0, sizeof(struct libwifi_wpa_info));

    // Create a pointer we can manipulate from the tag data
    unsigned char *data = ((unsigned char *) tag_data);

    // Handle the WPA Version
    memcpy(&info->wpa_version, data, sizeof(info->wpa_version));
    data += sizeof(info->wpa_version);

    // Handle the WPA Multicast Cipher Suite
    memcpy(&info->multicast_cipher_suite, data, sizeof(struct libwifi_cipher_suite));
    data += sizeof(struct libwifi_cipher_suite);

    // Bounds check and handle the WPA Unicast Cipher Suites
    if (data > tag_end) {
        return -EINVAL;
    }
    if ((data + sizeof(uint16_t)) > tag_end) {
        return -EINVAL;
    }
    uint16_t suite_count = *data;
    if (suite_count > LIBWIFI_MAX_CIPHER_SUITES) {
        suite_count = LIBWIFI_MAX_CIPHER_SUITES;
    }
    data += sizeof(suite_count);
    if ((((suite_count * sizeof(struct libwifi_cipher_suite)) + data)) > tag_end) {
        return -EINVAL;
    }
    info->num_unicast_cipher_suites = suite_count;

    // Iterate through the found Unicast Ciphers, adding them each time
    struct libwifi_cipher_suite *cur_cipher_suite = NULL;
    for (int i = 0; i < suite_count; ++i) {
        if (data > tag_end) {
            return -EINVAL;
        }
        cur_cipher_suite = (struct libwifi_cipher_suite *) data;
        memcpy(&info->unicast_cipher_suites[i], cur_cipher_suite, sizeof(struct libwifi_cipher_suite));
        data += sizeof(struct libwifi_cipher_suite);
    }

    // Bounds check and handle the WPA Authentication Key Management Suites
    if ((data + sizeof(suite_count)) > tag_end) {
        return -EINVAL;
    }
    suite_count = *data;
    if (suite_count > LIBWIFI_MAX_CIPHER_SUITES) {
        suite_count = LIBWIFI_MAX_CIPHER_SUITES;
    }
    data += sizeof(suite_count);
    if ((((suite_count * sizeof(struct libwifi_cipher_suite)) + data)) > tag_end) {
        return -EINVAL;
    }
    info->num_auth_key_mgmt_suites = suite_count;

    // Iterate through the found Auth Key Management Suites, adding them each time
    for (int i = 0; i < suite_count; ++i) {
        if (data > tag_end) {
            return -EINVAL;
        }
        cur_cipher_suite = (struct libwifi_cipher_suite *) data;
        memcpy(&info->auth_key_mgmt_suites[i], cur_cipher_suite, sizeof(struct libwifi_cipher_suite));
        data += sizeof(struct libwifi_cipher_suite);
    }

    return 0;
}

/**
 * Similarly to libwifi_enumerate_wpa_suites, this function will enumerate over a supplied
 * struct libwifi_wpa_info and write the following into a supplied struct libwifi_bss:
 *
 * - Multicast Cipher Suite
 * - Up to 3 Unicast Cipher Suites
 * - Up to 3 Auth Key Management Suites
 *
 * The bss->encryption_info field is a 64-bit wide bitmask. The larger length is
 * required to accomodate the different types of cipher suites without having
 * any overlap between group cipher and pairwise cipher.
 */
void libwifi_enumerate_wpa_suites(struct libwifi_wpa_info *wpa_info, struct libwifi_bss *bss) {
    switch (wpa_info->multicast_cipher_suite.suite_type) {
        case CIPHER_SUITE_WEP40:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_WEP40;
            break;
        case CIPHER_SUITE_WEP104:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_WEP104;
            break;
        case CIPHER_SUITE_TKIP:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_TKIP;
            break;
        case CIPHER_SUITE_RESERVED:
            bss->encryption_info |= LIBWIFI_GROUP_CIPHER_SUITE_RESERVED;
            break;
        default:
            break;
    }

    for (int i = 0; i < wpa_info->num_unicast_cipher_suites; ++i) {
        if ((memcmp(wpa_info->unicast_cipher_suites[i].oui, MICROSOFT_OUI, 3) == 0)) {
            switch (wpa_info->unicast_cipher_suites[i].suite_type) {
                case CIPHER_SUITE_GROUP:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_SUITE_GROUP;
                    break;
                case CIPHER_SUITE_TKIP:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_TKIP;
                    break;
                case CIPHER_SUITE_RESERVED:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_RESERVED;
                    break;
                case CIPHER_SUITE_WEP40:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_WEP40;
                    break;
                case CIPHER_SUITE_WEP104:
                    bss->encryption_info |= LIBWIFI_PAIRWISE_CIPHER_SUITE_WEP104;
                    break;
                default:
                    break;
            }
        }
    }

    for (int i = 0; i < wpa_info->num_auth_key_mgmt_suites; ++i) {
        if (memcmp(wpa_info->auth_key_mgmt_suites[i].oui, MICROSOFT_OUI, 3) == 0) {
            switch (wpa_info->auth_key_mgmt_suites[i].suite_type) {
                case AKM_SUITE_RESERVED:
                    bss->encryption_info |= WPA;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_RESERVED;
                    break;
                case AKM_SUITE_1X:
                    bss->encryption_info |= WPA;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_1X;
                    break;
                case AKM_SUITE_PSK:
                    bss->encryption_info |= WPA;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_PSK;
                    break;
                case AKM_SUITE_1X_FT:
                    bss->encryption_info |= WPA;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_1X_FT;
                    break;
                case AKM_SUITE_PSK_FT:
                    bss->encryption_info |= WPA;
                    bss->encryption_info |= LIBWIFI_AKM_SUITE_PSK_FT;
                    break;
            }
        }
    }
}

void libwifi_get_security_type(struct libwifi_bss *bss, char *buf) {
    memset(buf, 0, LIBWIFI_SECURITY_BUF_LEN);

    int offset = 0;
    int append = 0;

    if (bss->encryption_info == 0) {
        snprintf(buf, LIBWIFI_SECURITY_BUF_LEN, "None");
        return;
    }

    if (bss->encryption_info & WPA3) {
        _libwifi_add_sec_item(buf, &offset, &append, "WPA3");
    }
    if (bss->encryption_info & WPA2) {
        _libwifi_add_sec_item(buf, &offset, &append, "WPA2");
    }
    if (bss->encryption_info & WPA) {
        _libwifi_add_sec_item(buf, &offset, &append, "WPA");
    }
    if (bss->encryption_info & WEP) {
        _libwifi_add_sec_item(buf, &offset, &append, "WEP");
    }
}

void libwifi_get_group_ciphers(struct libwifi_bss *bss, char *buf) {
    memset(buf, 0, LIBWIFI_SECURITY_BUF_LEN);

    int offset = 0;
    int append = 0;

    if (bss->encryption_info == 0) {
        snprintf(buf + offset, LIBWIFI_SECURITY_BUF_LEN, "None");
        return;
    }

    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_WEP40) {
        _libwifi_add_sec_item(buf, &offset, &append, "WEP40");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_TKIP) {
        _libwifi_add_sec_item(buf, &offset, &append, "TKIP");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_RESERVED) {
        _libwifi_add_sec_item(buf, &offset, &append, "RESERVED");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_CCMP128) {
        _libwifi_add_sec_item(buf, &offset, &append, "CCMP128");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_WEP104) {
        _libwifi_add_sec_item(buf, &offset, &append, "WEP104");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_BIP_CMAC128) {
        _libwifi_add_sec_item(buf, &offset, &append, "BIP_CMAC128");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_NOTALLOWED) {
        _libwifi_add_sec_item(buf, &offset, &append, "NOT_ALLOWED");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_GCMP128) {
        _libwifi_add_sec_item(buf, &offset, &append, "GCMP128");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_GCMP256) {
        _libwifi_add_sec_item(buf, &offset, &append, "GCMP256");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_CCMP256) {
        _libwifi_add_sec_item(buf, &offset, &append, "CCMP256");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_BIP_GMAC128) {
        _libwifi_add_sec_item(buf, &offset, &append, "BIP_GMAC128");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_BIP_GMAC256) {
        _libwifi_add_sec_item(buf, &offset, &append, "BIP_GMAC256");
    }
    if (bss->encryption_info & LIBWIFI_GROUP_CIPHER_SUITE_BIP_CMAC256) {
        _libwifi_add_sec_item(buf, &offset, &append, "BIP_CMAC256");
    }
}

void libwifi_get_pairwise_ciphers(struct libwifi_bss *bss, char *buf) {
    memset(buf, 0, LIBWIFI_SECURITY_BUF_LEN);

    int offset = 0;
    int append = 0;

    if (bss->encryption_info == 0) {
        snprintf(buf + offset, LIBWIFI_SECURITY_BUF_LEN, "None");
        return;
    }

    if (bss->encryption_info & LIBWIFI_PAIRWISE_SUITE_GROUP) {
        _libwifi_add_sec_item(buf, &offset, &append, "GROUP");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_WEP40) {
        _libwifi_add_sec_item(buf, &offset, &append, "WEP40");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_TKIP) {
        _libwifi_add_sec_item(buf, &offset, &append, "TKIP");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_RESERVED) {
        _libwifi_add_sec_item(buf, &offset, &append, "RESERVED");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP128) {
        _libwifi_add_sec_item(buf, &offset, &append, "CCMP128");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_WEP104) {
        _libwifi_add_sec_item(buf, &offset, &append, "WEP104");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_CMAC128) {
        _libwifi_add_sec_item(buf, &offset, &append, "BIP_CMAC128");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_NOTALLOWED) {
        _libwifi_add_sec_item(buf, &offset, &append, "NOT_ALLOWED");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_GCMP128) {
        _libwifi_add_sec_item(buf, &offset, &append, "GCMP128");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_GCMP256) {
        _libwifi_add_sec_item(buf, &offset, &append, "GCMP256");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP256) {
        _libwifi_add_sec_item(buf, &offset, &append, "CCMP256");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_GMAC128) {
        _libwifi_add_sec_item(buf, &offset, &append, "BIP_GMAC128");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_GMAC256) {
        _libwifi_add_sec_item(buf, &offset, &append, "BIP_GMAC256");
    }
    if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_BIP_CMAC256) {
        _libwifi_add_sec_item(buf, &offset, &append, "BIP_CMAC256");
    }
}

void libwifi_get_auth_key_suites(struct libwifi_bss *bss, char *buf) {
    memset(buf, 0, LIBWIFI_SECURITY_BUF_LEN);

    int offset = 0;
    int append = 0;

    if (bss->encryption_info == 0) {
        snprintf(buf + offset, LIBWIFI_SECURITY_BUF_LEN, "None");
        return;
    }

    if (bss->encryption_info & LIBWIFI_AKM_SUITE_RESERVED) {
        _libwifi_add_sec_item(buf, &offset, &append, "RESERVED");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_1X) {
        _libwifi_add_sec_item(buf, &offset, &append, "802.1X");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_PSK) {
        _libwifi_add_sec_item(buf, &offset, &append, "PSK");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_1X_FT) {
        _libwifi_add_sec_item(buf, &offset, &append, "802.1X_FT");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_PSK_FT) {
        _libwifi_add_sec_item(buf, &offset, &append, "PSK_FT");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_1X_SHA256) {
        _libwifi_add_sec_item(buf, &offset, &append, "802.1X_SHA256");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_PSK_SHA256) {
        _libwifi_add_sec_item(buf, &offset, &append, "PSK_SHA256");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_TDLS) {
        _libwifi_add_sec_item(buf, &offset, &append, "TDLS");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_SAE) {
        _libwifi_add_sec_item(buf, &offset, &append, "SAE");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_SAE_FT) {
        _libwifi_add_sec_item(buf, &offset, &append, "SAE_FT");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_AP_PEER) {
        _libwifi_add_sec_item(buf, &offset, &append, "AP_PEER");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_1X_SUITEB_SHA256) {
        _libwifi_add_sec_item(buf, &offset, &append, "802.1X_SUITEB_SHA256");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_1X_SUITEB_SHA384) {
        _libwifi_add_sec_item(buf, &offset, &append, "802.1X_SUITEB_SHA384");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_1X_FT_SHA384) {
        _libwifi_add_sec_item(buf, &offset, &append, "802.1X_FT_SHA384");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_FILS_SHA256) {
        _libwifi_add_sec_item(buf, &offset, &append, "FILS_SHA256");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_FILS_SHA384) {
        _libwifi_add_sec_item(buf, &offset, &append, "FILS_SHA384");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_FILS_SHA256_FT) {
        _libwifi_add_sec_item(buf, &offset, &append, "FILS_SHA256_FT");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_FILS_SHA384_FT) {
        _libwifi_add_sec_item(buf, &offset, &append, "FILS_SHA384_FT");
    }
    if (bss->encryption_info & LIBWIFI_AKM_SUITE_OWE) {
        _libwifi_add_sec_item(buf, &offset, &append, "OWE");
    }
    if (bss->encryption_info & LIBWIFI_AKM_PSK_SHA384_FT) {
        _libwifi_add_sec_item(buf, &offset, &append, "PSK_SHA384_FT");
    }
    if (bss->encryption_info & LIBWIFI_AKM_PSK_SHA384) {
        _libwifi_add_sec_item(buf, &offset, &append, "PSK_SHA384");
    }
}

void _libwifi_add_sec_item(char *buf, int *offset, int *append, char *item) {
    if (*append) {
        snprintf(buf + *offset, LIBWIFI_SECURITY_BUF_LEN, ", ");
        *offset += strlen(", ");
    }
    snprintf(buf + *offset, LIBWIFI_SECURITY_BUF_LEN, "%s", item);
    *offset += strlen(item);
    *append = 1;
}
