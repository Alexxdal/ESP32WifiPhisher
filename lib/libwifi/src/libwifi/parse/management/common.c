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

#include "common.h"
#include "../../core/frame/tag.h"
#include "../misc/security.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * Different implementations can have variations of hidden SSIDs.
 * It is common to simply set the SSID to an empty string, but some
 * devices may "blank" the real SSID without reducing the character count.
 *
 * Example: "My-SSID" -> "\x00\x00\x00\x00\x00\x00\x00"
 */
void libwifi_handle_ssid_tag(void *target, int target_type, const char *tag_data, int tag_len) {
    int hidden = 0;
    int null_ssid = 1;

    if (tag_len <= 0) {
        hidden = 1;
    } else if (tag_len > 32) {
        tag_len = 32;
    }

    for (int i = 0; i < tag_len; i++) {
        if (memcmp(&tag_data[i], "\x00", 1) != 0) {
            null_ssid = 0;
            break;
        }
    }

    if (null_ssid) {
        hidden = 1;
    }

    if (target_type == LIBWIFI_BSS) {
        struct libwifi_bss *bss = (struct libwifi_bss *) target;
        memcpy(bss->ssid, tag_data, tag_len);
        bss->hidden = hidden;
    } else if (target_type == LIBWIFI_STA) {
        struct libwifi_sta *sta = (struct libwifi_sta *) target;
        memcpy(sta->ssid, tag_data, tag_len);
    }
}

/**
 * Handle the RSN Tagged Parameter.
 *
 * At the minimum, the required RSN data is the version and the group cipher suites.
 * RSN information is then enumerated within the libwifi_get_rsn_info() function.
 */
int libwifi_bss_handle_rsn_tag(struct libwifi_bss *bss, const unsigned char *rsn_data, int rsn_len) {
    struct libwifi_rsn_info rsn_info = {0};

    if (bss->encryption_info & WEP) {
        bss->encryption_info &= ~(unsigned int) WEP;
    }

    int min_len = sizeof(rsn_info.rsn_version) + sizeof(struct libwifi_cipher_suite);
    if (rsn_len < min_len) {
        return -EINVAL;
    }

    const unsigned char *rsn_end = rsn_data + rsn_len;

    if ((libwifi_get_rsn_info(&rsn_info, rsn_data, rsn_end) != 0)) {
        return -EINVAL;
    }

    libwifi_enumerate_rsn_suites(&rsn_info, bss);

    memcpy(&bss->rsn_info, &rsn_info, sizeof(struct libwifi_rsn_info));

    return 0;
}

/**
 * The Microsoft vendor tag is used to advertise WPA and WPS information, as well as
 * some other features such as WMM/WME.
 *
 * The difference between the tags is found via the "Vendor Specific OUI Type" field.
 * A common representation of this is XX:XX:XX:YY, such as 00:50:F2:04, where
 * 00:50:F2 is the Microsoft OUI and 04 is the type.
 *
 * It is important to skip the OUI and Type as described above before parsing the data of
 * the tag. This is encapsulated with the libwifi_tag_vendor_header struct.
 */
int libwifi_bss_handle_msft_tag(struct libwifi_bss *bss, const unsigned char *msft_data, int msft_len) {
    struct libwifi_wpa_info wpa_info = {0};
    struct libwifi_tag_vendor_header *vendor_header = (struct libwifi_tag_vendor_header *) msft_data;

    switch (vendor_header->type) {
        case MICROSOFT_OUI_TYPE_WPA:
            if (bss->encryption_info & WEP) {
                bss->encryption_info &= ~(unsigned int) WEP;
            }
            bss->encryption_info |= WPA;

            // Skip 4 bytes for the OUI (3) and Vendor Tag Type (1)
            const unsigned char *wpa_data = msft_data + sizeof(struct libwifi_tag_vendor_header);
            const unsigned char *wpa_end = msft_data + (msft_len + sizeof(struct libwifi_tag_vendor_header));

            if ((libwifi_get_wpa_info(&wpa_info, wpa_data, wpa_end) != 0)) {
                return -EINVAL;
            }

            libwifi_enumerate_wpa_suites(&wpa_info, bss);

            memcpy(&bss->wpa_info, &wpa_info, sizeof(struct libwifi_wpa_info));
            break;
        case MICROSOFT_OUI_TYPE_WMM:
            // WMM/WME Supported
            break;
        case MICROSOFT_OUI_TYPE_WPS:
            bss->wps = 1;
            break;
    }

    return 0;
}

/**
 * This function is a parser for common and useful tags found in frames usually originating
 * from the BSS. These include the SSID and DS or HT fields, which can be used to determine
 * the channel.
 */
int libwifi_bss_tag_parser(struct libwifi_bss *bss, struct libwifi_tag_iterator *it) {
    struct libwifi_tag_vendor_header *vendor_header = NULL;
    struct libwifi_tag_extension_header *extension_header = NULL;

    do {
        switch (it->tag_header->tag_num) {
            case TAG_SSID:
                libwifi_handle_ssid_tag((void *) bss, LIBWIFI_BSS, (const char *) it->tag_data,
                                        it->tag_header->tag_len);
                break;
            case TAG_DS_PARAMETER:
            case TAG_HT_OPERATION:
                memcpy(&bss->channel, it->tag_data, 1);
                break;
            case TAG_RSN:
                if ((libwifi_bss_handle_rsn_tag(bss, it->tag_data, it->tag_header->tag_len) != 0)) {
                    return -EINVAL;
                };
                break;
            case TAG_VENDOR_SPECIFIC:
                vendor_header = (struct libwifi_tag_vendor_header *) it->tag_data;

                if (memcmp(vendor_header->oui, MICROSOFT_OUI, 3) == 0) {
                    if ((libwifi_bss_handle_msft_tag(bss, it->tag_data, it->tag_header->tag_len) != 0)) {
                        return -EINVAL;
                    }
                }
                break;
            case TAG_ELEMENT_EXTENSION:
                extension_header = (struct libwifi_tag_extension_header *) it->tag_data;

                switch (extension_header->tag_num) {
                    default:
                        /* Not Implemented */
                        break;
                }

                break;
        }
    } while (libwifi_tag_iterator_next(it) != -1);

    return 0;
}

/**
 * This function is a parser for common and useful tags found in frames usually originating
 * from the STA. These include the SSID and DS or HT fields, which can be used to determine
 * the channel.
 */
int libwifi_sta_tag_parser(struct libwifi_sta *sta, struct libwifi_tag_iterator *it) {
    do {
        switch (it->tag_header->tag_num) {
            case TAG_SSID:
                libwifi_handle_ssid_tag(sta, LIBWIFI_STA, (const char *) it->tag_data,
                                        it->tag_header->tag_len);
                break;
            case TAG_DS_PARAMETER:
                memcpy(&sta->channel, it->tag_data, 1);
                break;
        }
    } while (libwifi_tag_iterator_next(it) != -1);

    return 0;
}
