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

#ifndef LIBWIFI_PARSE_MGMT_COMMON_H
#define LIBWIFI_PARSE_MGMT_COMMON_H

#include "../../core/frame/management/common.h"
#include "../../core/frame/tag_iterator.h"
#include "../../core/misc/security.h"

/**
 * A helper function to set the SSID of a libwifi_bss, as well as check
 * if it is hidden or not.
 *
 * @param target A libwifi_bss or libwifi_sta
 * @param target_type LIBWIFI_BSS or LIBWIFI_STA
 * @param ssid The SSID to set
 * @param ssid_len The length of the supplied SSID
 */
void libwifi_handle_ssid_tag(void *target, int target_type, const char *ssid, int ssid_len);

/**
 * A helper function to handle the parsing of the RSN IE.
 *
 * @param bss A libwifi_bss
 * @param rsn_data The RSN tag data
 * @param rsn_len The length of the RSN tag data
 */
int libwifi_bss_handle_rsn_tag(struct libwifi_bss *bss, const unsigned char *rsn_data, int rsn_len);

/**
 * A helper function to handle the parsing of the Microsoft Vendor IE.
 *
 * @param bss A libwifi_bss
 * @param msft_data The Microsoft vendor tag data
 * @param msft_len The length of the Microsoft tag data
 */
int libwifi_bss_handle_msft_tag(struct libwifi_bss *bss, const unsigned char *msft_data, int msft_len);

/**
 * A helper function to iterate through common tags found in a libwifi_bss.
 *
 * @param bss A libwifi_bss
 * @param it A libwifi_tag_iterator
 * @return 0 if successful, a negative number if not
 */
int libwifi_bss_tag_parser(struct libwifi_bss *bss, struct libwifi_tag_iterator *it);

/**
 * A helper function to iterate through common tags found in a libwifi_sta.
 *
 * @param sta A libwifi_sta
 * @param it A libwifi_tag_iterator
 * @return 0 if successful, a negative number if not
 */
int libwifi_sta_tag_parser(struct libwifi_sta *sta, struct libwifi_tag_iterator *it);

#endif /* LIBWIFI_PARSE_MGMT_COMMON_H */
