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

#ifndef LIBWIFI_PARSE_SECURITY_H
#define LIBWIFI_PARSE_SECURITY_H

#include "../../core/frame/management/common.h"
#include "../../core/misc/security.h"

#include <stdint.h>

#define LIBWIFI_SECURITY_BUF_LEN 256

/**
 * Get the RSN related information and store it in a
 * libwifi_rsn_info. This function will detect and enumerate
 * cipher suites, and AKM suites, and the RSN capabilities
 * from a specified RSN IE.
 *
 * @param info A libwifi_rsn_info
 * @param tag_data An RSN IE tag
 * @param tag_end The end of the specified RSN IE tag
 * @return
 */
int libwifi_get_rsn_info(struct libwifi_rsn_info *info, const unsigned char *tag_data,
                         const unsigned char *tag_end);

/**
 * Enumerate the RSN cipher suites in a libwifi_rsn_info.
 *
 * This function can be used to fill a libwifi_bss struct
 * with information related to the cipher suites and AKM suites
 * in the specified libwifi_rsn_info.
 *
 * @param rsn_info A libwifi_rsn_info
 * @param libwifi_bss A libwifi_bss
 */
void libwifi_enumerate_rsn_suites(struct libwifi_rsn_info *rsn_info, struct libwifi_bss *bss);

/**
 * Get the WPA related information and store it in a
 * libwifi_wpa_info. This function will detect and enumerate
 * cipher suites and AKM suites from a specified WPA IE.
 *
 * @param info A libwifi_wpa_info
 * @param tag_data A WPA IE tag
 * @param tag_end The end of the specified WPA IE tag
 * @return
 */
int libwifi_get_wpa_info(struct libwifi_wpa_info *info, const unsigned char *tag_data,
                         const unsigned char *tag_end);

/**
 * Enumerate the WPA cipher suites in a libwifi_wpa_info.
 *
 * This function can be used to fill a libwifi_bss struct
 * with information related to the cipher suites and AKM suites
 * in the specified libwifi_wpa_info.
 *
 * @param wpa_info A libwifi_wpa_info
 * @param libwifi_bss A libwifi_bss
 */
void libwifi_enumerate_wpa_suites(struct libwifi_wpa_info *wpa_info, struct libwifi_bss *bss);

/**
 * Enumerate the security types (WEP, WPA, WPA2, WPA3, etc) in a given libwifi_bss,
 * formatted into the given buffer.
 *
 * @param bss A libwifi_bss struct
 * @param buf A buffer of length LIBWIFI_SECURITY_BUF_LEN
 */
void libwifi_get_security_type(struct libwifi_bss *bss, char *buf);

/**
 * Enumerate the group ciphers (CCMP, GCMP128, etc) in a given libwifi_bss,
 * formatted into the given buffer.
 *
 * @param bss A libwifi_bss struct
 * @param buf A buffer of length LIBWIFI_SECURITY_BUF_LEN
 */
void libwifi_get_group_ciphers(struct libwifi_bss *bss, char *buf);

/**
 * Enumerate the pairwise ciphers (GROUP, CCMP, BIP_CMAC128, etc) in a given libwifi_bss,
 * formatted into the given buffer.
 *
 * @param bss A libwifi_bss struct
 * @param buf A buffer of length LIBWIFI_SECURITY_BUF_LEN
 */
void libwifi_get_pairwise_ciphers(struct libwifi_bss *bss, char *buf);

/**
 * Enumerate the auth key management suites in a given libwifi_bss,
 * formatted into the given buffer.
 *
 * @param bss A libwifi_bss struct
 * @param buf A buffer of length LIBWIFI_SECURITY_BUF_LEN
 */
void libwifi_get_auth_key_suites(struct libwifi_bss *bss, char *buf);

/**
 * Internal function for adding a formatted string to a buffer for use with
 * libwifi_get_* security functions.
 *
 * @param buf A buffer of length LIBWIFI_SECURITY_BUF_LEN
 * @param offset A pointer to the current buffer offset variable
 * @param append A pointer to the append state variable
 * @param item A pointer to the string to append to the given buf
 */
void _libwifi_add_sec_item(char *buf, int *offset, int *append, char *item);

#endif /* LIBWIFI_PARSE_SECURITY_H */
