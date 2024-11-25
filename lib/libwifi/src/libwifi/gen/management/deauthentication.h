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

#ifndef LIBWIFI_GEN_DEAUTH_H
#define LIBWIFI_GEN_DEAUTH_H

#include <stdint.h>

#include "../../core/frame/management/deauthentication.h"

/**
 * Calculate the length of a given libwifi_deauth
 *
 * @param deauth A libwifi_deauth
 * @return       The length of the given deauth
 */
size_t libwifi_get_deauth_length(struct libwifi_deauth *deauth);

/**
 * Generate a populated libwifi deauth.
 *
 * A generated libwifi deauth can be "dumped" into a buffer for packet injection
 * via the libwifi_dump_deauth.
 *
 * @param deauth      A libwifi_deauth
 * @param receiver    The receiver MAC address, aka address 1
 * @param transmitter The source MAC address, aka address 2
 * @param address3    The address 3 frame field value, typically the BSSID
 * @param reason_code The deauth reason code
 * @return            Zero on success, or negative error
 */
int libwifi_create_deauth(struct libwifi_deauth *deauth,
                          const unsigned char receiver[6],
                          const unsigned char transmitter[6],
                          const unsigned char address3[6],
                          uint16_t reason_code);

/**
 * Dump a libwifi_deauth into a raw format for packet injection.
 *
 * @param deauth  A libwifi_deauth
 * @param buf     The output buffer for the frame data
 * @param buf_len The length of the output buffer
 * @return        The length of the dumped deauth, or negative error
 */
size_t libwifi_dump_deauth(struct libwifi_deauth *deauth, unsigned char *buf, size_t buf_len);

/**
 * Free any memory claimed by a libwifi_deauth back to the system.
 *
 * @param deauth A libwifi_deauth
 */
void libwifi_free_deauth(struct libwifi_deauth *deauth);

#endif /* LIBWIFI_GEN_DEAUTH_H */
