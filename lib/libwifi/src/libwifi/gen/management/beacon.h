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

#ifndef LIBWIFI_GEN_BEACON_H
#define LIBWIFI_GEN_BEACON_H

#include "../../core/frame/management/beacon.h"

/**
 * Set the SSID of a struct libwifi_beacon.
 *
 * @param beacon A struct libwifi_beacon
 * @param ssid   The new SSID
 * @return       Zero on success, or negative error
 */
int libwifi_set_beacon_ssid(struct libwifi_beacon *beacon, const char *ssid);

/**
 * Set the channel of a struct libwifi_beacon.
 *
 * @param beacon  A struct libwifi_beacon
 * @param channel The new channel
 * @return        Zero on success, or negative error
 */
int libwifi_set_beacon_channel(struct libwifi_beacon *beacon, uint8_t channel);

/**
 * Calculate the length of a given struct libwifi_beacon
 *
 * @param beacon A libwifi_beacon struct
 * @return       The length of the given beacon, or negative error
 */
size_t libwifi_get_beacon_length(struct libwifi_beacon *beacon);

/**
 * Generate a populated libwifi beacon.
 *
 * A generated libwifi beacon can be "dumped" into a buffer for packet injection
 * via the libwifi_dump_beacon.
 *
 * @param beacon      A struct libwifi_beacon
 * @param receiver    The receiver MAC address, aka address 1
 * @param transmitter The source MAC address, aka address 2
 * @param address3    The address 3 frame field value, typically the BSSID
 * @param ssid        The SSID of the beacon. Maximum length is 32 characters
 * @param channel     The desired channel of the beacon
 * @return            Zero on success, or negative error
 */
int libwifi_create_beacon(struct libwifi_beacon *beacon,
                          const unsigned char receiver[6],
                          const unsigned char transmitter[6],
                          const unsigned char address3[6],
                          const char *ssid,
                          uint8_t channel);

/**
 * Dump a struct libwifi_beacon into a raw format for packet injection.
 *
 * @param beacon  A struct libwifi_beacon
 * @param buf     The output buffer for the frame data
 * @param buf_len The length of the output buffer
 * @return        The length of the dumped beacon, or negative error
 */
size_t libwifi_dump_beacon(struct libwifi_beacon *beacon, unsigned char *buf, size_t buf_len);

/**
 * Free any memory claimed by a struct libwifi_beacon back to the system.
 *
 * @param beacon A struct libwifi_beacon
 */
void libwifi_free_beacon(struct libwifi_beacon *beacon);

#endif /* LIBWIFI_GEN_BEACON_H */
