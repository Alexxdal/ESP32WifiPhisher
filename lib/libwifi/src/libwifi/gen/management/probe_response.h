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

#ifndef LIBWIFI_GEN_PROBERESP_H
#define LIBWIFI_GEN_PROBERESP_H

#include "../../core/frame/management/probe_response.h"

/**
 * Set the SSID of a libwifi_probe_resp.
 *
 * @param probe_resp A libwifi_probe_resp struct
 * @param ssid       The new SSID
 * @return           Zero on success, or negative error
 */
int libwifi_set_probe_resp_ssid(struct libwifi_probe_resp *probe_resp, const char *ssid);

/**
 * Set the channel of a libwifi_probe_resp.
 *
 * @param probe_resp A libwifi_probe_resp struct
 * @param channel    The new channel
 * @return           Zero on success, or negative error
 */
int libwifi_set_probe_resp_channel(struct libwifi_probe_resp *probe_resp, uint8_t channel);

/**
 * Calculate the length of a given libwifi_probe_resp
 *
 * @param probe_resp A libwifi_probe_resp struct
 * @return           The length of the given probe_resp, or negative error
 */
size_t libwifi_get_probe_resp_length(struct libwifi_probe_resp *probe_resp);

/**
 * Generate a populated libwifi probe_resp.
 *
 * A generated libwifi probe_resp can be "dumped" into a buffer for packet injection
 * via the libwifi_dump_probe_resp.
 *
 * @param probe_resp  A libwifi_probe_resp
 * @param receiver    The receiver MAC address, aka address 1
 * @param transmitter The source MAC address, aka address 2
 * @param address3    The address 3 frame field value, typically the BSSID
 * @param ssid        The SSID of the probe_resp. Maximum length is 32 characters
 * @param channel     The desired channel of the probe_resp
 * @return            Zero on success, or negative error
 */
int libwifi_create_probe_resp(struct libwifi_probe_resp *probe_resp,
                              const unsigned char receiver[6],
                              const unsigned char transmitter[6],
                              const unsigned char address3[6],
                              const char *ssid,
                              uint8_t channel);

/**
 * Dump a libwifi_probe_resp into a raw format for packet injection.
 *
 * @param probe_resp A libwifi_probe_resp
 * @param buf        The output buffer for the frame data
 * @param buf_len    The length of the output buffer
 * @return           The length of the dumped probe_resp, or negative error
 */
size_t libwifi_dump_probe_resp(struct libwifi_probe_resp *probe_resp, unsigned char *buf, size_t buf_len);

/**
 * Free any memory claimed by a libwifi_probe_resp back to the system.
 *
 * @param probe_resp A libwifi_probe_resp
 */
void libwifi_free_probe_resp(struct libwifi_probe_resp *probe_resp);

#endif /* LIBWIFI_GEN_PROBERESP_H */
