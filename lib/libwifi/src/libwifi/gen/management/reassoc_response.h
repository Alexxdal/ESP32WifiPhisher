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

#ifndef LIBWIFI_GEN_REASSOCRESP_H
#define LIBWIFI_GEN_REASSOCRESP_H

#include "../../core/frame/management/reassoc_response.h"

/**
 * Set the channel of a libwifi_reassoc_resp.
 *
 * @param reassoc_resp A libwifi_reassoc_resp
 * @param channel      The desired channel
 * @return             Zero on success, or negative error
 */
int libwifi_set_reassoc_resp_channel(struct libwifi_reassoc_resp *reassoc_resp, uint8_t channel);

/**
 * Calculate the length of a given libwifi_reassoc_resp
 *
 * @param reassoc_resp A libwifi_reassoc_resp
 * @return             The length of the given reassoc_resp, or negative error
 */
size_t libwifi_get_reassoc_resp_length(struct libwifi_reassoc_resp *reassoc_resp);

/**
 * Generate a populated libwifi reassoc_resp.
 *
 * A generated libwifi reassoc_resp can be "dumped" into a buffer for packet injection
 * via the libwifi_dump_reassoc_resp.
 *
 * @param reassoc_resp A libwifi_reassoc_resp
 * @param receiver     The receiver MAC address, aka address 1
 * @param transmitter  The source MAC address, aka address 2
 * @param address3     The address 3 frame field value, typically the BSSID
 * @param channel      The desired channel of the reassoc_resp
 * @return             Zero on success, or negative error
 */
int libwifi_create_reassoc_resp(struct libwifi_reassoc_resp *reassoc_resp,
                                const unsigned char receiver[6],
                                const unsigned char transmitter[6],
                                const unsigned char address3[6],
                                uint8_t channel);

/**
 * Dump a libwifi_reassoc_resp into a raw format for packet injection.
 *
 * @param reassoc_resp A libwifi_reassoc_resp
 * @param buf The output buffer for the frame data
 * @param buf_len The length of the output buffer
 * @return The length of the dumped reassoc_resp, or negative error
 */
size_t libwifi_dump_reassoc_resp(struct libwifi_reassoc_resp *reassoc_resp, unsigned char *buf,
                                 size_t buf_len);

/**
 * Free any memory claimed by a libwifi_reassoc_resp back to the system.
 *
 * @param reassoc_resp A libwifi_reassoc_resp struct
 */
void libwifi_free_reassoc_resp(struct libwifi_reassoc_resp *reassoc_resp);

#endif /* LIBWIFI_GEN_REASSOCRESP_H */
