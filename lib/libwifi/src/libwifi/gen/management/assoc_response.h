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

#ifndef LIBWIFI_GEN_ASSOCRESP_H
#define LIBWIFI_GEN_ASSOCRESP_H

#include "../../core/frame/management/assoc_response.h"

/**
 * Set the channel of a libwifi_assoc_resp.
 *
 * @param assoc_resp A libwifi_assoc_resp
 * @param channel    The new channel
 * @return           Zero on success, or negative error
 */
int libwifi_set_assoc_resp_channel(struct libwifi_assoc_resp *assoc_resp, uint8_t channel);

/**
 * Calculate the length of a given libwifi_assoc_resp
 *
 * @param assoc_resp A libwifi_assoc_resp
 * @return           The length of the given assoc_resp, or negative error
 */
size_t libwifi_get_assoc_resp_length(struct libwifi_assoc_resp *assoc_resp);

/**
 * Generate a populated libwifi assoc_resp.
 *
 * A generated libwifi assoc_resp can be "dumped" into a buffer for packet injection
 * via the libwifi_dump_assoc_resp.
 *
 * @param assoc_resp  A libwifi_assoc_resp
 * @param receiver    The receiver MAC address, aka address 1
 * @param transmitter The source MAC address, aka address 2
 * @param address3    The address 3 frame field value, typically the BSSID
 * @param channel     The desired channel of the assoc_resp
 * @return            Zero on success, or negative error
 */
int libwifi_create_assoc_resp(struct libwifi_assoc_resp *assoc_resp,
                              const unsigned char receiver[6],
                              const unsigned char transmitter[6],
                              const unsigned char address3[6],
                              uint8_t channel);

/**
 * Dump a libwifi_assoc_resp into a raw format for packet injection.
 *
 * @param assoc_resp A libwifi_assoc_resp
 * @param buf        The output buffer for the frame data
 * @param buf_len    The length of the output buffer
 * @return           The length of the dumped assoc_resp, or negative error
 */
size_t libwifi_dump_assoc_resp(struct libwifi_assoc_resp *assoc_resp, unsigned char *buf, size_t buf_len);

/**
 * Free any memory claimed by a libwifi_assoc_resp back to the system.
 *
 * @param assoc_resp A libwifi_assoc_resp
 */
void libwifi_free_assoc_resp(struct libwifi_assoc_resp *assoc_resp);

#endif /* LIBWIFI_GEN_ASSOCRESP_H */
