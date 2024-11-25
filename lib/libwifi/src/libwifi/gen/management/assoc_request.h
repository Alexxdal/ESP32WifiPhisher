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

#ifndef LIBWIFI_GEN_ASSOCREQUEST_H
#define LIBWIFI_GEN_ASSOCREQUEST_H

#include "../../core/frame/frame.h"
#include "../../core/frame/management/assoc_request.h"
#include "../../core/frame/management/common.h"

/**
 * Create a new association request
 *
 * @param assoc_req   A new libwifi_assoc_req struct
 * @param receiver    The receiver MAC address
 * @param transmitter The transmitter MAC address
 * @param address3    The address 3 frame field value, typically the BSSID
 * @param ssid        The desired BSS SSID
 * @param channel     The desired channel
 * @param             Zero on success, or negative error
 */
int libwifi_create_assoc_req(struct libwifi_assoc_req *assoc_req,
                             const unsigned char receiver[6],
                             const unsigned char transmitter[6],
                             const unsigned char address3[6],
                             const char *ssid,
                             uint8_t channel);

/**
 * Get the length of a given libwifi_assoc_req
 *
 * @param assoc_req A libwifi_assoc_req struct
 * @return          Length of the given libwifi_assoc_req
 */
size_t libwifi_get_assoc_req_length(struct libwifi_assoc_req *assoc_req);

/**
 * Dump a libwifi_assoc_req into a raw format for packet injection.
 *
 * @param assoc_req A libwifi_assoc_req struct
 * @param buf       The buffer to dump into
 * @param buf_len   The length of the supplied buffer
 * @param           The amount of bytes dumped, or negative error
 */
size_t libwifi_dump_assoc_req(struct libwifi_assoc_req *assoc_req, unsigned char *buf, size_t buf_len);


/**
 * Free any memory claimed by a libwifi_assoc_req back to the system.
 *
 * @param assoc_req A libwifi_assoc_req
 */
void libwifi_free_assoc_req(struct libwifi_assoc_req *assoc_req);

#endif /* LIBWIFI_GEN_ASSOCREQUEST_H */
