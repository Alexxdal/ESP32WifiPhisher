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

#ifndef LIBWIFI_GEN_PROBEREQ_H
#define LIBWIFI_GEN_PROBEREQ_H

#include <stdint.h>

#include "../../core/frame/management/probe_request.h"

/**
 * Calculate the length of a given libwifi_probe_req
 *
 * @param probe_req A libwifi_probe_req
 * @return          The length of the given probe_req, or negative error
 */
size_t libwifi_get_probe_req_length(struct libwifi_probe_req *probe_req);

/**
 * Generate a populated libwifi probe_req.
 *
 * A generated libwifi probe_req can be "dumped" into a buffer for packet injection
 * via the libwifi_dump_probe_req.
 *
 * @param probe_req   A libwifi_probe_req
 * @param receiver    The receiver MAC address, aka address 1
 * @param transmitter The source MAC address, aka address 2
 * @param address3    The address 3 frame field value, typically the BSSID
 * @param ssid        The probe request SSID
 * @param channel     The probe request channel
 * @return            Zero on success, or negative error
 */
int libwifi_create_probe_req(struct libwifi_probe_req *probe_req,
                             const unsigned char receiver[6],
                             const unsigned char transmitter[6],
                             const unsigned char address3[6],
                             const char *ssid,
                             uint8_t channel);

/**
 * Dump a libwifi_probe_req into a raw format for packet injection.
 *
 * @param probe_req A libwifi_probe_req
 * @param buf       The output buffer for the frame data
 * @param buf_len   The length of the output buffer
 * @return          The length of the dumped probe_req, or negative error
 */
size_t libwifi_dump_probe_req(struct libwifi_probe_req *probe_req, unsigned char *buf, size_t buf_len);

/**
 * Free any memory claimed by a libwifi_probe_req back to the system.
 *
 * @param probe_req A libwifi_probe_req
 */
void libwifi_free_probe_req(struct libwifi_probe_req *probe_req);

#endif /* LIBWIFI_GEN_PROBEREQ_H */
