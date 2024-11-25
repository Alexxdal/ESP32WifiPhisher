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

#ifndef LIBWIFI_GEN_AUTH_H
#define LIBWIFI_GEN_AUTH_H

#include <stdint.h>

#include "../../core/frame/management/authentication.h"

/**
 * Calculate the length of a given libwifi_auth
 *
 * @param auth A libwifi_auth
 * @return     The length of the given auth
 */
size_t libwifi_get_auth_length(struct libwifi_auth *auth);

/**
 * Generate a populated libwifi auth.
 *
 * A generated libwifi auth can be "dumped" into a buffer for packet injection
 * via the libwifi_dump_auth.
 *
 * @param auth                 A libwifi_auth
 * @param receiver             The receiver MAC address, aka address 1
 * @param transmitter          The source MAC address, aka address 2
 * @param address3             The address 3 frame field value, typically the BSSID
 * @param algorithm_number     Algorithm type to use, as defined in the IEEE802.11 spec
 * @param transaction_sequence Transaction sequence value to use
 * @param status_code          Status code to use, as defined in the IEEE802.11 spec
 * @return                     Zero on success, or negative error
 */
int libwifi_create_auth(struct libwifi_auth *auth,
                        const unsigned char receiver[6],
                        const unsigned char transmitter[6],
                        const unsigned char address3[6],
                        uint16_t algorithm_number,
                        uint16_t transaction_sequence,
                        uint16_t status_code);

/**
 * Dump a libwifi_auth into a raw format for packet injection.
 *
 * @param auth    A libwifi_auth
 * @param buf     The output buffer for the frame data
 * @param buf_len The length of the output buffer
 * @return        The length of the dumped auth, or negative error
 */
size_t libwifi_dump_auth(struct libwifi_auth *auth, unsigned char *buf, size_t buf_len);

/**
 * Free any memory claimed by a libwifi_auth back to the system.
 *
 * @param auth A libwifi_auth
 */
void libwifi_free_auth(struct libwifi_auth *auth);

#endif /* LIBWIFI_GEN_AUTH_H */
