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

#ifndef LIBWIFI_PARSE_RADIOTAP_H
#define LIBWIFI_PARSE_RADIOTAP_H

#include "../../core/misc/radiotap.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Parse the radiotap information out of a raw frame into a
 * libwifi_radiotap_info.
 *
 * @param info A libwifi_radiotap_info
 * @param frame A raw 802.11 frame
 * @param frame_len Length of the given 802.11 frame
 * @returns Negative errno on error, 0 on success
*/
int libwifi_parse_radiotap_info(struct libwifi_radiotap_info *info, const unsigned char *frame, size_t frame_len);

/**
 * Retrieve the signal strength from a raw frame via radiotap header.
 *
 * @param frame A raw 802.11 frame
 * @return signal strength in dBm
 */
int8_t libwifi_parse_radiotap_rssi(const unsigned char *frame);

#endif /* LIBWIFI_PARSE_RADIOTAP_H */
