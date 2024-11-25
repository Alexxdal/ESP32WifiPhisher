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

#ifndef LIBWIFI_GEN_TIMINGAD_H
#define LIBWIFI_GEN_TIMINGAD_H

#include "../../core/frame/management/timing_ad.h"

/**
 * Create a populated libwifi_timing_advert struct
 *
 * A generated libwifi timing advert can be "dumped" into a buffer for packet injection
 * via the libwifi_dump_timing_advert function.
 *
 * @param adv           A new libwifi_timing_advert struct
 * @param receiver      The receiver MAC address, aka address 1
 * @param transmitter   The source MAC address, aka address 2
 * @param address3      The address 3 frame field value, typically the BSSID
 * @param adv_fields    A libwifi_timing_advert_fields struct
 * @param country       The ISO 3166-1 country code field value
 * @param max_reg_power Maximum Regulatory Power value
 * @param max_tx_power  Maximum Transmit Power value
 * @param tx_power_used Transmit Power Used value
 * @param noise_floor   Noise Floor value
 * @return              Zero on success, or negative errno
 */
int libwifi_create_timing_advert(struct libwifi_timing_advert *adv,
                                 const unsigned char receiver[6],
                                 const unsigned char transmitter[6],
                                 const unsigned char address3[6],
                                 struct libwifi_timing_advert_fields *adv_fields,
                                 const char country[3],
                                 uint16_t max_reg_power,
                                 uint8_t max_tx_power,
                                 uint8_t tx_power_used,
                                 uint8_t noise_floor);

/**
 * Get the length of the specified libwifi_timing_advert struct
 *
 * @return Length of the specified timing advert, or negative error
 */
size_t libwifi_get_timing_advert_length(struct libwifi_timing_advert *adv);

/**
 * Dump a libwifi_timing_advert into a raw format for packet injection.
 *
 * @param adv     A libwifi_timing_advert
 * @param buf     The output buffer for the frame data
 * @param buf_len The length of the output buffer
 * @return        The length of the dumped timing advert, or negative error
 */
size_t libwifi_dump_timing_advert(struct libwifi_timing_advert *adv, unsigned char *buf, size_t buf_len);

/**
 * Free any memory claimed by a libwifi_timing_advert back to the system.
 *
 * @param adv A libwifi_timing_advert struct
 */
void libwifi_free_timing_advert(struct libwifi_timing_advert *adv);

#endif /* LIBWIFI_GEN_TIMINGAD_H */
