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

#ifndef LIBWIFI_CORE_TIMINGAD_H
#define LIBWIFI_CORE_TIMINGAD_H

#include <stdint.h>
#include "../frame.h"
#include "../tag.h"

/**
 *       Timing Advertisement Layout
 *   ──────────────────────────────────
 *  ┌──────────────────────────────────┐
 *  │               Header             │  Bytes: 24
 *  ├──────────────────────────────────┤
 *  │          Fixed Parameters        │  Bytes: 6
 *  │┌────────────────────────────────┐│
 *  ││            timestamp           ││  Bytes: 8
 *  │├────────────────────────────────┤│
 *  ││   measurement pilot interval   ││  Bytes: 1
 *  │├────────────────────────────────┤│
 *  ││         beacon interval        ││  Bytes: 2
 *  │├────────────────────────────────┤│
 *  ││    capabilities information    ││  Bytes: 2
 *  │├────────────────────────────────┤│
 *  ││           country code         ││  Bytes: 3
 *  │├────────────────────────────────┤│
 *  ││    maxmimum regulatory power   ││  Bytes: 2
 *  │├────────────────────────────────┤│
 *  ││      maximum transmit power    ││  Bytes: 1
 *  │├────────────────────────────────┤│
 *  ││       transmit power used      ││  Bytes: 1
 *  │├────────────────────────────────┤│
 *  ││           noise floor          ││  Bytes: 1
 *  │└────────────────────────────────┘│
 *  ├──────────────────────────────────┤
 *  │         Tagged Parameters        │  Bytes: Variable
 *  │┌────────────────────────────────┐│
 *  ││      timing advert fields      ││  Bytes: 17
 *  │└────────────────────────────────┘│
 *  └──────────────────────────────────┘
 */

struct libwifi_timing_advert_fields {
    uint8_t timing_capabilities;
    unsigned char time_value[10];
    unsigned char time_error[5];
    unsigned char time_update[1];
} __attribute__((packed));

struct libwifi_timing_advert_fixed_params {
    uint64_t timestamp;
    uint8_t measurement_pilot_interval;
    uint16_t beacon_interval;
    uint16_t capabilities_information;
    char country[3];
    uint16_t max_reg_power;
    uint8_t max_tx_power;
    uint8_t tx_power_used;
    uint8_t noise_floor;
} __attribute__((packed));

struct libwifi_timing_advert {
    struct libwifi_mgmt_unordered_frame_header frame_header;
    struct libwifi_timing_advert_fixed_params fixed_parameters;
    struct libwifi_tagged_parameters tags;
} __attribute__((packed));

#endif /* LIBWIFI_CORE_TIMINGAD_H */
