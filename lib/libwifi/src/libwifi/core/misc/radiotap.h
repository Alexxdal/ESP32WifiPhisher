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

#ifndef LIBWIFI_CORE_RADIOTAP_H
#define LIBWIFI_CORE_RADIOTAP_H

#include <stdint.h>

#define LIBWIFI_MAX_RADIOTAP_LEN 128
#define LIBWIFI_MAX_RADIOTAP_ANTENNAS 16

#define LIBWIFI_RADIOTAP_BAND_2GHZ (1 << 0)
#define LIBWIFI_RADIOTAP_BAND_5GHZ (1 << 1)
#define LIBWIFI_RADIOTAP_BAND_6GHZ (1 << 2)
#define LIBWIFI_RADIOTAP_BAND_900MHZ (1 << 3)

/**
 * A channel field in radiotap consists of a 2-byte wide flags
 * sub-field and a 2-byte wide frequency field.
 *
 * libwifi will also calculate the band and center channel.
 */
struct libwifi_radiotap_channel {
    uint16_t flags;
    uint16_t freq;
    uint8_t center;
    uint8_t band;
} __attribute__((packed));

/**
 * The radiotap antenna field consists of an antenna number and signal in dBm
 */
struct libwifi_radiotap_antenna {
    uint8_t antenna_number;
    int8_t signal;
} __attribute__((packed));

/**
 * The radiotap MCS field is made up of 3 2-byte fields.
 */
struct libwifi_radiotap_mcs {
    uint8_t known;
    uint8_t flags;
    uint8_t mcs;
} __attribute__((packed));

/**
 * The radiotap timestamp field consists of a timestamp field, accuracy, unit and flags.
 */
struct libwifi_radiotap_timestamp {
    uint64_t timestamp;
    uint16_t accuracy;
    uint8_t unit;
    uint8_t flags;
} __attribute__((packed));

struct libwifi_radiotap_info {
    // Header
    uint32_t present;
    // Body
    struct libwifi_radiotap_channel channel;
    int8_t rate_raw;
    float rate;
    uint8_t antenna_count;
    struct libwifi_radiotap_antenna antennas[LIBWIFI_MAX_RADIOTAP_ANTENNAS];
    int8_t signal;
    uint8_t flags;
    uint32_t extended_flags;
    uint16_t rx_flags;
    uint16_t tx_flags;
    struct libwifi_radiotap_mcs mcs;
    int8_t tx_power;
    struct libwifi_radiotap_timestamp timestamp;
    uint8_t rts_retries;
    uint8_t data_retries;
    // Other
    uint8_t length;
} __attribute__((packed));

#endif /* LIBWIFI_CORE_RADIOTAP_H */
