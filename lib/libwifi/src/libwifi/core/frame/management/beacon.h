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

#ifndef LIBWIFI_CORE_BEACON_H
#define LIBWIFI_CORE_BEACON_H

#include "../frame.h"
#include "../tag.h"
#include <stdint.h>

/**
 *            Beacon Layout
 *   ──────────────────────────────
 *  ┌──────────────────────────────┐
 *  │             Header           │  Bytes: 24
 *  ├──────────────────────────────┤
 *  │        Fixed Parameters      │  Bytes: 12
 *  │┌────────────────────────────┐│
 *  ││          timestamp         ││  Bytes: 4
 *  │├────────────────────────────┤│
 *  ││           interval         ││  Bytes: 2
 *  │├────────────────────────────┤│
 *  ││         capabilities       ││  Bytes: 2
 *  │└────────────────────────────┘│
 *  ├──────────────────────────────┤
 *  │       Tagged Parameters      │  Bytes: Variable
 *  └──────────────────────────────┘
 */

struct libwifi_beacon_fixed_parameters {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_information;
} __attribute__((packed));

struct libwifi_beacon {
    struct libwifi_mgmt_unordered_frame_header frame_header;
    struct libwifi_beacon_fixed_parameters fixed_parameters;
    struct libwifi_tagged_parameters tags;
} __attribute__((packed));

#endif /* LIBWIFI_CORE_BEACON_H */
