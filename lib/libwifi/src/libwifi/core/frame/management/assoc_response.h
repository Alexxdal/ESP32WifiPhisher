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

#ifndef LIBWIFI_CORE_ASSOCRESP_H
#define LIBWIFI_CORE_ASSOCRESP_H

#include "../frame.h"
#include "../tag.h"
#include <stdint.h>

/**
 *       Association Response Layout
 *   ─────────────────────────────────
 *  ┌─────────────────────────────────┐
 *  │              Header             │  Bytes: 24
 *  ├─────────────────────────────────┤
 *  │         Fixed Parameters        │  Bytes: 6
 *  │┌───────────────────────────────┐│
 *  ││          capabilities         ││  Bytes: 2
 *  │├───────────────────────────────┤│
 *  ││             status            ││  Bytes: 2
 *  │├───────────────────────────────┤│
 *  ││         association id        ││  Bytes: 2
 *  │└───────────────────────────────┘│
 *  ├─────────────────────────────────┤
 *  │        Tagged Parameters        │  Bytes: Variable
 *  └─────────────────────────────────┘
 */

struct libwifi_assoc_resp_fixed_parameters {
    uint16_t capabilities_information;
    uint16_t status_code;
    uint16_t association_id;
} __attribute__((packed));

struct libwifi_assoc_resp {
    struct libwifi_mgmt_unordered_frame_header frame_header;
    struct libwifi_assoc_resp_fixed_parameters fixed_parameters;
    struct libwifi_tagged_parameters tags;
} __attribute__((packed));

#endif /* LIBWIFI_CORE_ASSOCRESP_H */
