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

#ifndef LIBWIFI_CORE_ACTIONS_H
#define LIBWIFI_CORE_ACTIONS_H

#include "../frame.h"
#include <stdint.h>

/* Defined action fixed parameter values */
enum libwifi_actions {
    ACTION_SPECTRUM_MGMT = 0,
    ACTION_QOS = 1,
    // Reserved 2
    ACTION_BLOCK_ACK = 3,
    ACTION_PUBLIC = 4,
    ACTION_RADIO_MEASUREMENT = 5,
    ACTION_FAST_BSS_TRANSITION = 6,
    ACTION_HT = 7,
    ACTION_SA_QUERY = 8,
    ACTION_PROTECTED_DOPA = 9,
    ACTION_WNM = 10,
    ACTION_UNSUPPORTED_WNM = 11,
    ACTION_TDLS = 12,
    ACTION_MESH = 13,
    ACTION_MULTIHOP = 14,
    ACTION_SELF_PROTECTED = 15,
    ACTION_DMG = 16,
    // Reserved 17
    ACTION_FAST_SESSION_TRANSFER = 18,
    ACTION_ROBUST_AV_STREAM = 19,
    ACTION_UNPROTECTED_DMG = 20,
    ACTION_VHT = 21,
    ACTION_UNPROTECTED_SIG = 22,
    ACTION_SIG = 23,
    ACTION_FLOW_CONTROL = 24,
    ACTION_CTRL_MCS_NEG = 25,
    ACTION_FILS = 26,
    ACTION_CDMG = 27,
    ACTION_CMMG = 28,
    ACTION_GLK = 29,
    // Reserved 30-125
    ACTION_VENDOR_PROTECTED = 126,
    ACTION_VENDOR = 127,
    // Error 128-255
};

/**
 *                Action Layout
 *   ─────────────────────────────────────
 *  ┌─────────────────────────────────────┐
 *  │                Header               │  Bytes: 24
 *  ├─────────────────────────────────────┤
 *  │            Fixed Parameters         │  Bytes: Variable
 *  │┌───────────────────────────────────┐│
 *  ││              category             ││  Bytes: 1
 *  │├───────────────────────────────────┤│
 *  ││               detail              ││  Bytes: Variable
 *  ││┌─────────────────────────────────┐││
 *  │││         tagged parameters       │││
 *  ││└─────────────────────────────────┘││
 *  │└───────────────────────────────────┘│
 *  └─────────────────────────────────────┘
 */

struct libwifi_action_detail {
    uint8_t detail_length;
    char *detail;
} __attribute__((packed));

struct libwifi_action_fixed_parameters {
    uint8_t category;
    struct libwifi_action_detail details;
} __attribute__((packed));

struct libwifi_action {
    struct libwifi_mgmt_unordered_frame_header frame_header;
    struct libwifi_action_fixed_parameters fixed_parameters;
} __attribute__((packed));

#endif /* LIBWIFI_CORE_ACTIONS_H */
