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

#ifndef LIBWIFI_CORE_ATIM_H
#define LIBWIFI_CORE_ATIM_H

#include "../frame.h"

/**
 *            ATIM Frame Layout
 *   ─────────────────────────────────
 *  ┌─────────────────────────────────┐
 *  │              Header             │  Bytes: 24
 *  └─────────────────────────────────┘
 */

struct libwifi_atim {
    struct libwifi_mgmt_unordered_frame_header frame_header;
};

#endif /* LIBWIFI_CORE_ATIM_H */
