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

#ifndef LIBWIFI_CORE_LLC_H
#define LIBWIFI_CORE_LLC_H

#include <stdint.h>

#define XEROX_OUI "\x00\x00\x00"

#define LLC_TYPE_AUTH 0x888E

struct libwifi_logical_link_ctrl {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;
    unsigned char oui[3];
    uint16_t type;
} __attribute__((packed));

#endif /* LIBWIFI_CORE_LLC_H */
