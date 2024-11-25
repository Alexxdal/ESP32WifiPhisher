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

#ifndef LIBWIFI_GEN_ATIM_H
#define LIBWIFI_GEN_ATIM_H

#include "../../core/frame/management/atim.h"

/**
 * Generate a populated ATIM frame.
 *
 * @param atim        A new libwifi_atim struct
 * @param transmitter The transmitter address, aka address 1
 * @param receiver    The receiver address, aka address 2
 * @param address3    The address 3 frame value, typically the BSSID
 * @return            Zero on success, or negative error
*/
int libwifi_create_atim(struct libwifi_atim *atim,
                        const unsigned char transmitter[6],
                        const unsigned char receiver[6],
                        const unsigned char address3[6]);

#endif /* LIBWIFI_GEN_ATIM_H */
