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

#ifndef LIBWIFI_GEN_RADIOTAP_H
#define LIBWIFI_GEN_RADIOTAP_H

#include "../../core/misc/radiotap.h"
#include <sys/types.h>

/*
 * Generate a customised radiotap header based on the input provided in info.
 *
 * @param info              A libwifi_radiotap_info struct with desired radiotap data.
 * @param radiotap_header   Buffer to write the radiotap header into.
 * @return                  Length of the generated radiotap header.
 */
size_t libwifi_create_radiotap(struct libwifi_radiotap_info *info, char *radiotap_header);

#endif /* LIBWIFI_GEN_RADIOTAP_H */
