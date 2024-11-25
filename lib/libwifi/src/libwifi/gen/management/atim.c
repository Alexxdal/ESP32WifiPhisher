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

#include "atim.h"

#include <stdlib.h>
#include <string.h>

int libwifi_create_atim(struct libwifi_atim *atim,
                        const unsigned char transmitter[6],
                        const unsigned char receiver[6],
                        const unsigned char address3[6]) {
    memset(atim, 0, sizeof(struct libwifi_atim));

    atim->frame_header.frame_control.type = TYPE_MANAGEMENT;
    atim->frame_header.frame_control.subtype = SUBTYPE_ATIM;
    memcpy(&atim->frame_header.addr1, transmitter, 6);
    memcpy(&atim->frame_header.addr2, receiver, 6);
    memcpy(&atim->frame_header.addr3, address3, 6);

    return 0;
}
