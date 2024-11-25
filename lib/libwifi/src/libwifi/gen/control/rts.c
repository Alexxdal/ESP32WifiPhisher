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

#include "rts.h"

#include <string.h>

int libwifi_create_rts(struct libwifi_rts *rts, const unsigned char transmitter[6],
                       const unsigned char receiver[6], uint16_t duration) {
    memset(rts, 0, sizeof(struct libwifi_rts));

    rts->frame_header.frame_control.type = TYPE_CONTROL;
    rts->frame_header.frame_control.subtype = SUBTYPE_RTS;
    rts->frame_header.duration = duration;

    memcpy(rts->transmitter_addr, transmitter, 6);
    memcpy(rts->receiver_addr, receiver, 6);

    return 0;
}
