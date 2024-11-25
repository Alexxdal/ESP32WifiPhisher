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

#include "reassoc_request.h"
#include "../../core/frame/tag_iterator.h"
#include "common.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * libwifi_parse_reassoc_req will parse useful fields into a struct libwifi_sta.
 *
 * This function also checks to see if the transmitter address can be ANDed
 * with 0x02, to determine a likelihood of randomized addresses.
 *
 * ┌─────────────────────────────────────────────┐
 * │        Header (Ordered or Unordered)        │  ── Ressociation Request Header
 * ├─────────────────────────────────────────────┤
 * │                Fixed Parameters             │  ─┐
 * ├─────────────────────────────────────────────┤   |── Ressociation Request Body
 * │               Tagged  Parameters            │  ─┘
 * └─────────────────────────────────────────────┘
 */
int libwifi_parse_reassoc_req(struct libwifi_sta *sta, struct libwifi_frame *frame) {
    memset(sta, 0, sizeof(struct libwifi_sta));

    if (frame->frame_control.type != TYPE_MANAGEMENT || frame->frame_control.subtype != SUBTYPE_REASSOC_REQ) {
        return -EINVAL;
    }

    if (frame->frame_control.flags.ordered) {
        memcpy(sta->transmitter, frame->header.mgmt_ordered.addr2, 6);
        memcpy(sta->bssid, frame->header.mgmt_ordered.addr3, 6);
    } else {
        memcpy(sta->transmitter, frame->header.mgmt_unordered.addr2, 6);
        memcpy(sta->bssid, frame->header.mgmt_unordered.addr3, 6);
    }

    if (sta->transmitter[0] & 0x02) {
        sta->randomized = 1;
    } else {
        sta->randomized = 0;
    }

    // Fixed Parameters must be present
    if (frame->len <= (frame->header_len + sizeof(struct libwifi_reassoc_req_fixed_parameters))) {
        return -EINVAL;
    }

    sta->tags.length = (frame->len - frame->header_len);
    const unsigned char *tagged_params = frame->body;
    sta->tags.parameters = malloc(sta->tags.length);
    memcpy(sta->tags.parameters, tagged_params, sta->tags.length);

    struct libwifi_tag_iterator it;
    if (libwifi_tag_iterator_init(&it, sta->tags.parameters, sta->tags.length) != 0) {
        return -EINVAL;
    }

    if (libwifi_sta_tag_parser(sta, &it) != 0) {
        return -EINVAL;
    }

    return 0;
}
