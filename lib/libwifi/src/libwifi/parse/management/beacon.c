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

#include "../../core/frame/management/beacon.h"
#include "../../core/frame/frame.h"
#include "../../core/frame/tag.h"
#include "../../core/frame/tag_iterator.h"
#include "../../core/misc/types.h"
#include "../../parse/misc/security.h"
#include "beacon.h"
#include "common.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * libwifi_parse_beacon will parse useful fields out of a supplied beacon frame
 * in the format of a struct libwifi_frame.
 *
 * ┌─────────────────────────────────────────────┐
 * │        Header (Ordered or Unordered)        │  ── Beacon Header
 * ├─────────────────────────────────────────────┤
 * │               Fixed Parameters              │  ─┐
 * ├─────────────────────────────────────────────┤   ├── Beacon Body
 * │              Tagged  Parameters             │  ─┘
 * └─────────────────────────────────────────────┘
 */
int libwifi_parse_beacon(struct libwifi_bss *bss, struct libwifi_frame *frame) {
    memset(bss, 0, sizeof(struct libwifi_bss));

    if (frame->frame_control.type != TYPE_MANAGEMENT || frame->frame_control.subtype != SUBTYPE_BEACON) {
        return -EINVAL;
    }

    if (frame->frame_control.flags.ordered) {
        memcpy(bss->receiver, frame->header.mgmt_ordered.addr1, 6);
        memcpy(bss->transmitter, frame->header.mgmt_ordered.addr2, 6);
        memcpy(bss->bssid, frame->header.mgmt_ordered.addr3, 6);
    } else {
        memcpy(bss->receiver, frame->header.mgmt_unordered.addr1, 6);
        memcpy(bss->transmitter, frame->header.mgmt_unordered.addr2, 6);
        memcpy(bss->bssid, frame->header.mgmt_unordered.addr3, 6);
    }

    // Fixed Parameters must be present
    if (frame->len <= (frame->header_len + sizeof(struct libwifi_beacon_fixed_parameters))) {
        return -EINVAL;
    }

    // At least one Tagged Parameter must be present
    // + 2 represents two additional bytes: Tag number and a single byte value
    if (frame->len < (frame->header_len + sizeof(struct libwifi_beacon_fixed_parameters) + 2)) {
        return -EINVAL;
    }

    struct libwifi_beacon_fixed_parameters *fixed_params =
        (struct libwifi_beacon_fixed_parameters *) frame->body;
    if (libwifi_check_capabilities(fixed_params->capabilities_information, CAPABILITIES_PRIVACY)) {
        bss->encryption_info |= WEP;
    }

    bss->tags.length = (frame->len - (frame->header_len + sizeof(struct libwifi_beacon_fixed_parameters)));
    const unsigned char *tagged_params = frame->body + sizeof(struct libwifi_beacon_fixed_parameters);
    bss->tags.parameters = malloc(bss->tags.length);
    memcpy(bss->tags.parameters, tagged_params, bss->tags.length);

    // Iterate through common BSS tagged parameters (WPA, RSN, etc)
    struct libwifi_tag_iterator it;
    memset(&it, 0, sizeof(struct libwifi_tag_iterator));
    if (libwifi_tag_iterator_init(&it, bss->tags.parameters, bss->tags.length) != 0) {
        return -EINVAL;
    }
    if (libwifi_bss_tag_parser(bss, &it) != 0) {
        return -EINVAL;
    };

    return 0;
}
