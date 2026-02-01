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

#include "deauthentication.h"
#include "common.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * TODO: potentally write a parsed_to_gen function that converts a parsed deauth back into
 * something that can be passed directly into the interface?
 */

/**
 * Deauthentication frames can originate from the BSS or the STA, with no way to know
 * who sent the frame by looking at just the frame alone. Because of this, they are
 * parsed into a struct libwifi_parsed_deauth instead of a libwifi_bss or libwifi_sta.
 *
 * ┌─────────────────────────────────────────────┐
 * │        Header (Ordered or Unordered)        │  ── Deauthentication Header
 * ├─────────────────────────────────────────────┤
 * │               Fixed Parameters              │  ─┐
 * ├─────────────────────────────────────────────┤   ├──  Deauthentication Body
 * │              Tagged  Parameters             │  ─┘
 * └─────────────────────────────────────────────┘
 */
int libwifi_parse_deauth(struct libwifi_parsed_deauth *deauth, struct libwifi_frame *frame)
{
    memset(deauth, 0, sizeof(*deauth));

    if (frame->frame_control.type != TYPE_MANAGEMENT ||
        frame->frame_control.subtype != SUBTYPE_DEAUTH) {
        return -EINVAL;
    }

    deauth->ordered = frame->frame_control.flags.ordered;

    int hdr_len = deauth->ordered
        ? (int)sizeof(struct libwifi_mgmt_ordered_frame_header)
        : (int)sizeof(struct libwifi_mgmt_unordered_frame_header);

    int min_len = hdr_len + (int)sizeof(struct libwifi_deauth_fixed_parameters);
    if ((int)frame->len < min_len) {
        return -EINVAL;
    }

    int tags_len = (int)frame->len - hdr_len - (int)sizeof(struct libwifi_deauth_fixed_parameters);
    if (tags_len < 0) return -EINVAL;

    if (deauth->ordered) {
        memcpy(&deauth->frame_header.ordered, &frame->header.mgmt_ordered,
               sizeof(struct libwifi_mgmt_ordered_frame_header));
    } else {
        memcpy(&deauth->frame_header.unordered, &frame->header.mgmt_unordered,
               sizeof(struct libwifi_mgmt_unordered_frame_header));
    }

    const unsigned char *body = (const unsigned char *)frame->body;

    memcpy(&deauth->fixed_parameters, body, sizeof(struct libwifi_deauth_fixed_parameters));
    body += sizeof(struct libwifi_deauth_fixed_parameters);

    if (tags_len > 0) {
        deauth->tags.parameters = malloc((size_t)tags_len);
        if (!deauth->tags.parameters) return -ENOMEM;

        memcpy(deauth->tags.parameters, body, (size_t)tags_len);
        deauth->tags.length = (uint32_t)tags_len;
    }

    return 0;
}

void libwifi_free_parsed_deauth(struct libwifi_parsed_deauth *deauth) {
    if (deauth && deauth->tags.parameters) free(deauth->tags.parameters);
    if (deauth) deauth->tags.parameters = NULL;
}