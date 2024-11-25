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

#include "disassociation.h"
#include "../../core/misc/byteswap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * The length of a disassoc frame is the sum of the header length, the fixed parameters length, and the tagged
 * parameters length.
 */
size_t libwifi_get_disassoc_length(struct libwifi_disassoc *disassoc) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) +
           sizeof(struct libwifi_disassoc_fixed_parameters) + disassoc->tags.length;
}

/**
 * The generated disassociation frame contains only the supplied receiver, transmitter and reason_code by
 * default.
 */
int libwifi_create_disassoc(struct libwifi_disassoc *disassoc,
                            const unsigned char receiver[6],
                            const unsigned char transmitter[6],
                            const unsigned char address3[6],
                            uint16_t reason_code) {
    memset(disassoc, 0, sizeof(struct libwifi_disassoc));

    disassoc->frame_header.frame_control.type = TYPE_MANAGEMENT;
    disassoc->frame_header.frame_control.subtype = SUBTYPE_DISASSOC;
    memcpy(&disassoc->frame_header.addr1, receiver, 6);
    memcpy(&disassoc->frame_header.addr2, transmitter, 6);
    memcpy(&disassoc->frame_header.addr3, address3, 6);
    memcpy(&disassoc->fixed_parameters.reason_code, &reason_code, sizeof(reason_code));

    return 0;
}

/**
 * Copy a libwifi_disassoc into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_disassoc(struct libwifi_disassoc *disassoc, unsigned char *buf, size_t buf_len) {
    size_t disassoc_len = libwifi_get_disassoc_length(disassoc);
    if (disassoc_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &disassoc->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &disassoc->fixed_parameters, sizeof(struct libwifi_disassoc_fixed_parameters));
    offset += sizeof(struct libwifi_disassoc_fixed_parameters);

    memcpy(buf + offset, disassoc->tags.parameters, disassoc->tags.length);
    offset += disassoc->tags.length;

    return disassoc_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_disassoc(struct libwifi_disassoc *disassoc) {
    free(disassoc->tags.parameters);
}
