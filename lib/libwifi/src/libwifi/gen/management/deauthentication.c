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
#include "../../core/misc/byteswap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * The length of a deauth frame is the sum of the header length, the fixed parameters length, and the tagged
 * parameters length.
 */
size_t libwifi_get_deauth_length(struct libwifi_deauth *deauth) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) +
           sizeof(struct libwifi_deauth_fixed_parameters) + deauth->tags.length;
}

/**
 * The generated deauthentication frame contains only the supplied receiver, transmitter and reason_code by
 * default.
 */
int libwifi_create_deauth(struct libwifi_deauth *deauth,
                          const unsigned char receiver[6],
                          const unsigned char transmitter[6],
                          const unsigned char address3[6],
                          uint16_t reason_code) {
    memset(deauth, 0, sizeof(struct libwifi_deauth));

    deauth->frame_header.frame_control.type = TYPE_MANAGEMENT;
    deauth->frame_header.frame_control.subtype = SUBTYPE_DEAUTH;
    memcpy(&deauth->frame_header.addr1, receiver, 6);
    memcpy(&deauth->frame_header.addr2, transmitter, 6);
    memcpy(&deauth->frame_header.addr3, address3, 6);
    memcpy(&deauth->fixed_parameters.reason_code, &reason_code, sizeof(reason_code));

    return 0;
}

/**
 * Copy a libwifi_deauth into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_deauth(struct libwifi_deauth *deauth, unsigned char *buf, size_t buf_len) {
    size_t deauth_len = libwifi_get_deauth_length(deauth);
    if (deauth_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &deauth->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &deauth->fixed_parameters, sizeof(struct libwifi_deauth_fixed_parameters));
    offset += sizeof(struct libwifi_deauth_fixed_parameters);

    memcpy(buf + offset, deauth->tags.parameters, deauth->tags.length);
    offset += deauth->tags.length;

    return deauth_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_deauth(struct libwifi_deauth *deauth) {
    free(deauth->tags.parameters);
}
