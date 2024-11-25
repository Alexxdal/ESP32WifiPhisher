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

#include "authentication.h"
#include "../../core/misc/byteswap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * The length of an authentication frame is the sum of the header length, the fixed parameters length, and the
 * tagged parameters length.
 */
size_t libwifi_get_auth_length(struct libwifi_auth *auth) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) + sizeof(struct libwifi_auth_fixed_parameters) +
           auth->tags.length;
}

/**
 * The generated authentication frame is made with sane defaults defined in common.h.
 */
int libwifi_create_auth(struct libwifi_auth *auth,
                        const unsigned char receiver[6],
                        const unsigned char transmitter[6],
                        const unsigned char address3[6],
                        uint16_t algorithm_number,
                        uint16_t transaction_sequence,
                        uint16_t status_code) {
    memset(auth, 0, sizeof(struct libwifi_auth));

    auth->frame_header.frame_control.type = TYPE_MANAGEMENT;
    auth->frame_header.frame_control.subtype = SUBTYPE_AUTH;
    memcpy(&auth->frame_header.addr1, receiver, 6);
    memcpy(&auth->frame_header.addr2, transmitter, 6);
    memcpy(&auth->frame_header.addr3, address3, 6);
    auth->fixed_parameters.algorithm_number = algorithm_number;
    auth->fixed_parameters.transaction_sequence = transaction_sequence;
    auth->fixed_parameters.status_code = status_code;

    return 0;
}

/**
 * Copy a libwifi_auth into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_auth(struct libwifi_auth *auth, unsigned char *buf, size_t buf_len) {
    size_t auth_len = libwifi_get_auth_length(auth);
    if (auth_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &auth->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &auth->fixed_parameters, sizeof(struct libwifi_auth_fixed_parameters));
    offset += sizeof(struct libwifi_auth_fixed_parameters);

    memcpy(buf + offset, auth->tags.parameters, auth->tags.length);
    offset += auth->tags.length;

    return auth_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_auth(struct libwifi_auth *auth) {
    free(auth->tags.parameters);
}
