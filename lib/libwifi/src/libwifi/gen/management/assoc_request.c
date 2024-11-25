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

#include "assoc_request.h"
#include "common.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * The length of an association request frame is the sum of the header length, the fixed parameters length,
 * and the tagged parameters length.
 */
size_t libwifi_get_assoc_req_length(struct libwifi_assoc_req *assoc_req) {
    return sizeof(assoc_req->frame_header) + sizeof(struct libwifi_assoc_req_fixed_parameters) +
           assoc_req->tags.length;
}

/**
 * The generated association request frame is made with sane defaults defined in common.h.
 * Two tagged parameters are also added to the association request: SSID and Channel.
 */
int libwifi_create_assoc_req(struct libwifi_assoc_req *assoc_req,
                             const unsigned char receiver[6],
                             const unsigned char transmitter[6],
                             const unsigned char address3[6],
                             const char *ssid,
                             uint8_t channel) {
    memset(assoc_req, 0, sizeof(struct libwifi_assoc_req));

    assoc_req->frame_header.frame_control.type = TYPE_MANAGEMENT;
    assoc_req->frame_header.frame_control.subtype = SUBTYPE_ASSOC_REQ;
    memcpy(&assoc_req->frame_header.addr1, receiver, 6);
    memcpy(&assoc_req->frame_header.addr2, transmitter, 6);
    memcpy(&assoc_req->frame_header.addr3, address3, 6);
    assoc_req->fixed_parameters.capabilities_information = BYTESWAP16(LIBWIFI_DEFAULT_AP_CAPABS);
    assoc_req->fixed_parameters.listen_interval = BYTESWAP16(LIBWIFI_DEFAULT_LISTEN_INTERVAL);

    int ret = libwifi_quick_add_tag(&assoc_req->tags, TAG_SSID, (const unsigned char *) ssid, strlen(ssid));
    if (ret != 0) {
        return ret;
    }

    ret = libwifi_quick_add_tag(&assoc_req->tags, TAG_DS_PARAMETER, (const unsigned char *) &channel, 1);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

/**
 * Copy a libwifi_assoc_req into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_assoc_req(struct libwifi_assoc_req *assoc_req, unsigned char *buf, size_t buf_len) {
    size_t assoc_req_len = libwifi_get_assoc_req_length(assoc_req);
    if (assoc_req_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &assoc_req->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &assoc_req->fixed_parameters, sizeof(struct libwifi_assoc_req_fixed_parameters));
    offset += sizeof(struct libwifi_assoc_req_fixed_parameters);

    memcpy(buf + offset, assoc_req->tags.parameters, assoc_req->tags.length);
    offset += assoc_req->tags.length;

    return assoc_req_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_assoc_req(struct libwifi_assoc_req *assoc_req) {
    free(assoc_req->tags.parameters);
}
