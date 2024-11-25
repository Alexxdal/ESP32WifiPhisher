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
#include "common.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * The length of a reassociation request frame is the sum of the header length, the fixed parameters length,
 * and the tagged parameters length.
 */
size_t libwifi_get_reassoc_req_length(struct libwifi_reassoc_req *reassoc_req) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) +
           sizeof(struct libwifi_reassoc_req_fixed_parameters) +
           reassoc_req->tags.length;
}

/**
 * The generated reassociation request frame is made with sane defaults defined in common.h.
 * Two tagged parameters are also added to the reassociation frame: SSID and Channel
 */
int libwifi_create_reassoc_req(struct libwifi_reassoc_req *reassoc_req,
                               const unsigned char receiver[6],
                               const unsigned char transmitter[6],
                               const unsigned char address3[6],
                               const unsigned char current_ap[6],
                               const char *ssid,
                               uint8_t channel) {
    memset(reassoc_req, 0, sizeof(struct libwifi_reassoc_req));

    reassoc_req->frame_header.frame_control.type = TYPE_MANAGEMENT;
    reassoc_req->frame_header.frame_control.subtype = SUBTYPE_REASSOC_REQ;
    memcpy(&reassoc_req->frame_header.addr1, receiver, 6);
    memcpy(&reassoc_req->frame_header.addr2, transmitter, 6);
    memcpy(&reassoc_req->frame_header.addr3, address3, 6);
    reassoc_req->fixed_parameters.capabilities_information = BYTESWAP16(LIBWIFI_DEFAULT_AP_CAPABS);
    reassoc_req->fixed_parameters.listen_interval = BYTESWAP16(LIBWIFI_DEFAULT_LISTEN_INTERVAL);
    memcpy(&reassoc_req->fixed_parameters.current_ap_address, current_ap, 6);

    int ret = libwifi_quick_add_tag(&reassoc_req->tags, TAG_SSID, (const unsigned char *) ssid, strlen(ssid));
    if (ret != 0) {
        return ret;
    }

    ret = libwifi_quick_add_tag(&reassoc_req->tags, TAG_DS_PARAMETER, (const unsigned char *) &channel, 1);

    return ret;
}

/**
 * Copy a libwifi_reassoc_req into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_reassoc_req(struct libwifi_reassoc_req *reassoc_req, unsigned char *buf, size_t buf_len) {
    size_t reassoc_req_len = libwifi_get_reassoc_req_length(reassoc_req);
    if (reassoc_req_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &reassoc_req->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &reassoc_req->fixed_parameters, sizeof(struct libwifi_reassoc_req_fixed_parameters));
    offset += sizeof(struct libwifi_reassoc_req_fixed_parameters);

    memcpy(buf + offset, reassoc_req->tags.parameters, reassoc_req->tags.length);
    offset += reassoc_req->tags.length;

    return reassoc_req_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_reassoc_req(struct libwifi_reassoc_req *reassoc_req) {
    free(reassoc_req->tags.parameters);
}
