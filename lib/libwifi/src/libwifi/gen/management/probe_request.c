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

#include "probe_request.h"
#include "../../core/misc/byteswap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * The length of a probe request frame is the sum of the header length plus the tagged parameters length.
 */
size_t libwifi_get_probe_req_length(struct libwifi_probe_req *probe_req) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) + probe_req->tags.length;
}

/**
 * The generated probe request frame is made with sane defaults defined in common.h.
 * Two tagged parameters are also added to the beacon: SSID and Channel.
 */
int libwifi_create_probe_req(struct libwifi_probe_req *probe_req,
                             const unsigned char receiver[6],
                             const unsigned char transmitter[6],
                             const unsigned char address3[6],
                             const char *ssid,
                             uint8_t channel) {
    memset(probe_req, 0, sizeof(struct libwifi_probe_req));

    probe_req->frame_header.frame_control.type = TYPE_MANAGEMENT;
    probe_req->frame_header.frame_control.subtype = SUBTYPE_PROBE_REQ;
    memcpy(&probe_req->frame_header.addr1, receiver, 6);
    memcpy(&probe_req->frame_header.addr2, transmitter, 6);
    memcpy(&probe_req->frame_header.addr3, address3, 6);

    int ret = libwifi_quick_add_tag(&probe_req->tags, TAG_SSID, (const unsigned char *) ssid, strlen(ssid));
    if (ret != 0) {
        return ret;
    }

    ret = libwifi_quick_add_tag(&probe_req->tags, TAG_DS_PARAMETER, (const unsigned char *) &channel, 1);
    return ret;
}

/**
 * Copy a libwifi_probe_req into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_probe_req(struct libwifi_probe_req *probe_req, unsigned char *buf, size_t buf_len) {
    size_t probe_req_len = libwifi_get_probe_req_length(probe_req);
    if (probe_req_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &probe_req->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, probe_req->tags.parameters, probe_req->tags.length);
    offset += probe_req->tags.length;

    return probe_req_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_probe_req(struct libwifi_probe_req *probe_req) {
    free(probe_req->tags.parameters);
}
