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

#include "reassoc_response.h"
#include "../../core/frame/tag.h"
#include "../../core/frame/tag_iterator.h"
#include "../../core/misc/byteswap.h"
#include "../../core/misc/epoch.h"
#include "../../core/misc/types.h"
#include "common.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/**
 * The length of a reassociation response frame is the sum of the header length, the fixed parameters length,
 * and the tagged parameters length.
 */
size_t libwifi_get_reassoc_resp_length(struct libwifi_reassoc_resp *reassoc_resp) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) +
           sizeof(struct libwifi_reassoc_resp_fixed_parameters) +
           reassoc_resp->tags.length;
}

/**
 * Simple helper to set the reassociation response DS tag by removing it and then adding it back with the new
 * value.
 */
int libwifi_set_reassoc_resp_channel(struct libwifi_reassoc_resp *reassoc_resp, uint8_t channel) {
    int ret = 0;

    if (reassoc_resp->tags.length != 0) {
        ret = libwifi_remove_tag(&reassoc_resp->tags, TAG_DS_PARAMETER);
        if (ret != 0) {
            return ret;
        }
    }

    const unsigned char *chan = (const unsigned char *) &channel;
    ret = libwifi_quick_add_tag(&reassoc_resp->tags, TAG_DS_PARAMETER, chan, 1);

    return ret;
}

/**
 * The generated reassoc_resp frame is made with sane defaults defined in common.h.
 * One tagged parameters is also added to the reassoc_resp: Channel.
 */
int libwifi_create_reassoc_resp(struct libwifi_reassoc_resp *reassoc_resp,
                                const unsigned char receiver[6],
                                const unsigned char transmitter[6],
                                const unsigned char address3[6],
                                uint8_t channel) {
    memset(reassoc_resp, 0, sizeof(struct libwifi_reassoc_resp));

    reassoc_resp->frame_header.frame_control.type = TYPE_MANAGEMENT;
    reassoc_resp->frame_header.frame_control.subtype = SUBTYPE_REASSOC_RESP;
    memcpy(&reassoc_resp->frame_header.addr1, receiver, 6);
    memcpy(&reassoc_resp->frame_header.addr2, transmitter, 6);
    memcpy(&reassoc_resp->frame_header.addr3, address3, 6);
    reassoc_resp->fixed_parameters.capabilities_information = BYTESWAP16(LIBWIFI_DEFAULT_AP_CAPABS);
    reassoc_resp->fixed_parameters.status_code = STATUS_SUCCESS;

    int ret = libwifi_set_reassoc_resp_channel(reassoc_resp, channel);

    return ret;
}

/**
 * Copy a libwifi_reassoc_resp into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_reassoc_resp(struct libwifi_reassoc_resp *reassoc_resp, unsigned char *buf,
                                 size_t buf_len) {
    size_t reassoc_resp_len = libwifi_get_reassoc_resp_length(reassoc_resp);
    if (reassoc_resp_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &reassoc_resp->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &reassoc_resp->fixed_parameters,
           sizeof(struct libwifi_reassoc_resp_fixed_parameters));
    offset += sizeof(struct libwifi_reassoc_resp_fixed_parameters);

    memcpy(buf + offset, reassoc_resp->tags.parameters, reassoc_resp->tags.length);
    offset += reassoc_resp->tags.length;

    return reassoc_resp_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_reassoc_resp(struct libwifi_reassoc_resp *reassoc_resp) {
    free(reassoc_resp->tags.parameters);
}
