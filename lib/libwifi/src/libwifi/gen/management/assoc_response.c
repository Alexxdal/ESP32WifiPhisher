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

#include "assoc_response.h"
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
 * The length of an association response frame is the sum of the header length, the fixed parameters length,
 * and the tagged parameters length.
 */
size_t libwifi_get_assoc_resp_length(struct libwifi_assoc_resp *assoc_resp) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) +
           sizeof(struct libwifi_assoc_resp_fixed_parameters) +
           assoc_resp->tags.length;
}

/**
 * Simple helper function to set the channel of an association response by removing and re-adding the
 * DS tagged parameter.
 */
int libwifi_set_assoc_resp_channel(struct libwifi_assoc_resp *assoc_resp, uint8_t channel) {
    int ret = 0;

    if (assoc_resp->tags.length != 0) {
        ret = libwifi_remove_tag(&assoc_resp->tags, TAG_DS_PARAMETER);
        if (ret != 0) {
            return ret;
        }
    }

    const unsigned char *chan = (const unsigned char *) &channel;
    ret = libwifi_quick_add_tag(&assoc_resp->tags, TAG_DS_PARAMETER, chan, 1);

    return ret;
}

/**
 * The generated association response frame is made with sane defaults defined in common.h and core/types.h.
 * Two tagged parameters are also added to the association response: Channel and Supported Rates.
 */
int libwifi_create_assoc_resp(struct libwifi_assoc_resp *assoc_resp,
                              const unsigned char receiver[6],
                              const unsigned char transmitter[6],
                              const unsigned char address3[6],
                              uint8_t channel) {
    memset(assoc_resp, 0, sizeof(struct libwifi_assoc_resp));

    assoc_resp->frame_header.frame_control.type = TYPE_MANAGEMENT;
    assoc_resp->frame_header.frame_control.subtype = SUBTYPE_ASSOC_RESP;
    memcpy(&assoc_resp->frame_header.addr1, receiver, 6);
    memcpy(&assoc_resp->frame_header.addr2, transmitter, 6);
    memcpy(&assoc_resp->frame_header.addr3, address3, 6);
    assoc_resp->fixed_parameters.capabilities_information = BYTESWAP16(LIBWIFI_DEFAULT_AP_CAPABS);
    assoc_resp->fixed_parameters.status_code = STATUS_SUCCESS;

    libwifi_set_assoc_resp_channel(assoc_resp, channel);

    const unsigned char supported_rates[] = LIBWIFI_DEFAULT_SUPP_RATES;
    int ret = libwifi_quick_add_tag(&assoc_resp->tags, TAG_SUPP_RATES, supported_rates, sizeof(supported_rates) - 1);

    return ret;
}

/**
 * Copy a libwifi_assoc_resp into a regular unsigned char buffer. This is useful when injecting generated
 * libwifi frames.
 */
size_t libwifi_dump_assoc_resp(struct libwifi_assoc_resp *assoc_resp, unsigned char *buf, size_t buf_len) {
    size_t assoc_resp_len = libwifi_get_assoc_resp_length(assoc_resp);
    if (assoc_resp_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;
    memcpy(buf + offset, &assoc_resp->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &assoc_resp->fixed_parameters, sizeof(struct libwifi_assoc_resp_fixed_parameters));
    offset += sizeof(struct libwifi_assoc_resp_fixed_parameters);

    memcpy(buf + offset, assoc_resp->tags.parameters, assoc_resp->tags.length);
    offset += assoc_resp->tags.length;

    return assoc_resp_len;
}

/**
 * Because the tagged parameters memory is managed inside of the library, the library must
 * be the one to free it, too.
 */
void libwifi_free_assoc_resp(struct libwifi_assoc_resp *assoc_resp) {
    free(assoc_resp->tags.parameters);
}
