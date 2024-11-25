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

#include "action.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

size_t libwifi_add_action_detail(struct libwifi_action_detail *detail, const unsigned char *data,
                                 size_t data_len) {
    if (detail->detail_length != 0) {
        detail->detail = realloc(detail->detail, data_len + detail->detail_length);
    } else {
        detail->detail = malloc(data_len);
    }

    if (detail->detail == NULL) {
        return -EINVAL;
    }

    memcpy(detail->detail + detail->detail_length, data, data_len);
    detail->detail_length += data_len;

    return detail->detail_length;
}

void libwifi_free_action_detail(struct libwifi_action_detail *detail) {
    if (detail->detail_length != 0) {
        free(detail->detail);
        detail->detail_length = 0;
    }
}

int libwifi_create_action(struct libwifi_action *action,
                          const unsigned char receiver[6],
                          const unsigned char transmitter[6],
                          const unsigned char address3[6],
                          uint8_t category) {
    memset(action, 0, sizeof(struct libwifi_action));

    action->frame_header.frame_control.type = TYPE_MANAGEMENT;
    action->frame_header.frame_control.subtype = SUBTYPE_ACTION;
    memcpy(&action->frame_header.addr1, receiver, 6);
    memcpy(&action->frame_header.addr2, transmitter, 6);
    memcpy(&action->frame_header.addr3, address3, 6);
    action->fixed_parameters.category = category;

    return 0;
}

int libwifi_create_action_no_ack(struct libwifi_action *action,
                                 const unsigned char receiver[6],
                                 const unsigned char transmitter[6],
                                 const unsigned char address3[6],
                                 uint8_t category) {
    memset(action, 0, sizeof(struct libwifi_action));

    action->frame_header.frame_control.type = TYPE_MANAGEMENT;
    action->frame_header.frame_control.subtype = SUBTYPE_ACTION_NOACK;
    memcpy(&action->frame_header.addr1, receiver, 6);
    memcpy(&action->frame_header.addr2, transmitter, 6);
    memcpy(&action->frame_header.addr3, address3, 6);
    action->fixed_parameters.category = category;

    return 0;
}

size_t libwifi_get_action_length(struct libwifi_action *action) {
    return sizeof(struct libwifi_mgmt_unordered_frame_header) + sizeof(action->fixed_parameters.category) +
           action->fixed_parameters.details.detail_length;
}

size_t libwifi_dump_action(struct libwifi_action *action, unsigned char *buf, size_t buf_len) {
    size_t action_len = libwifi_get_action_length(action);
    if (action_len > buf_len) {
        return -EINVAL;
    }

    size_t offset = 0;

    memcpy(buf + offset, &action->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));
    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);

    memcpy(buf + offset, &action->fixed_parameters.category, sizeof(action->fixed_parameters.category));
    offset += sizeof(action->fixed_parameters.category);
    
    memcpy(buf + offset, action->fixed_parameters.details.detail,
           action->fixed_parameters.details.detail_length);
    offset += action->fixed_parameters.details.detail_length;

    return action_len;
}

void libwifi_free_action(struct libwifi_action *action) {
    free(action->fixed_parameters.details.detail);
}
