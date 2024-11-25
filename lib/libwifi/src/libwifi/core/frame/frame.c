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

#include "frame.h"
#include "../../parse/misc/radiotap.h"
#include "../misc/byteswap.h"
#include "../radiotap/radiotap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
 * Turn sniffed data into a libwifi_frame struct for use with other libwifi functions.
 *
 * Supported frames:
 *  - Management Frames (Ordered)
 *  - Management Frames (Unordered)
 *  - Data Frames
 *  - QoS Data Frames
 *  - Control Frames
 */
int libwifi_get_wifi_frame(struct libwifi_frame *fi, const unsigned char *frame, size_t frame_len, int radiotap) {
    union libwifi_frame_header fh = {0};
    size_t header_len = 0;
    size_t frame_data_len = frame_len;
    const unsigned char *frame_data = frame;

    memset(fi, 0, sizeof(struct libwifi_frame));

    if (radiotap) {
        struct libwifi_radiotap_info rtap_info = {0};
        int ret = libwifi_parse_radiotap_info(&rtap_info, frame, frame_len);
        if (ret != 0) {
            return ret;
        }

        // Skip forward by the length of the radiotap header
        frame_data_len -= rtap_info.length;
        frame_data += rtap_info.length;

        // Remove the FCS from the end of the frame data, if present
        if (rtap_info.flags & IEEE80211_RADIOTAP_F_FCS) {
            fi->flags |= LIBWIFI_FLAGS_FCS_PRESENT;
            frame_data_len -= sizeof(uint32_t); // FCS is 4 bytes wide
        }

        fi->flags |= LIBWIFI_FLAGS_RADIOTAP_PRESENT;
        fi->radiotap_info = malloc(sizeof(struct libwifi_radiotap_info));
        memcpy(fi->radiotap_info, &rtap_info, sizeof(struct libwifi_radiotap_info));
    }

    struct libwifi_frame_ctrl *frame_control = (struct libwifi_frame_ctrl *) frame_data;

    switch (frame_control->type) {
        case TYPE_DATA:
            switch (frame_control->subtype) {
                case SUBTYPE_DATA_QOS_DATA:
                case SUBTYPE_DATA_QOS_NULL:
                case SUBTYPE_DATA_QOS_DATA_CF_ACK:
                case SUBTYPE_DATA_QOS_DATA_CF_ACK_CF_POLL:
                case SUBTYPE_DATA_QOS_DATA_CF_POLL:
                case SUBTYPE_DATA_QOS_CF_ACK_CF_POLL:
                case SUBTYPE_DATA_QOS_CF_POLL:
                    fi->flags |= LIBWIFI_FLAGS_IS_QOS;
                    break;
            }

            if (fi->flags & LIBWIFI_FLAGS_IS_QOS) {
                header_len = sizeof(struct libwifi_data_qos_frame_header);
            } else {
                header_len = sizeof(struct libwifi_data_frame_header);
            }

            if (frame_data_len < header_len) {
                return -EINVAL;
            }

            if (fi->flags & LIBWIFI_FLAGS_IS_QOS) {
                memset(&fh.data_qos, 0, sizeof(struct libwifi_data_qos_frame_header));
                memcpy(&fh.data_qos, frame_data, sizeof(struct libwifi_data_qos_frame_header));
            } else {
                memset(&fh.data, 0, sizeof(struct libwifi_data_frame_header));
                memcpy(&fh.data, frame_data, sizeof(struct libwifi_data_frame_header));
            }
            break;
        case TYPE_MANAGEMENT:
            if (frame_control->flags.ordered) {
                fi->flags |= LIBWIFI_FLAGS_IS_ORDERED;
                header_len = sizeof(struct libwifi_mgmt_ordered_frame_header);
                if (frame_data_len < header_len) {
                    return -EINVAL;
                }
                memcpy(&fh.mgmt_ordered, frame_data, header_len);
            } else {
                header_len = sizeof(struct libwifi_mgmt_unordered_frame_header);
                if (frame_data_len < header_len) {
                    return -EINVAL;
                }
                memcpy(&fh.mgmt_unordered, frame_data, header_len);
            }
            break;
        case TYPE_CONTROL:
            header_len = sizeof(struct libwifi_ctrl_frame_header);
            if (frame_data_len < header_len) {
                return -EINVAL;
            }
            memcpy(&fh.ctrl, frame_data, sizeof(struct libwifi_ctrl_frame_header));
            break;
        default:
            return -EINVAL;
    }

    fi->len = frame_data_len;
    fi->header = fh;
    fi->header_len = header_len;
    memcpy(&fi->frame_control, frame_control, sizeof(struct libwifi_frame_ctrl));

    size_t body_len = fi->len - fi->header_len;
    if (body_len > 0) {
        fi->body = malloc(body_len);
        if (fi->body == NULL) {
            return -ENOMEM;
        }
        memcpy(fi->body, frame_data + header_len, body_len);
    }

    return 0;
}

void libwifi_free_wifi_frame(struct libwifi_frame *fi) {
    free(fi->radiotap_info);
    free(fi->body);
}
