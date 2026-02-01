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

#include "eapol.h"
#include "../../core/frame/frame.h"
#include "../../core/misc/byteswap.h"
#include "../../core/misc/llc.h"
#include "../../core/misc/security.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "endian.h"
#endif

/**
 * A libwifi_frame is deemed to be an EAPOL handshake if the following criteria is met:
 * - The frame is of type TYPE_DATA, and
 * - The frame contains a logical link control layer, and
 * - There is enough data in the frame body to fill a libwifi_wpa_auth_data struct.
 */
int libwifi_check_wpa_handshake(struct libwifi_frame *frame) {
    // WPA Handshakes are transmitted in EAPOL frames
    if (frame->frame_control.type != TYPE_DATA) {
        return -EINVAL;
    }

    // Data frame must be at least the length of the header plus the encapsulating LLC
    if (frame->len < (frame->header_len + sizeof(struct libwifi_logical_link_ctrl))) {
        return -EINVAL;
    }

    // Represent the LLC layer so that we can check the OUI and ensure it is correct
    struct libwifi_logical_link_ctrl *llc = (struct libwifi_logical_link_ctrl *) (frame->body);
    if (memcmp(llc->oui, XEROX_OUI, sizeof(llc->oui)) != 0) {
        return -EINVAL;
    }

    // Match the network byte-order of LLC and ensure we have a frame containing 802.1X information
    if (ntohs(llc->type) != LLC_TYPE_AUTH) {
        return -EINVAL;
    }

    // Ensure we have enough information in the frame to fill a libwifi_wpa_auth_data struct
    // This value is calculated by ensuring the frame is at least the length of the LLC layer, plus the length
    // of the libwifi_wpa_auth_data struct, however, the length of an unsigned char pointer is subtracted due
    // to the possibility of the frame having no WPA key data.
    size_t required_data_length =
        frame->header_len + (sizeof(struct libwifi_logical_link_ctrl) +
                             (sizeof(struct libwifi_wpa_auth_data) - sizeof(unsigned char *)));
    if (frame->len < required_data_length) {
        return -EINVAL;
    }

    return 1;
}

/*
 * The specific EAPOL message in the supplied libwifi_frame is determined via the 802.1X key information
 * field.
 */
int libwifi_check_wpa_message(struct libwifi_frame *frame) {
    // Ensure we have enough information in the frame to fill a libwifi_wpa_auth_data struct
    // This value is calculated by ensuring the frame is at least the length of the LLC layer, plus the length
    // of the libwifi_wpa_auth_data struct, however, the length of an unsigned char pointer is subtracted due
    // to the possibility of the frame having no WPA key data.
    size_t required_data_length =
        frame->header_len + (sizeof(struct libwifi_logical_link_ctrl) +
                             (sizeof(struct libwifi_wpa_auth_data) - sizeof(unsigned char *)));
    if (frame->len < required_data_length) {
        return HANDSHAKE_INVALID;
    }

    struct libwifi_wpa_auth_data *auth_data =
        (struct libwifi_wpa_auth_data *) (frame->body + sizeof(struct libwifi_logical_link_ctrl));
    switch (ntohs(auth_data->key_info.information)) {
        case EAPOL_KEY_INFO_M1:
            return HANDSHAKE_M1;
        case EAPOL_KEY_INFO_M2:
            return HANDSHAKE_M2;
        case EAPOL_KEY_INFO_M3:
            return HANDSHAKE_M3;
        case EAPOL_KEY_INFO_M4:
            return HANDSHAKE_M4;
        default:
            return HANDSHAKE_INVALID;
    }
}

/*
 * Simple helper function to print a string depending on the EAPOL message
 */
const char *libwifi_get_wpa_message_string(struct libwifi_frame *frame) {
    int message = libwifi_check_wpa_message(frame);

    switch (message) {
        case HANDSHAKE_M1:
            return "Message 1";
        case HANDSHAKE_M2:
            return "Message 2";
        case HANDSHAKE_M3:
            return "Message 3";
        case HANDSHAKE_M4:
            return "Message 4";
        case HANDSHAKE_INVALID:
        default:
            return "Invalid";
    }
}

/*
 * The value returned here is the length of the data available _after_ the rest of the EAPOL data,
 * and should be used for obtaining the EAPOL Key Data, if present.
 */
int libwifi_get_wpa_key_data_length(struct libwifi_frame *frame) {
    if (libwifi_check_wpa_handshake(frame) < 0) {
        return -EINVAL;
    }

    struct libwifi_wpa_auth_data *auth_data =
        (struct libwifi_wpa_auth_data *) (frame->body + sizeof(struct libwifi_logical_link_ctrl));

    // Byte-swap the multi-byte length key_data_length for the host system
    return ntohs(auth_data->key_info.key_data_length);
}

/*
 * Data in the supplied libwifi_frame is expected to be in network byte order. To avoid confusion, this
 * data is byte-swapped to the host system's endianess.
 *
 * If the supplied key_data is not NULL, any key data at the end of the frame will be written into the
 * supplied key_data buffer. You can obtain the length to malloc such a buffer with
 * libwifi_get_wpa_key_data_length.
 */
int libwifi_get_wpa_data(struct libwifi_frame *frame, struct libwifi_wpa_auth_data *data) {
    memset(data, 0, sizeof(struct libwifi_wpa_auth_data));

    if (libwifi_check_wpa_handshake(frame) < 0) {
        return -EINVAL;
    }

    struct libwifi_wpa_auth_data *auth_data =
        (struct libwifi_wpa_auth_data *) (frame->body + sizeof(struct libwifi_logical_link_ctrl));

    // Multi-byte fields will be byte-swapped to the host byte order
    data->version = auth_data->version;
    data->type = auth_data->type;
    data->length = ntohs(auth_data->length);
    data->descriptor = auth_data->descriptor;
    memcpy(&data->key_info, &auth_data->key_info, sizeof(struct libwifi_wpa_key_info));
    data->key_info.information = ntohs(auth_data->key_info.information);
    data->key_info.key_length = ntohs(auth_data->key_info.key_length);
    data->key_info.replay_counter = be64toh(auth_data->key_info.replay_counter);
    data->key_info.key_data_length = ntohs(auth_data->key_info.key_data_length);

    if (data->key_info.key_data_length > 0) {
        // Prevent huge allocations in corrupted or malicious frames
        if (data->key_info.key_data_length > 1024) {
            data->key_info.key_data_length = 1024;
        }

        data->key_info.key_data = malloc(data->key_info.key_data_length);
        if (data->key_info.key_data == NULL) {
            return -ENOMEM;
        }
        size_t key_data_offset = sizeof(struct libwifi_logical_link_ctrl) +
                                 sizeof(struct libwifi_wpa_auth_data) - sizeof(unsigned char *);
        memcpy(data->key_info.key_data, frame->body + key_data_offset, data->key_info.key_data_length);
    }

    return 0;
}

void libwifi_free_wpa_data(struct libwifi_wpa_auth_data *data) {
    if (data->key_info.key_data_length > 0) {
        free(data->key_info.key_data);
    }
}
