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

#ifndef LIBWIFI_PARSE_EAPOL_H
#define LIBWIFI_PARSE_EAPOL_H

#include "../../core/frame/frame.h"
#include "../../core/misc/security.h"

enum WPA_HANDSHAKE_PART {
    HANDSHAKE_M1 = 1,
    HANDSHAKE_M2 = 2,
    HANDSHAKE_M3 = 4,
    HANDSHAKE_M4 = 8,
    HANDSHAKE_INVALID = 16
};

/**
 * Check if a libwifi_frame contains a WPA1/2 handshake message.
 *
 * @param libwifi_frame A libwifi_frame
 * @return 1 if a handshake is detected, 0 if not.
 */
int libwifi_check_wpa_handshake(struct libwifi_frame *frame);

/**
 * Check what message of the WPA1/2 handshake is in the given frame.
 *
 * The returned value can be used with the WPA_HANDSHAKE_PART enum,
 * such as:
 *
 * part = libwifi_check_wpa_message(frame);
 * if (part & HANDSHAKE_M1) {
 *     // This is EAPOL Message 1
 * }
 *
 * @param libwifi_frame A libwifi_frame
 * @return A bitmask of parts.
 */
int libwifi_check_wpa_message(struct libwifi_frame *frame);

/**
 * Get a string describing the WPA handshake message inside a supplied libwifi_frame.
 *
 * @param libwifi_frame A libwifi_frame
 * @return A string describing the WPA handshake message found
 */
const char *libwifi_get_wpa_message_string(struct libwifi_frame *frame);

/**
 * Get the length of the key data, if any, present at the end of an EAPOL frame.
 *
 * @param libwifi_frame A libwifi_frame
 * @return The length of the key data
 */
int libwifi_get_wpa_key_data_length(struct libwifi_frame *frame);

/**
 * Get the EAPOL/WPA information from a given libwifi_frame.
 *
 * As the values in the frame below and including the logical link control layer will be in
 * network byte order, the values will be automatically byte swapped if necessary to match
 * the host systems byte order.
 *
 * @param libwifi_frame A libwifi_frame
 * @param data A pointer to a libwifi_wpa_auth_data struct
 * @return 0 on success, -1 on failure
 */
int libwifi_get_wpa_data(struct libwifi_frame *frame, struct libwifi_wpa_auth_data *data);

/**
 * Free any memory allocated inside of a libwifi_wpa_auth data, such as a buffer
 * for WPA key data allocated by the library.
 *
 * @param data A pointer to a libwifi_wpa_auth_data struct
 */
void libwifi_free_wpa_data(struct libwifi_wpa_auth_data *data);

#endif /* LIBWIFI_PARSE_EAPOL_H */
