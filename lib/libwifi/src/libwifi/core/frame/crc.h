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

#ifndef LIBWIFI_CORE_CRC_H
#define LIBWIFI_CORE_CRC_H

#include <stdint.h>
#include <sys/types.h>

/**
 * Calculate the CRC32 sum of a given buffer.
 *
 * @param message Buffer of data
 * @param message_len Length of the data buffer
 * @return CRC32 sum of the given buffer
 */
uint32_t libwifi_crc32(const unsigned char *message, int message_len);

/**
 * Calculate the frame checksum for an 802.11 frame.
 *
 * @param frame An 802.11 frame
 * @param frame_len Length of the frame
 * @return frame checksum of the frame
 */
uint32_t libwifi_calculate_fcs(const unsigned char *frame, size_t frame_len);

/**
 * Check if the given raw 802.11 frame has a valid FCS.
 *
 * This function relies on an assumption that the last 4 bytes of the supplied
 * frame is the CRC, as stated in the Radiotap specification.
 *
 * You can check if the frame data has this field by using libwifi_get_wifi_frame()
 * and then checking if the libwifi_frame's flags has the LIBWIFI_FLAGS_FCS_PRESENT
 * bit set.
 *
 * @param frame An 802.11 frame with an FCS
 * @param frame_len Length of the frame
 * @return 1 if verified, 0 if not
 */
int libwifi_frame_verify(void *frame, size_t frame_len);

#endif /* LIBWIFI_CORE_CRC_H */
