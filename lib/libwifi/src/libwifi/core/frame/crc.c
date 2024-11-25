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

#include "crc.h"
#include "../misc/byteswap.h"

#include <stdint.h>
#include <sys/types.h>

/*
 * Basic CRC32 implementation for getting the frame check sum of
 * a supplied message, usually frame data.
 */
uint32_t libwifi_crc32(const unsigned char *message, int message_len) {
    int i, j;
    unsigned int byte, crc, mask;
    i = 0;
    crc = 0xFFFFFFFF;
    while (i < message_len) {
        byte = message[i];
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        i = i + 1;
    }
    return ~crc;
}

/*
 * Specific function for calculating a frame FCS, byteswapped for the
 * host endianess.
 */
uint32_t libwifi_calculate_fcs(const unsigned char *frame, size_t frame_len) {
    return BYTESWAP32(libwifi_crc32(frame, frame_len));
}

/*
 * Verify a raw frame containing a FCS at the end to the FCS calculated
 * by libwifi.
 */
int libwifi_frame_verify(void *frame, size_t frame_len) {
    // A frame with a CRC will have the CRC placed at the end, and is 4 bytes long.
    uint32_t oCRC = *((uint32_t *) ((char *) frame + (frame_len - 4)));
    uint32_t rCRC = libwifi_calculate_fcs(frame, frame_len);

    if (rCRC == oCRC) {
        return 1;
    }

    return 0;
}
