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

#include "radiotap.h"
#include "../../core/radiotap/radiotap.h"
#include "../../core/radiotap/radiotap_iter.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LIBWIFI_RADIOTAP_HEADER_LEN 8

size_t libwifi_create_radiotap(struct libwifi_radiotap_info *info, char *radiotap_header) {
    struct ieee80211_radiotap_header rtap_hdr = {0};
    rtap_hdr.it_version = 0;
    rtap_hdr.it_pad = 0;
    rtap_hdr.it_present = info->present;
    rtap_hdr.it_len = sizeof(struct ieee80211_radiotap_header);

    char rtap_data[LIBWIFI_MAX_RADIOTAP_LEN - LIBWIFI_RADIOTAP_HEADER_LEN] = {0};
    int offset = 0;

    uint32_t presence_bit = rtap_hdr.it_present;
    for (int field = 0; field < radiotap_ns.n_bits; field++) {
        if (presence_bit & 1) {
            uint8_t padding = offset % radiotap_ns.align_size[field].align;
            if (padding > 0) {
                memset(rtap_data + offset, 0, padding);
                offset += padding;
            }
            switch (field) {
                case IEEE80211_RADIOTAP_CHANNEL:
                    memcpy(rtap_data + offset, &info->channel.freq, sizeof(info->channel.freq));
                    offset += sizeof(info->channel.freq);
                    memcpy(rtap_data + offset, &info->channel.flags, sizeof(info->channel.flags));
                    offset += sizeof(info->channel.flags);
                    break;
                case IEEE80211_RADIOTAP_RATE:
                    memcpy(rtap_data + offset, &info->rate_raw, sizeof(info->rate_raw));
                    offset += sizeof(info->rate_raw);
                    break;
                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                    memcpy(rtap_data + offset, &info->signal, sizeof(info->signal));
                    offset += sizeof(info->signal);
                    break;
                case IEEE80211_RADIOTAP_ANTENNA:
                    for (int i = 0; i < info->antenna_count; i++) {
                        memcpy(rtap_data + offset, &info->antennas->antenna_number,
                               sizeof(info->antennas->antenna_number));
                        offset += sizeof(info->antennas->antenna_number);
                        memcpy(rtap_data + offset, &info->antennas->signal, sizeof(info->antennas->signal));
                        offset += sizeof(info->antennas->signal);
                    }
                    break;
                case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                    break;
                case IEEE80211_RADIOTAP_FLAGS:
                    memcpy(rtap_data + offset, &info->flags, sizeof(info->flags));
                    offset += sizeof(info->flags);
                    break;
                case IEEE80211_RADIOTAP_EXT:
                    memcpy(rtap_data + offset, &info->extended_flags, sizeof(info->extended_flags));
                    offset += sizeof(info->extended_flags);
                    break;
                case IEEE80211_RADIOTAP_RX_FLAGS:
                    memcpy(rtap_data + offset, &info->rx_flags, sizeof(info->rx_flags));
                    offset += sizeof(info->rx_flags);
                    break;
                case IEEE80211_RADIOTAP_TX_FLAGS:
                    memcpy(rtap_data + offset, &info->tx_flags, sizeof(info->tx_flags));
                    offset += sizeof(info->tx_flags);
                    break;
                case IEEE80211_RADIOTAP_MCS:
                    memcpy(rtap_data + offset, &info->mcs.known, sizeof(info->mcs.known));
                    offset += sizeof(info->mcs.known);
                    memcpy(rtap_data + offset, &info->mcs.flags, sizeof(info->mcs.flags));
                    offset += sizeof(info->mcs.flags);
                    memcpy(rtap_data + offset, &info->mcs.mcs, sizeof(info->mcs.mcs));
                    offset += sizeof(info->mcs.mcs);
                    break;
                case IEEE80211_RADIOTAP_DBM_TX_POWER:
                    memcpy(rtap_data + offset, &info->tx_power, sizeof(info->tx_power));
                    offset += sizeof(info->tx_power);
                    break;
                case IEEE80211_RADIOTAP_TIMESTAMP:
                    memcpy(rtap_data + offset, &info->timestamp.timestamp, sizeof(info->timestamp.timestamp));
                    offset += sizeof(info->timestamp.timestamp);
                    memcpy(rtap_data + offset, &info->timestamp.accuracy, sizeof(info->timestamp.accuracy));
                    offset += sizeof(info->timestamp.accuracy);
                    memcpy(rtap_data + offset, &info->timestamp.unit, sizeof(info->timestamp.unit));
                    offset += sizeof(info->timestamp.unit);
                    memcpy(rtap_data + offset, &info->timestamp.flags, sizeof(info->timestamp.flags));
                    offset += sizeof(info->timestamp.flags);
                    break;
                case IEEE80211_RADIOTAP_RTS_RETRIES:
                    memcpy(rtap_data + offset, &info->rts_retries, sizeof(info->rts_retries));
                    offset += sizeof(info->rts_retries);
                    break;
                case IEEE80211_RADIOTAP_DATA_RETRIES:
                    memcpy(rtap_data + offset, &info->data_retries, sizeof(info->data_retries));
                    offset += sizeof(info->data_retries);
                    break;
            }
        }

        presence_bit >>= 1;
    }

    rtap_hdr.it_len += offset;

    memcpy(radiotap_header, &rtap_hdr, sizeof(struct ieee80211_radiotap_header));
    memcpy(radiotap_header + sizeof(struct ieee80211_radiotap_header), &rtap_data, offset);

    return rtap_hdr.it_len;
}
