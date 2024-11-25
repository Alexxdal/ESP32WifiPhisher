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
#include "../../core/radiotap/radiotap_iter.h"

#include <errno.h>
#include <stdint.h>

#if !(__APPLE__)
#include <endian.h>
#endif

/**
 * The libwifi radiotap parser uses the usual ieee80211_radiotap_iterator to parse incoming
 * radiotap headers into a consumable libwifi_radiotap_info struct.
 */
int libwifi_parse_radiotap_info(struct libwifi_radiotap_info *info, const unsigned char *frame,
                                size_t frame_len) {
    memset(info, 0, sizeof(struct libwifi_radiotap_info));

    if (frame_len < sizeof(struct ieee80211_radiotap_header)) {
        return -EINVAL;
    }

    struct ieee80211_radiotap_header *rh = (struct ieee80211_radiotap_header *) frame;
    struct ieee80211_radiotap_iterator it = {0};
    int ret = ieee80211_radiotap_iterator_init(&it, (void *) frame, rh->it_len, NULL);

    int skipped_antenna = 0;
    info->length = rh->it_len;

    while (!ret) {
        switch (it.this_arg_index) {
            case IEEE80211_RADIOTAP_CHANNEL:
                info->channel.freq = le16toh(*(uint16_t *) it.this_arg);
                info->channel.flags = le16toh(*(uint16_t *) (it.this_arg + 2));

                // Handle band and channel
                if (info->channel.freq >= 2412 && info->channel.freq <= 2484) {
                    info->channel.band |= LIBWIFI_RADIOTAP_BAND_2GHZ;
                    if (info->channel.freq == 2484) {
                        info->channel.center = 14;
                    } else {
                        info->channel.center = (info->channel.freq - 2407) / 5;
                    }
                } else if (info->channel.freq >= 5160 && info->channel.freq <= 5885) {
                    info->channel.band |= LIBWIFI_RADIOTAP_BAND_5GHZ;
                    info->channel.center = (info->channel.freq - 5000) / 5;
                } else if (info->channel.freq >= 5955 && info->channel.freq <= 7115) {
                    info->channel.band |= LIBWIFI_RADIOTAP_BAND_6GHZ;
                    info->channel.center = (info->channel.freq - 5950) / 5;
                }

                break;
            case IEEE80211_RADIOTAP_RATE:
                info->rate_raw = *it.this_arg;
                info->rate = (*it.this_arg / 2.0);
                break;
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                // Radiotap Headers will include the ANTSIGNAL without an explicit Antenna definition.
                if (!skipped_antenna) {
                    info->signal = *it.this_arg;
                    skipped_antenna = 1;
                    break;
                }

                if (info->antenna_count < LIBWIFI_MAX_RADIOTAP_ANTENNAS) {
                    struct libwifi_radiotap_antenna antenna = {.antenna_number = info->antenna_count,
                                                               .signal = *it.this_arg};
                    info->antennas[info->antenna_count] = antenna;
                    info->antenna_count += 1;
                }
                break;
            case IEEE80211_RADIOTAP_ANTENNA:
                info->antennas[info->antenna_count - 1].antenna_number = *it.this_arg;
                break;
            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                break;
            case IEEE80211_RADIOTAP_FLAGS:
                info->flags = *it.this_arg;
                break;
            case IEEE80211_RADIOTAP_EXT:
                info->extended_flags = *it.this_arg;
                break;
            case IEEE80211_RADIOTAP_RX_FLAGS:
                info->rx_flags = *it.this_arg;
                break;
            case IEEE80211_RADIOTAP_TX_FLAGS:
                info->tx_flags = *it.this_arg;
                break;
            case IEEE80211_RADIOTAP_MCS:
                info->mcs.known = *(uint8_t *) it.this_arg;
                info->mcs.flags = *(uint8_t *) (it.this_arg + 2);
                info->mcs.mcs = *(uint8_t *) (it.this_arg + 3);
                break;
            case IEEE80211_RADIOTAP_DBM_TX_POWER:
                info->tx_power = *it.this_arg;
                break;
            case IEEE80211_RADIOTAP_TIMESTAMP:
                info->timestamp.timestamp = le64toh(*(uint64_t *) it.this_arg);
                info->timestamp.accuracy = le16toh(*(uint16_t *) (it.this_arg + 2));
                info->timestamp.unit = *(uint8_t *) (it.this_arg + 3);
                info->timestamp.flags = *(uint8_t *) (it.this_arg + 4);
                break;
            case IEEE80211_RADIOTAP_RTS_RETRIES:
                info->rts_retries = *it.this_arg;
                break;
            case IEEE80211_RADIOTAP_DATA_RETRIES:
                info->data_retries = *it.this_arg;
                break;
        }

        ret = ieee80211_radiotap_iterator_next(&it);
    }

    return 0;
}

/**
 * A simpler function than the main libwifi_parse_radiotap_info function, designed to extract
 * only the signal strength field.
 */
int8_t libwifi_parse_radiotap_rssi(const unsigned char *frame) {
    struct ieee80211_radiotap_header *rh = (struct ieee80211_radiotap_header *) frame;

    int8_t rssi = 0;

    struct ieee80211_radiotap_iterator it;
    int ret = ieee80211_radiotap_iterator_init(&it, (void *) frame, rh->it_len, NULL);

    while (!ret) {
        if (it.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
            rssi = *it.this_arg;
            break;
        }

        ret = ieee80211_radiotap_iterator_next(&it);
    }

    return rssi;
}
