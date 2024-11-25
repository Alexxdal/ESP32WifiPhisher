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

#ifndef LIBWIFI_GEN_COMMON_H
#define LIBWIFI_GEN_COMMON_H

/**
 * A sane default for an AP-side capabilities information field.
 *
 * 0x0001 = Transmitter is an AP
 */
#define LIBWIFI_DEFAULT_AP_CAPABS 0x0001

/**
 * A sane default for an STA-side capabilities information field.
 *
 * 0x0000 = None
 */
#define LIBWIFI_DEFAULT_STA_CAPABS 0x0000

/**
 * A sane default for the listen_interval field.
 *
 * 0x0001 = 1 Beacon Interval
 */
#define LIBWIFI_DEFAULT_LISTEN_INTERVAL 0x0001

/**
 * A sane default for a beacon_interval field.
 *
 * 0x0064 = 0.1024 Seconds
 */
#define LIBWIFI_DEFAULT_BEACON_INTERVAL 0x0064

/**
 * A sane default for the supported rates frame field.
 *
 * 1, 2, 5.5, 11, 18, 24, 36, 54 Mbit/s
 */
#define LIBWIFI_DEFAULT_SUPP_RATES "\x82\x84\x8b\x96\x24\x30\x48\x6c"

#endif /* LIBWIFI_GEN_COMMON_H */
