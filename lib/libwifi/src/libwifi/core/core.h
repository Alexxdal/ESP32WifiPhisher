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

#ifndef LIBWIFI_CORE_H
#define LIBWIFI_CORE_H

#ifndef LIBWIFI_VERSION
#define LIBWIFI_VERSION "UNSET_VERSION"
#endif

/**
 * Commonly used fixed fields
 */
#define LIBWIFI_BCAST_MAC "\xFF\xFF\xFF\xFF\xFF\xFF"
#define LIBWIFI_ZERO_MAC "\x00\x00\x00\x00\x00\x00"

/**
 * Helpers for MAC Addresses
 */
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

/**
 * Function to randomly generate a MAC address.
 *
 * @param buf A buffer for the generated MAC to be written to
 * @param prefix An optional OUI prefix
 */
void libwifi_random_mac(unsigned char buf[6], unsigned char prefix[3]);

/**
 * Dummy function for linker testing purposes.
 */
void libwifi_dummy(void);

/**
 * Obtain the version of libwifi.
 *
 * @return The version of the installed libwifi.
 */
const char *libwifi_get_version(void);

#endif /* LIBWIFI_CORE_H */
