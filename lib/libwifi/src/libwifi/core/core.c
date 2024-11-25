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

#include "core.h"
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

/**
 * Random MAC addresses, achieved by obtaining 6 bytes of /dev/urandom via getrandom()
 */
void libwifi_random_mac(unsigned char buf[6], unsigned char prefix[3]) {
    memset(buf, 0, 6);
    if (prefix != NULL) {
        memcpy(buf, prefix, 3);
#if __APPLE__
        arc4random_buf(buf + 3, 3);
#else
        getrandom(buf + 3, 3, 0);
#endif /* __APPLE__ */
    } else {
#if __APPLE__
        arc4random_buf(buf, 6);
#else
        getrandom(buf, 6, 0);
#endif /* __APPLE__ */
    }
}

/**
 * Dummy linker test function
 */
void libwifi_dummy(void) {
    return;
}

/**
 * Version
 */
const char *libwifi_get_version(void) {
    return LIBWIFI_VERSION;
}
