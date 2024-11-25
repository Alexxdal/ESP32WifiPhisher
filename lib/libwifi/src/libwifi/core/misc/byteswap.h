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

#ifndef LIBWIFI_CORE_BYTESWAP_H
#define LIBWIFI_CORE_BYTESWAP_H

#if __APPLE__
#include <libkern/OSByteOrder.h>

#define BYTESWAP16(x) OSSwapInt16(x)
#define BYTESWAP32(x) OSSwapInt32(x)
#define BYTESWAP64(x) OSSwapInt64(x)

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#else
#include "byteswap.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BYTESWAP16(x) x
#define BYTESWAP32(x) x
#define BYTESWAP64(x) x
#else
#define BYTESWAP16(x) (__bswap_16(x))
#define BYTESWAP32(x) (__bswap_32(x))
#define BYTESWAP64(x) (__bswap_32(x))
#endif /* __BYTE_ORDER__ */
#endif /* __APPLE__ */

#endif /* LIBWIFI_CORE_BYTESWAP_H */
