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

#ifndef LIBWIFI_CORE_TAGITERATOR_H
#define LIBWIFI_CORE_TAGITERATOR_H

#include "../misc/byteswap.h"
#include "frame.h"
#include "tag.h"
#include <stddef.h>

/**
 * A libwifi_tag_iterator is used to iterate through a list of tagged parameters
 * in a wifi frame.
 */
struct libwifi_tag_iterator {
    struct libwifi_tag_header *tag_header;
    const unsigned char *tag_data;
    struct libwifi_tag_header *_next_tag_header;
    const unsigned char *_frame_end;
};

/**
 * Initialise a libwifi frame tag iterator.
 *
 * @param it         A libwifi tag iterator struct
 * @param tags_start The beginning of a frame's tag data
 * @param data_len   The total length of the frame's tag data
 * @return negative number on error, zero on success
 */
int libwifi_tag_iterator_init(struct libwifi_tag_iterator *it, const void *tags_start, size_t data_len);

/**
 * Iterate towards the next tagged parameter in a libwifi tag iterator.
 *
 * @param A libwifi tag iterator sturct, after being initalised
 * @return The tag number of the next tag
 */
int libwifi_tag_iterator_next(struct libwifi_tag_iterator *it);

#endif /* LIBWIFI_CORE_TAGITERATOR_H */
