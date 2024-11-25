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

#include "tag_iterator.h"

#include <errno.h>
#include <string.h>

int libwifi_tag_iterator_init(struct libwifi_tag_iterator *it, const void *tags_start, size_t data_len) {
    if (data_len <= 0) {
        return -EINVAL;
    }

    it->tag_header = (struct libwifi_tag_header *) tags_start;
    it->tag_data = (unsigned char *) tags_start + sizeof(struct libwifi_tag_header);
    it->_next_tag_header = (struct libwifi_tag_header *) (it->tag_data + it->tag_header->tag_len);
    it->_frame_end = (unsigned char *) (tags_start) + data_len - 1;

    return 0;
}

int libwifi_tag_iterator_next(struct libwifi_tag_iterator *it) {
    unsigned char *next_th = (unsigned char *) it->_next_tag_header;
    if (next_th >= it->_frame_end) {
        return -1;
    }

    it->tag_header = it->_next_tag_header;
    if (it->tag_header->tag_len <= 0) {
        return -1;
    }

    unsigned long bytes_left = (char *) it->_frame_end - (char *) it->tag_header;
    if (it->tag_header->tag_len >= bytes_left) {
        return -1;
    }

    it->tag_data = ((unsigned char *) (it->tag_header)) + sizeof(struct libwifi_tag_header);
    it->_next_tag_header = (struct libwifi_tag_header *) (it->tag_data + it->tag_header->tag_len);

    return it->tag_header->tag_num;
}
