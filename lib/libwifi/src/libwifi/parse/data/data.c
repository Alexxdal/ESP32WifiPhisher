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

#include "data.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int libwifi_parse_data(struct libwifi_data *data, struct libwifi_frame *frame) {
    if (frame->frame_control.type != TYPE_DATA) {
        return -EINVAL;
    }

    if (frame->flags & LIBWIFI_FLAGS_IS_QOS) {
        memcpy(data->receiver, frame->header.data_qos.addr1, 6);
        memcpy(data->transmitter, frame->header.data_qos.addr2, 6);
    } else {
        memcpy(data->receiver, frame->header.data.addr1, 6);
        memcpy(data->transmitter, frame->header.data.addr2, 6);
    }

    data->body_len = frame->len - frame->header_len;

    data->body = malloc(data->body_len);
    if (data->body == NULL) {
        return -ENOMEM;
    }
    memcpy(data->body, frame->body, data->body_len);

    return 0;
}

void libwifi_free_data(struct libwifi_data *data) {
    free(data->body);
}
