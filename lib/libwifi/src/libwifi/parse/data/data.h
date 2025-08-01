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

#ifndef LIBWIFI_PARSE_DATA_H
#define LIBWIFI_PARSE_DATA_H

#include "../../core/frame/data/data.h"
#include "../../core/frame/frame.h"

int libwifi_parse_data(struct libwifi_data *data, struct libwifi_frame *frame);

void libwifi_free_data(struct libwifi_data *data);

#endif /* LIBWIFI_PARSE_DATA_H */
