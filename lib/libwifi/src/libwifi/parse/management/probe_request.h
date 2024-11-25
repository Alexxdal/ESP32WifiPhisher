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

#ifndef LIBWIFI_PARSE_PROBEREQ_H
#define LIBWIFI_PARSE_PROBEREQ_H

#include "../../core/frame/frame.h"
#include "../../core/frame/management/common.h"
#include "../../core/frame/management/probe_request.h"

/**
 * Parse a probe request into a libwifi_sta.
 *
 * @param sta A libwifi_sta
 * @param frame A libwifi_frame
 * @return 0 if successful, a negative number if not
 */
int libwifi_parse_probe_req(struct libwifi_sta *sta, struct libwifi_frame *frame);

#endif /* LIBWIFI_PARSE_PROBEREQ_H */
