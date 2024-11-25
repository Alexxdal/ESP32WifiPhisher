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

#ifndef LIBWIFI_PARSE_ASSOCRESP_H
#define LIBWIFI_PARSE_ASSOCRESP_H

#include <stdint.h>
#include <sys/types.h>

#include "../../core/frame/frame.h"
#include "../../core/frame/management/common.h"
#include "../../core/misc/security.h"

/**
 * Parse an association response frame into a libwifi_bss.
 *
 * @param bss A libwifi_bss
 * @param frame A libwifi_frame
 * @return 0 if successful, a negative number if not.
 */
int libwifi_parse_assoc_resp(struct libwifi_bss *bss, struct libwifi_frame *frame);

#endif /* LIBWIFI_PARSE_ASSOCRESP_H */
