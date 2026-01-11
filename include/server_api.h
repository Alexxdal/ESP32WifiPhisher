#ifndef _SERVER_API_H_
#define _SERVER_API_H_

#include "esp_err.h"

/**
 * @brief Get MIME type from file path
 */
const char* mime_from_path(const char* path);

/**
 * @brief Register server API handlers
 */
esp_err_t register_server_api_handlers(httpd_handle_t server);


#endif /* _SERVER_API_H_ */