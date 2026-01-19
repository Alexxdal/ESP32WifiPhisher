#ifndef _SERVER_API_H_
#define _SERVER_API_H_

#include <esp_err.h>
#include <esp_http_server.h>

typedef enum {
    API_GET_STATUS = 0,
    API_SET_AP_SETTINGS,
    API_GET_AP_SETTINGS,
    API_WIFI_SCAN,
    API_START_EVILTWIN,
    API_GET_EVILTWIN_TARGET,
    API_CHECK_INPUT_PASSWORD,
    API_GET_PASSWORDS,
    API_KARMA_ATTACK_SCAN,
    API_GET_KARMA_PROBES,
    API_KARMA_ATTACK_START,
    API_MAX_COMMAND
} api_commant_t;

/**
 * @brief Get MIME type from file path
 */
const char* mime_from_path(const char* path);

/**
 * @brief Register server API handlers
 * @deprecated To be removed and replaced with websocket
 */
esp_err_t register_server_api_handlers(httpd_handle_t server) __attribute((deprecated));


/**
 * @brief Parse incoming websocket API request
 * 
 * @param req Websocket frame request
 */
void http_api_parse(httpd_ws_frame_t *req);


#endif /* _SERVER_API_H_ */