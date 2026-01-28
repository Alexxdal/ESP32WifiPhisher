#ifndef _SERVER_API_H_
#define _SERVER_API_H_

#include <esp_err.h>
#include <esp_http_server.h>
#include "server.h"

typedef enum {
    API_GET_STATUS = 0,
    API_SET_AP_SETTINGS,
    API_GET_AP_SETTINGS,
    API_WIFI_SCAN,
    API_START_EVILTWIN,
    API_STOP_EVILTWIN,
    API_GET_EVILTWIN_TARGET,
    API_CHECK_INPUT_PASSWORD,
    API_GET_PASSWORDS,
    API_KARMA_ATTACK_SCAN,
    API_GET_KARMA_PROBES,
    API_KARMA_ATTACK_START,
    API_DEAUTHER_START,
    API_DEAUTHER_STOP,
    API_START_RAW_SNIFFER,
    API_STOP_RAW_SNIFFER,
    API_MAX_COMMAND
} api_commant_t;


/**
 * @brief Get MIME type from file path
 */
const char* mime_from_path(const char* path);


/**
 * @brief Parse incoming websocket API request
 * 
 * @param req Websocket frame request
 */
void http_api_parse(ws_frame_req_t *req);


/**
 * @brief Send formatted log message via websocket
 * 
 * @param level Log level (e.g., "INFO", "WARNING", "ERROR")
 * @param format Printf-style format string
 * @param ... Variable arguments matching format string
 */
void ws_log(const char *level, const char *format, ...);


#endif /* _SERVER_API_H_ */