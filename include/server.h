#ifndef _SERVER_H
#define _SERVER_H

#include <esp_http_server.h>

typedef enum 
{
    FIRMWARE_UPGRADE = 0,
    WEB_NET_MANAGER,
    PLUGIN_UPDATE,
    OAUTH_LOGIN
} attack_scheme_t;


#define WS_FRAME_BUFFER_SIZE 1024
#define WS_FRAME_QUEUE_LENGTH 15

/**
 * @brief Websocket frame type
 */
typedef enum {
    WS_RX_FRAME = 0,
    WS_TX_FRAME,
    WS_MAX_FRAME
} ws_frame_type_t;


/**
 * @brief HTTP websocket send request structure
 * 
 * @param hd HTTP server handle
 * @param fd Websocket file descriptor
 * @param payload Payload to send
 */
typedef struct {
    ws_frame_type_t frame_type;
    httpd_handle_t hd;
    int fd;
    size_t payload_len;
    char payload[WS_FRAME_BUFFER_SIZE];
} ws_frame_req_t;


/**
 * @brief Send command over websocket
 * 
 * @param _req Websocket send request structure
 * @param payload Payload to send
 */
void ws_send_command_to_queue(ws_frame_req_t *_req, const char *payload);


/**
 * @brief Start http server task
 * 
 */
void http_server_start(void);


/**
 * @brief Stop http server
 * 
 */
void http_server_stop(void);

#endif