#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include <lwip/sockets.h>
#include "esp_http_server.h"
#include "passwordMng.h"
#include "server.h"
#include "server_api.h"


/* Server handler */
static httpd_handle_t server = NULL;
static const char *TAG = "ADMIN_SERVER";


static esp_err_t file_get_handler(httpd_req_t *req) 
{
    char filepath[128] = "/spiffs";
    const char *uri = req->uri;

    if (strcmp(uri, "/") == 0) { 
        uri = "/admin.html";
    }

    strlcat(filepath, uri, sizeof(filepath));

    FILE *f = fopen(filepath, "r");
    if (!f) 
    { 
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
        return ESP_OK; 
    }

    httpd_resp_set_type(req, mime_from_path(filepath));
    
    char buf[1024];
    size_t n;
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


void http_admin_server_start(void)
{
    if( server != NULL )
    {
        ESP_LOGD(TAG, "Admin server already started.");
        return;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
	config.lru_purge_enable = true;
    config.ctrl_port = 8081;
    config.server_port = 8080;
    config.max_uri_handlers = 10;

    if (httpd_start(&server, &config) == ESP_OK) 
	{
        ESP_ERROR_CHECK(register_server_api_handlers(server));
        
        httpd_uri_t any = {
            .uri = "/*", 
            .method = HTTP_GET, 
            .handler = file_get_handler, 
            .user_ctx = NULL
        };
        ESP_ERROR_CHECK(httpd_register_uri_handler(server, &any));
    }
}


void http_admin_server_stop(void)
{
    if( server != NULL )
    {
        if( httpd_stop(server) != ESP_OK )
        {
            ESP_LOGD(TAG, "Failed to stop admin server.");
            return;
        }
        server = NULL;
    }
}