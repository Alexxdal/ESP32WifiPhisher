#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "spi_flash_mmap.h"

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
#include "web/admin_page.h"
#include "config.h"
#include "evil_twin.h"
#include "img/admin_favicon.h"


/* Server handler */
static httpd_handle_t server = NULL;
static const char *TAG = "ADMIN_SERVER:";
/* Strings for sending chiper information */
static const char *authmode_str[] = {
        "Open", "WEP", "WPA/PSK", "WPA2/PSK", "WPA_WPA2/PSK", "WPA3/PSK", "WPA2_WPA3/PSK", "WAPI/PSK"
};
/* Buffers for json used for network scanning */
static char json_response[4096];
static char entry[300];


static esp_err_t admin_page_handler(httpd_req_t *req) 
{
    char ssid[32] = {0};
    char password[64] = {0};
    int32_t channel = 1;
    char buffer[512] = { 0 };

    /* Read value from flash */
    if( read_string_from_flash("wifi_ssid", ssid) != ESP_OK )
    {
        strcpy(ssid, DEFAULT_WIFI_SSID);
    }
    if( read_string_from_flash("wifi_pass", password) != ESP_OK )
    {
        strcpy(password, DEFAULT_WIFI_PASS);
    }
    if( read_int_from_flash("wifi_chan", &channel) != ESP_OK )
    {
        channel = DEFAULT_WIFI_CHAN;
    }
    

    httpd_resp_set_type(req, "text/html");
    /* Send page header */
    httpd_resp_send_chunk(req, admin_page_header, sizeof(admin_page_header));

    /* Send parameters */
    httpd_resp_send_chunk(req, "<script>", HTTPD_RESP_USE_STRLEN);
    snprintf(buffer, sizeof(buffer), admin_page_settings, ssid, password, (int)channel);
    httpd_resp_send_chunk(req, buffer, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "</script>\n", HTTPD_RESP_USE_STRLEN);

    /* Send body */
    httpd_resp_send_chunk(req, admin_page_body, sizeof(admin_page_body));
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}


static esp_err_t admin_page_settings_ap_submit_handler(httpd_req_t *req)
{
    char buffer[256];
    int ret;

    ret = httpd_req_recv(req, buffer, sizeof(buffer) - 1);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    buffer[ret] = '\0';
    char ssid[64] = {0};
    char password[64] = {0};
    int channel = 1;
    sscanf(buffer, "ssid=%63[^&]&password=%63[^&]&channel=%d", ssid, password, &channel);

    /* Save new settings */
    save_string_to_flash(WIFI_SSID_KEY, ssid);
    save_string_to_flash(WIFI_PASS_KEY, password);
    save_int_to_flash(WIFI_CHAN_KEY, channel);
    
    /* Send response */
    httpd_resp_send(req, "Settings updated successfully!\nRestart the device to make it effective!", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
} 


static esp_err_t targets_scan_handler(httpd_req_t *req) 
{
    wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100,
        .scan_time.active.max = 500,
    };

    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
    uint16_t ap_count = 0;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    wifi_ap_record_t ap_records[ap_count];
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, ap_records));

    memset(&json_response, 0, sizeof(json_response));
    snprintf(json_response, sizeof(json_response), "[");
    for (int i = 0; i < ap_count; i++) {
        memset(&entry, 0, sizeof(entry));
        snprintf(entry, sizeof(entry),
                 "{\"ssid\":\"%s\","
                 "\"signal\":%d,"
                 "\"channel\":%d,"
                 "\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
                 "\"authmode\":\"%s\","
                 "\"pairwise_cipher\":\"%d\","
                 "\"group_cipher\":\"%d\","
                 "\"wps\":%d}%s",
                 ap_records[i].ssid,
                 ap_records[i].rssi,
                 ap_records[i].primary,
                 ap_records[i].bssid[0], ap_records[i].bssid[1], ap_records[i].bssid[2],
                 ap_records[i].bssid[3], ap_records[i].bssid[4], ap_records[i].bssid[5],
                 authmode_str[ap_records[i].authmode],
                 ap_records[i].pairwise_cipher,
                 ap_records[i].group_cipher,
                 ap_records[i].wps,
                 (i < ap_count - 1) ? "," : "");
        strncat(json_response, entry, sizeof(json_response) - strlen(json_response) - 1);
    }
    strncat(json_response, "]", sizeof(json_response) - strlen(json_response) - 1);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_response, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}


static esp_err_t admin_favicon_handler(httpd_req_t *req) 
{
    httpd_resp_set_type(req, "image/png");
    httpd_resp_send(req, (const char *)admin_favicon_data, admin_favicon_size);
    return ESP_OK;
}


static esp_err_t evil_twin_handler(httpd_req_t *req) 
{
    char buffer[300];
    int ret = httpd_req_recv(req, buffer, sizeof(buffer) - 1);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    buffer[ret] = '\0';
    char bssid[64] = {0};
    target_info_t target_info = { 0 };
    sscanf(buffer,"ssid=%32[^&]&bssid=%17[^&]&channel=%hhu&signal=%hhd&pairwise=%hhu&group=%hhu&scheme=%hhd", 
    target_info.ssid, bssid, &target_info.channel, &target_info.rssi, (unsigned char *)&target_info.pairwise_cipher, (unsigned char *)&target_info.group_cipher, &target_info.attack_scheme);

    if (sscanf(bssid, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &target_info.bssid[0], &target_info.bssid[1], &target_info.bssid[2],
               &target_info.bssid[3], &target_info.bssid[4], &target_info.bssid[5]) != 6) {
        ESP_LOGE(TAG, "Errore nel parsing del BSSID\n");
        return ESP_FAIL;
    }

    httpd_resp_sendstr(req, "EvilTwin attack is started, this page will no longer be enabled until device reset.");
    httpd_resp_send(req, NULL, 0);

    /* Start evil twin attack */
    evil_twin_start_attack(&target_info);

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
	config.lru_purge_enable = true;
    config.ctrl_port = 8081;
    config.server_port = 8080;

    if (httpd_start(&server, &config) == ESP_OK) 
	{
        /* Admin favicon */
        httpd_uri_t admin_favicon_uri = {
            .uri = "/favicon.ico",
            .method = HTTP_GET,
            .handler = admin_favicon_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &admin_favicon_uri);

        /* Main page handler*/
        httpd_uri_t admin_uri = {
            .uri = "/",
            .method = HTTP_GET,
            .handler = admin_page_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &admin_uri);

        /* Handler for saving admin ap settings */
        httpd_uri_t save_ap_uri = {
            .uri = "/save_ap",
            .method = HTTP_POST,
            .handler = admin_page_settings_ap_submit_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &save_ap_uri);

        /* Handler for targets scan */
        httpd_uri_t targets_scan_uri = {
            .uri = "/scan_networks",
            .method = HTTP_GET,
            .handler = targets_scan_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &targets_scan_uri);

        /* Handler for starting evil twin attack */
        httpd_uri_t evil_twin_uri = {
            .uri = "/evil_twin",
            .method = HTTP_POST,
            .handler = evil_twin_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &evil_twin_uri);
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