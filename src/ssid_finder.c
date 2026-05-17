#include <string.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "ssid_finder.h"
#include "wifi_attacks.h"
#include "wifiMng.h"
#include "sniffer.h"
#include "deauther.h"

static const char *TAG = "SSID_FINDER";
static TaskHandle_t ssid_finder_task_handle = NULL;
static EventGroupHandle_t ssid_finder_evt = NULL;
#define SSID_FINDER_EXIT_BIT (1 << 0)
static volatile bool ssid_finder_running = false;
static target_info_t ssid_finder_target = {0}; 


static void ssid_finder_task(void *pvParameters)
{
    wifi_switch_ap_channel_csa(ssid_finder_target.channel);
    wifi_start_sniffing();
    wifi_sniffer_set_bssid_filter(ssid_finder_target.bssid);
    wifi_sniffer_scan_fill_aps_fast();

    while(ssid_finder_running)
    {
        deauther_send_frames(&ssid_finder_target, DEAUTHER_ATTACK_DISASSOC_FRAME);
        vTaskDelay(pdMS_TO_TICKS(1000)); 
    }

    wifi_stop_sniffing();

    if(ssid_finder_evt != NULL) {
        xEventGroupSetBits(ssid_finder_evt, SSID_FINDER_EXIT_BIT);
    }
    vTaskDelete(NULL);
}


esp_err_t ssid_finder_start(target_info_t *target_info)
{
    if(target_info == NULL) {
        ESP_LOGE(TAG, "target_info is null.");
        return ESP_ERR_INVALID_ARG;
    }

    if( ssid_finder_task_handle != NULL ) {   
        ESP_LOGE(TAG, "SSID finder task already started.");
        return ESP_ERR_INVALID_STATE;
    }

    if (ssid_finder_evt == NULL) {
        ssid_finder_evt = xEventGroupCreate();
    }
    xEventGroupClearBits(ssid_finder_evt, SSID_FINDER_EXIT_BIT);

    memcpy(&ssid_finder_target, target_info, sizeof(target_info_t));
    ssid_finder_running = true;
    xTaskCreate(ssid_finder_task, "SSID_FINDER", 2048, NULL, 5, &ssid_finder_task_handle);

    return ESP_OK;
}


esp_err_t ssid_finder_stop(void)
{
    if (ssid_finder_task_handle == NULL)
    {
        ESP_LOGW(TAG, "SSID finder task is not running.");
        return ESP_ERR_INVALID_STATE;
    }

    ssid_finder_running = false;
    
    if (ssid_finder_evt != NULL) {
        xEventGroupWaitBits(ssid_finder_evt, SSID_FINDER_EXIT_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
        vEventGroupDelete(ssid_finder_evt);
        ssid_finder_evt = NULL;
    }

    ssid_finder_task_handle = NULL;

    ESP_LOGI(TAG, "SSID Finder stopped");
    return ESP_OK;
}