#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_task_wdt.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include "server.h"
#include "wifiMng.h"
#include "dns.h"
#include "passwordMng.h"
#include "portmap.h"
#include "networking.h"
#include "sniffer.h"
#include "console.h"
#include "scanner.h"

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    #include "esp_wifi_usb.h"
#endif


static const char *TAG = "MAIN";


/**
 * @brief Block system when an unrecoverable error occurs.
 * 
 */
static void fatal_error_handler(void)
{ 
    while(true)
    {
        ESP_LOGE("FATAL_ERROR:", "Fatal error occurred, system is blocked and can't continue execution.");
        vTaskDelay(pdMS_TO_TICKS(5000));
    } 
}


void app_main() 
{
    esp_err_t ret = ESP_OK;

    /* Deinit WDT (Error can be ignored) */
    esp_task_wdt_deinit();

    /* Initialize NVS */
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3)
    if(esp_wifi_usb_init(2000) == ESP_OK) {
        esp_wifi_usb_set_tx_power(50);
        ESP_ERROR_CHECK(esp_wifi_usb_start());
        wifi_usb_set_present(true);
    } else {
        wifi_usb_set_present(false);
    }
#endif

    /* Init password manager */
    if(password_manager_init())
    {
        fatal_error_handler();
    }

    /* Init wifi */
    if(wifi_init())
    {
        fatal_error_handler();
    }

    /* Init Wifi Sniffer */
    if(wifi_sniffer_init() != ESP_OK)
    {
        fatal_error_handler();
    }

    /* Configure DNAT for captive portal */
    /*if(setup_dnat_for_captive_portal() != ESP_OK)
    {
        fatal_error_handler();
    }*/

    /* Init networking */
    if(networking_init() != ESP_OK)
    {
        fatal_error_handler();
    }

    #ifdef DEBUG
    esp_log_level_set("wifi", ESP_LOG_DEBUG);
    esp_log_level_set("esp_netif_lwip", ESP_LOG_DEBUG);
    esp_log_level_set("httpd_txrx", ESP_LOG_WARN);
    esp_log_level_set("httpd_ws", ESP_LOG_WARN);
    #else
    esp_log_level_set("wifi", ESP_LOG_ERROR);
    esp_log_level_set("esp_netif_lwip", ESP_LOG_WARN);
    esp_log_level_set("httpd_txrx", ESP_LOG_ERROR);
    esp_log_level_set("httpd_ws", ESP_LOG_ERROR);
    #endif

    /* Start wifi AP */
    wifi_start_softap();

    /* Start web server */
    http_server_start();

    /* Config wdt */
    uint32_t idle_core_mask = (1 << portNUM_PROCESSORS) - 1; // Mask for single and dual core processors
    const esp_task_wdt_config_t wdt_conf = {
        .idle_core_mask = idle_core_mask,
        .timeout_ms = 10000,
        .trigger_panic = false
    };
    ESP_ERROR_CHECK(esp_task_wdt_init(&wdt_conf));

    //console_init();

    if(scanner_init() != ESP_OK) 
    {
        fatal_error_handler();
    }

    /* Suspend main task */
    vTaskSuspend(NULL); 
}