#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_task_wdt.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "server.h"
#include "admin_server.h"
#include "wifiMng.h"
#include "dns.h"
#include "passwordMng.h"


/**
 * @brief Block system when an unrecoverable error accurs.
 * 
 */
static void fatal_error_handler(void)
{ 
    while(true)
    {
        ESP_LOGE("FATAL_ERROR:", "Fatal error occurs, system is blocked.");
        vTaskDelay(pdMS_TO_TICKS(5000));
    } 
}


void app_main() 
{
    esp_err_t ret = ESP_OK;

    /* Initialize NVS */
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Config wdt */
    const esp_task_wdt_config_t wdt_conf = {
      .idle_core_mask = 0x3,
      .timeout_ms = 10000,
      .trigger_panic = false
    };
    /* Deinit first bugfix for S3 */
    esp_task_wdt_deinit();
    esp_task_wdt_init(&wdt_conf);

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

    /* Start wifi AP */
    wifi_start_softap();

    /* Start dns server */
    dns_server_start();

    /* Start admin http server */
    http_admin_server_start();
}