#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "TaskManager.h"
#include "bleMng.h"

static const char *TAG = "BLE_MNG";

#if CONFIG_BT_ENABLED

#include "esp_coexist.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/util/util.h"

/* Stub per risolvere il bug di ESP-IDF quando CONFIG_BT_NIMBLE_GATT_SERVER
 * è disabilitato -- vive qui e non in ble_sniffer.c perché riguarda lo
 * stack NimBLE nel suo complesso, non la sola feature "sniffer". */
void ble_gatts_stop(void) { }

#define BLE_MNG_TASK_PRIO       5
#define BLE_MNG_TASK_STACK      4096
#define BLE_MNG_EVT_TASK_EXITED BIT0

static SemaphoreHandle_t      s_state_mutex = NULL;    /* protegge ble_init/ble_deinit, non l'host task */
static EventGroupHandle_t     s_ble_evt = NULL;
static TaskHandle_t           s_host_task_handle = NULL;
static volatile bool          s_host_ready = false;    /* NimBLE host synced con il controller */
static uint8_t                s_own_addr_type = 0;
static bool                   s_initialized = false;

/* Fires once the NimBLE host completes its reset/sync handshake with the
 * controller. I consumer (ble_sniffer, ble_spam, ...) vedono questo
 * tramite ble_is_ready(). */
static void ble_app_on_sync(void)
{
    int rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: %d", rc);
        return;
    }
    s_host_ready = true;
    ESP_LOGI(TAG, "NimBLE host synced");
}

/* Runs the NimBLE event loop for the engine's lifetime. Same exit
 * handshake as wifi_sniffer_channel_hopping_task: signal EXITED, then
 * unregister and self-delete. */
static void ble_host_task(void *param)
{
    if (s_ble_evt) {
        xEventGroupClearBits(s_ble_evt, BLE_MNG_EVT_TASK_EXITED);
    }

    nimble_port_run();   /* blocks until nimble_port_stop() (called from ble_deinit) */

    if (s_ble_evt) {
        xEventGroupSetBits(s_ble_evt, BLE_MNG_EVT_TASK_EXITED);
    }
    task_manager_unregister_current_task();
    vTaskDelete(NULL);
}

/* Called with s_state_mutex held, s_initialized == false. */
static esp_err_t engine_start(void)
{
    if (s_ble_evt == NULL) {
        s_ble_evt = xEventGroupCreate();
        if (s_ble_evt == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    /* Favor WiFi in the coexistence arbiter: timing-sensitive attacks
     * (CSA spoofing, PMF downgrade, channel hopping) keep priority, BLE
     * scan/adv get the leftover slots. */
    esp_coex_preference_set(ESP_COEX_PREFER_WIFI);

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: (%d) %s", err, esp_err_to_name(err));
        return err;
    }
    ble_hs_cfg.sync_cb = ble_app_on_sync;

    if (s_host_task_handle == NULL) {
        err = task_manager_create_task(ble_host_task, "ble_mng_task",
                                        BLE_MNG_TASK_STACK, NULL,
                                        BLE_MNG_TASK_PRIO, &s_host_task_handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "failed to create ble_mng_task: (%d) %s", err, esp_err_to_name(err));
            return err;
        }
    }
    return ESP_OK;
}

/* Called with s_state_mutex held, s_initialized == true. */
static esp_err_t engine_stop(void)
{
    if (s_host_task_handle == NULL) {
        s_host_ready = false;
        return ESP_OK;
    }

    vTaskDelay(pdMS_TO_TICKS(250));
    nimble_port_stop();

    EventBits_t bits = xEventGroupWaitBits(
        s_ble_evt,
        BLE_MNG_EVT_TASK_EXITED,
        pdTRUE, pdFALSE,
        pdMS_TO_TICKS(10000)
    );

    if ((bits & BLE_MNG_EVT_TASK_EXITED) == 0) {
        ESP_LOGE(TAG, "ble_mng_task non è uscito entro il timeout, "
                       "salto nimble_port_deinit() per sicurezza");
        s_host_ready = false;
        return ESP_ERR_TIMEOUT;
    }

    vTaskDelay(pdMS_TO_TICKS(100));
    s_host_task_handle = NULL;

    /* Il --wrap di npl_freertos_event_deinit (vedi npl_event_deinit_fix.c)
     * neutralizza l'assert su ev->event NULL, quindi il deinit completo è
     * sicuro. Necessario non solo per liberare davvero la RAM ma anche per
     * riportare il controller BT allo stato IDLE: saltarlo fa fallire il
     * prossimo nimble_port_init() con ESP_ERR_INVALID_STATE (259). */
    nimble_port_deinit();

    s_host_ready = false;
    return ESP_OK;
}

esp_err_t ble_init(void)
{
    if (s_state_mutex == NULL) {
        s_state_mutex = xSemaphoreCreateMutex();
        if (s_state_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);

    esp_err_t err = ESP_OK;
    if (!s_initialized) {
        err = engine_start();
        if (err == ESP_OK) {
            s_initialized = true;
        }
    }

    xSemaphoreGive(s_state_mutex);
    return err;
}

esp_err_t ble_deinit(void)
{
    if (s_state_mutex == NULL || !s_initialized) {
        return ESP_OK;   /* mai inizializzato, o già spento: no-op */
    }

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);

    esp_err_t err = ESP_OK;
    if (s_initialized) {
        err = engine_stop();
        s_initialized = false;   /* anche in caso di timeout: vedi commento in engine_stop */
    }

    xSemaphoreGive(s_state_mutex);
    return err;
}

bool ble_is_ready(void)
{
    return s_host_ready;
}

uint8_t ble_get_own_addr_type(void)
{
    return s_own_addr_type;
}

#else /* !CONFIG_BT_ENABLED */

esp_err_t ble_init(void)
{
    ESP_LOGW(TAG, "BLE disabilitato in questa build (CONFIG_BT_ENABLED non impostato)");
    return ESP_OK;
}

esp_err_t ble_deinit(void)
{
    return ESP_OK;
}

bool ble_is_ready(void)
{
    return false;
}

uint8_t ble_get_own_addr_type(void)
{
    return 0;
}

#endif /* CONFIG_BT_ENABLED */