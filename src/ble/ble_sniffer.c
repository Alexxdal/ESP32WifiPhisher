#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_coexist.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "TaskManager.h"
#include "ble_identify.h"
#include "ble_sniffer.h"
 
static const char *TAG = "BLE_SNIFFER";
 
#define BLE_SNIFFER_TASK_PRIO       5
#define BLE_SNIFFER_TASK_STACK      4096
#define BLE_SNIFFER_EVT_TASK_EXITED BIT0
 
static ble_sniffer_device_t s_devices[BLE_SNIFFER_MAX_DEVICES];
static uint16_t             s_device_count = 0;
static ble_sniffer_stats_t  s_stats = { 0 };
 
static SemaphoreHandle_t      s_table_mutex = NULL;
static EventGroupHandle_t     s_ble_evt = NULL;
static TaskHandle_t           s_host_task_handle = NULL;
static volatile bool          s_host_ready = false;   /* NimBLE host synced with controller */
static volatile bool          s_running = false;       /* scan currently active */
static volatile bool          s_live_analyzer = false;
static ble_sniffer_frame_cb_t s_frame_cb = NULL;
static uint8_t                s_own_addr_type = 0;
 
/* --- device table --- */
 
static int find_device_index(const uint8_t *addr)
{
    for (int i = 0; i < s_device_count; i++) {
        if (memcmp(s_devices[i].addr, addr, 6) == 0) {
            return i;
        }
    }
    return -1;
}
 
static void addr_to_readable(const uint8_t *raw_le, uint8_t *out_readable)
{
    /* ble_addr_t.val is little-endian; flip it to the XX:XX:... order
     * used elsewhere in the project (e.g. vendors.c OUI lookup). */
    for (int i = 0; i < 6; i++) {
        out_readable[i] = raw_le[5 - i];
    }
}
 
/* Inserts/updates a device entry and its cumulative counters. Returns
 * NULL if the table is full and this is a new address (the frame is
 * still counted in the aggregate stats, just not tracked per-device). */
static ble_sniffer_device_t *track_device(const struct ble_gap_disc_desc *disc)
{
    uint8_t addr[6];
    addr_to_readable(disc->addr.val, addr);
 
    xSemaphoreTake(s_table_mutex, portMAX_DELAY);
 
    s_stats.total_packets++;
    s_stats.total_bytes += disc->length_data;
 
    int idx = find_device_index(addr);
    if (idx < 0) {
        if (s_device_count >= BLE_SNIFFER_MAX_DEVICES) {
            xSemaphoreGive(s_table_mutex);
            return NULL;
        }
        idx = s_device_count++;
        memset(&s_devices[idx], 0, sizeof(ble_sniffer_device_t));
        memcpy(s_devices[idx].addr, addr, 6);
        s_devices[idx].addr_type = (disc->addr.type == BLE_ADDR_PUBLIC) ?
                                     BLE_SNIFFER_ADDR_PUBLIC : BLE_SNIFFER_ADDR_RANDOM;
        s_devices[idx].first_seen_us = esp_timer_get_time();
        s_stats.unique_devices++;
    }
 
    ble_sniffer_device_t *dev = &s_devices[idx];
    dev->last_rssi = disc->rssi;
    dev->last_seen_us = esp_timer_get_time();
    dev->packet_count++;
    dev->byte_count += disc->length_data;
 
    uint8_t copy_len = disc->length_data;
    if (copy_len > BLE_SNIFFER_MAX_ADV_LEN) {
        copy_len = BLE_SNIFFER_MAX_ADV_LEN;   /* clamp, see extended-adv note in the header */
    }
    dev->last_adv_len = copy_len;
    memcpy(dev->last_adv_payload, disc->data, copy_len);
 
    /* The local name often shows up in a scan-response frame separate
     * from the one carrying manufacturer data -- only overwrite dev->name
     * when this frame actually has one, so it doesn't get blanked out. */
    char extracted_name[sizeof(dev->name)];
    if (ble_identify_extract_name(disc->data, disc->length_data, extracted_name, sizeof(extracted_name))) {
        strncpy(dev->name, extracted_name, sizeof(dev->name) - 1);
        dev->name[sizeof(dev->name) - 1] = '\0';
    }
 
    /* Re-classify on every frame: as we accumulate the name and/or the
     * manufacturer payload across frames, the classification can only
     * get better, never worse. */
    ble_identify_classify(disc->data, disc->length_data,
                          dev->name[0] != '\0' ? dev->name : NULL,
                          &dev->identify);
 
    xSemaphoreGive(s_table_mutex);
    return dev;
}
 
/* --- NimBLE callbacks --- */
 
static int ble_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    if (event->type != BLE_GAP_EVENT_DISC) {
        return 0;
    }
 
    ble_sniffer_device_t *dev = track_device(&event->disc);
    if (dev != NULL && s_live_analyzer && s_frame_cb != NULL) {
        s_frame_cb(dev);
    }
    return 0;
}
 
/* Fires once the NimBLE host completes its reset/sync handshake with the
 * controller. Only marks the host ready -- ble_sniffer_start() is what
 * actually kicks off discovery, so start/stop can be called independently
 * of this one-time sync. */
static void ble_app_on_sync(void)
{
    int rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: %d", rc);
        return;
    }
    s_host_ready = true;
    ESP_LOGI(TAG, "NimBLE host synced, ready to scan");
}
 
/* Runs the NimBLE event loop for the module's lifetime. Same exit
 * handshake as wifi_sniffer_channel_hopping_task: signal EXITED, then
 * unregister and self-delete. */
static void ble_host_task(void *param)
{
    if (s_ble_evt) {
        xEventGroupClearBits(s_ble_evt, BLE_SNIFFER_EVT_TASK_EXITED);
    }
 
    nimble_port_run();   /* blocks until nimble_port_stop() (called from deinit) */
 
    if (s_ble_evt) {
        xEventGroupSetBits(s_ble_evt, BLE_SNIFFER_EVT_TASK_EXITED);
    }
    task_manager_unregister_current_task();
    vTaskDelete(NULL);
}
 
/* --- public API --- */
 
esp_err_t ble_sniffer_init(void)
{
    if (s_table_mutex == NULL) {
        s_table_mutex = xSemaphoreCreateMutex();
        if (s_table_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_ble_evt == NULL) {
        s_ble_evt = xEventGroupCreate();
        if (s_ble_evt == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
 
    /* Favor WiFi in the coexistence arbiter: timing-sensitive attacks
     * (CSA spoofing, PMF downgrade, channel hopping) keep priority, BLE
     * scan gets the leftover slots. */
    esp_coex_preference_set(ESP_COEX_PREFER_WIFI);
 
    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %d", err);
        return err;
    }
    ble_hs_cfg.sync_cb = ble_app_on_sync;
 
    if (s_host_task_handle == NULL) {
        err = task_manager_create_task(ble_host_task, "ble_sniffer_task",
                                        BLE_SNIFFER_TASK_STACK, NULL,
                                        BLE_SNIFFER_TASK_PRIO, &s_host_task_handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "failed to create ble_sniffer_task: %d", err);
            return err;
        }
    }
    return ESP_OK;
}
 

esp_err_t ble_sniffer_deinit(void)
{
    ble_gap_disc_cancel();   /* no-op if not currently scanning */
    s_running = false;
 
    if (s_host_task_handle != NULL) {
        nimble_port_stop();   /* makes nimble_port_run() return inside the task */
 
        EventBits_t bits = xEventGroupWaitBits(
            s_ble_evt,
            BLE_SNIFFER_EVT_TASK_EXITED,
            pdTRUE, pdFALSE,
            pdMS_TO_TICKS(2000)
        );
 
        if ((bits & BLE_SNIFFER_EVT_TASK_EXITED) == 0) {
            /* Didn't confirm exit in time -> force-delete as a fallback. */
            task_manager_delete_task_by_handle(s_host_task_handle);
        }
        s_host_task_handle = NULL;
    }
 
    s_host_ready = false;
    return ESP_OK;
}
 

esp_err_t ble_sniffer_start(void)
{
    if (!s_host_ready) {
        ESP_LOGW(TAG, "Host not synced yet, call ble_sniffer_init() first and retry");
        return ESP_ERR_INVALID_STATE;
    }
    if (s_running) {
        return ESP_OK;
    }
 
    struct ble_gap_disc_params disc_params = {
        .passive = 1,             /* receive-only, no scan requests */
        .filter_duplicates = 0,   /* every frame, not just the first per device */
        .itvl = 0x0010,           /* scan interval, units of 0.625 ms */
        .window = 0x0010,         /* scan window per interval */
    };
 
    int rc = ble_gap_disc(s_own_addr_type, BLE_HS_FOREVER, &disc_params, ble_gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
        return ESP_FAIL;
    }
 
    s_running = true;
    ESP_LOGI(TAG, "BLE passive scan started");
    return ESP_OK;
}
 

esp_err_t ble_sniffer_stop(void)
{
    if (!s_running) {
        return ESP_OK;
    }
    ble_gap_disc_cancel();
    s_running = false;
    return ESP_OK;
}
 

bool ble_sniffer_is_running(void)
{
    return s_running;
}
 

void ble_sniffer_set_live_analyzer(bool enable)
{
    s_live_analyzer = enable;
}
 

void ble_sniffer_set_frame_callback(ble_sniffer_frame_cb_t cb)
{
    s_frame_cb = cb;
}
 

size_t ble_sniffer_get_devices(ble_sniffer_device_t *out, size_t max_out)
{
    xSemaphoreTake(s_table_mutex, portMAX_DELAY);
    size_t n = (s_device_count < max_out) ? s_device_count : max_out;
    memcpy(out, s_devices, n * sizeof(ble_sniffer_device_t));
    xSemaphoreGive(s_table_mutex);
    return n;
}
 

void ble_sniffer_get_stats(ble_sniffer_stats_t *out)
{
    xSemaphoreTake(s_table_mutex, portMAX_DELAY);
    *out = s_stats;
    xSemaphoreGive(s_table_mutex);
}

 
void ble_sniffer_clear(void)
{
    xSemaphoreTake(s_table_mutex, portMAX_DELAY);
    memset(s_devices, 0, sizeof(s_devices));
    memset(&s_stats, 0, sizeof(s_stats));
    s_device_count = 0;
    xSemaphoreGive(s_table_mutex);
}