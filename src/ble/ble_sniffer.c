#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_coexist.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "ble_sniffer.h"
 
static const char *TAG = "BLE_SNIFFER";
 
static ble_sniffer_device_t s_devices[BLE_SNIFFER_MAX_DEVICES];
static uint16_t             s_device_count = 0;
static ble_sniffer_stats_t  s_stats = { 0 };
 
static SemaphoreHandle_t      s_table_mutex = NULL;
static volatile bool          s_running = false;
static volatile bool          s_live_analyzer = false;
static ble_sniffer_frame_cb_t s_frame_cb = NULL;
 
/* --- utility indirizzi/tabella --- */
 
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
    /* ble_addr_t.val e' little-endian: lo giriamo per avere lo stesso
     * ordine "leggibile" XX:XX:XX:XX:XX:XX che usi altrove nel progetto
     * (es. vendors.c per l'OUI lookup Wi-Fi). */
    for (int i = 0; i < 6; i++) {
        out_readable[i] = raw_le[5 - i];
    }
}
 
/* Inserisce/aggiorna un dispositivo nella tabella e ne aggiorna i
 * contatori cumulativi. Ritorna NULL se la tabella e' piena e
 * l'indirizzo non era gia' presente (il frame viene comunque contato
 * nelle statistiche aggregate, solo non tracciato per-device). */
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
        copy_len = BLE_SNIFFER_MAX_ADV_LEN;   /* clamp: vedi nota extended adv in ble_sniffer.h */
    }
    dev->last_adv_len = copy_len;
    memcpy(dev->last_adv_payload, disc->data, copy_len);
 
    xSemaphoreGive(s_table_mutex);
    return dev;
}
 
/* --- callback GAP / host NimBLE --- */
 
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
 
static void ble_app_on_sync(void)
{
    uint8_t own_addr_type;
    int rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto fallita: %d", rc);
        return;
    }
 
    struct ble_gap_disc_params disc_params = {
        .passive = 1,             /* niente scan request: solo ricezione */
        .filter_duplicates = 0,   /* vogliamo ogni frame, non solo il primo per device */
        .itvl = 0x0010,           /* intervallo di scan, unita' di 0.625 ms */
        .window = 0x0010,         /* finestra di ricezione per intervallo */
    };
 
    rc = ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &disc_params, ble_gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc fallita: %d", rc);
        return;
    }
    ESP_LOGI(TAG, "Scan BLE passivo avviato");
}
 
static void ble_host_task(void *param)
{
    nimble_port_run();            /* non ritorna finche' non arriva nimble_port_stop() */
    nimble_port_freertos_deinit();
}
 
/* --- API pubblica --- */
 
esp_err_t ble_sniffer_init(void)
{
    if (s_table_mutex == NULL) {
        s_table_mutex = xSemaphoreCreateMutex();
        if (s_table_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
 
    /* Priorita' al Wi-Fi nell'arbitro di coexistence: lo sniffer BLE
     * prende solo gli slot residui. Se questa preferenza la imposti
     * gia' altrove (es. in main.c una volta per tutto il firmware),
     * questa riga e' ridondante ma non dannosa: togli il duplicato. */
    esp_coex_preference_set(ESP_COEX_PREFER_WIFI);
 
    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init fallita: %d", err);
        return err;
    }
 
    ble_hs_cfg.sync_cb = ble_app_on_sync;
    return ESP_OK;
}
 
esp_err_t ble_sniffer_start(void)
{
    if (s_running) {
        ESP_LOGW(TAG, "Sniffer BLE gia' in esecuzione");
        return ESP_OK;
    }
 
    /* nimble_port_freertos_init crea il task host con stack/priorita'/core
     * configurati via Kconfig (CONFIG_BT_NIMBLE_*): e' lui che chiama
     * ble_app_on_sync() -> ble_gap_disc() una volta pronto. */
    nimble_port_freertos_init(ble_host_task);
    s_running = true;
    return ESP_OK;
}
 
esp_err_t ble_sniffer_stop(void)
{
    if (!s_running) {
        return ESP_OK;
    }
 
    ble_gap_disc_cancel();
    nimble_port_stop();           /* fa ritornare nimble_port_run() nel task host,
                                      che poi si auto-elimina con nimble_port_freertos_deinit() */
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