#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "ble_sniffer.h"
#include "bleMng.h"

static const char *TAG = "BLE_SNIFFER";

#if CONFIG_BT_ENABLED

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "host/ble_hs.h"
#include "ble_identify.h"

static ble_sniffer_device_t s_devices[BLE_SNIFFER_MAX_DEVICES];
static uint16_t             s_device_count = 0;
static ble_sniffer_stats_t  s_stats = { 0 };

static SemaphoreHandle_t      s_table_mutex = NULL;
static volatile bool          s_running = false;       /* scan currently active */
static volatile bool          s_live_analyzer = false;
static ble_sniffer_frame_cb_t s_frame_cb = NULL;

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

/* --- public API --- */

esp_err_t ble_sniffer_start(void)
{
    if (s_table_mutex == NULL) {
        s_table_mutex = xSemaphoreCreateMutex();
        if (s_table_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (!ble_is_ready()) {
        ESP_LOGW(TAG, "Host not synced yet, call ble_init() first and retry");
        return ESP_ERR_INVALID_STATE;
    }
    if (s_running) {
        return ESP_OK;
    }

    struct ble_gap_disc_params disc_params = {
        .passive = 1,             /* receive-only, no scan requests */
        .filter_duplicates = 0,   /* every frame, not just the first per device */
        .itvl = 0x01E0,           /* 480 * 0.625ms = 300ms: ogni quanto il controller richiede il radio */
        .window = 0x0010,         /* 16 * 0.625ms = 10ms: quanto lo tiene occupato -> ~3.3% duty cycle,
                                    * lascia ~290ms liberi per il WiFi ad ogni ciclo */
    };

    int rc = ble_gap_disc(ble_get_own_addr_type(), BLE_HS_FOREVER, &disc_params, ble_gap_event_cb, NULL);
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

    ESP_LOGI(TAG, "BLE passive scan stopped");
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
    if (s_table_mutex == NULL) {
        return 0;   /* sniffer non ancora avviato: nessun dispositivo da restituire */
    }
    xSemaphoreTake(s_table_mutex, portMAX_DELAY);
    size_t n = (s_device_count < max_out) ? s_device_count : max_out;
    memcpy(out, s_devices, n * sizeof(ble_sniffer_device_t));
    xSemaphoreGive(s_table_mutex);
    return n;
}


void ble_sniffer_get_stats(ble_sniffer_stats_t *out)
{
    if (s_table_mutex == NULL) {
        memset(out, 0, sizeof(*out));
        return;
    }
    xSemaphoreTake(s_table_mutex, portMAX_DELAY);
    *out = s_stats;
    xSemaphoreGive(s_table_mutex);
}


void ble_sniffer_clear(void)
{
    if (s_table_mutex == NULL) {
        return;
    }
    xSemaphoreTake(s_table_mutex, portMAX_DELAY);
    memset(s_devices, 0, sizeof(s_devices));
    memset(&s_stats, 0, sizeof(s_stats));
    s_device_count = 0;
    xSemaphoreGive(s_table_mutex);
}

#else /* !CONFIG_BT_ENABLED */

/* BLE disattivato in questa build: nessuno stack NimBLE, nessun task,
 * nessuna RAM statica del device table (s_devices[64] + relativi buffer
 * spariscono dal .bss). Stub no-op per non dover toccare main.c. */

esp_err_t ble_sniffer_start(void)
{
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ble_sniffer_stop(void)
{
    return ESP_OK;
}

bool ble_sniffer_is_running(void)
{
    return false;
}

void ble_sniffer_set_live_analyzer(bool enable)
{
    (void)enable;
}

void ble_sniffer_set_frame_callback(ble_sniffer_frame_cb_t cb)
{
    (void)cb;
}

size_t ble_sniffer_get_devices(ble_sniffer_device_t *out, size_t max_out)
{
    (void)out;
    (void)max_out;
    return 0;
}

void ble_sniffer_get_stats(ble_sniffer_stats_t *out)
{
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
}

void ble_sniffer_clear(void)
{
}

#endif /* CONFIG_BT_ENABLED */
