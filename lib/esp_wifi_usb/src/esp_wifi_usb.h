/*
 * esp_wifi_usb.h - API pubblica del driver, con nomi ricalcati su esp_wifi.h
 *
 * L'idea e' poter scrivere codice applicativo che assomiglia a quello che si
 * scriverebbe con il Wi-Fi integrato dell'ESP32 (esp_wifi_init/start/stop,
 * promiscuous mode, invio di frame grezzi, cambio canale), ma per la
 * chiavetta USB RTL8188EU. Ogni funzione ha lo stesso nome della sua
 * controparte esp_wifi_*, con "usb" inserito subito dopo "esp_wifi_".
 *
 * Limiti noti rispetto al vero esp_wifi:
 *  - Nessuna modalita' stazione/AP: il chip e' pilotato solo in ricezione
 *    promiscua e in trasmissione di frame grezzi (va bene per sniffing e
 *    per iniezione, non per associarsi a una rete).
 *  - esp_wifi_usb_set_promiscuous(false) non spegne il filtro hardware (il
 *    chip resta sempre in modalita' promiscua a livello RCR): sospende solo
 *    la consegna dei frame alla callback registrata. Vedi commento sulla
 *    funzione piu' sotto per il perche'.
 *  - esp_wifi_usb_80211_tx() usa un descrittore di trasmissione ricostruito
 *    da UNA SOLA cattura reale (un probe request broadcast): funziona per
 *    quel caso, non e' stato verificato su hardware per frame di tipo o
 *    lunghezza diversi. Vedi i commenti in esp_wifi_usb.c.
 */
#ifndef ESP_WIFI_USB_H
#define ESP_WIFI_USB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <esp_wifi_types_generic.h>
#include <esp_wifi_types_native.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Tipi, ricalcati su wifi_promiscuous_pkt_type_t / wifi_pkt_rx_ctrl_t ---- */

typedef enum {
    WIFI_USB_PKT_MGMT,   /* type=0: beacon, probe, auth, assoc... */
    WIFI_USB_PKT_CTRL,   /* type=1: RTS, CTS, ACK... */
    WIFI_USB_PKT_DATA,   /* type=2 */
    WIFI_USB_PKT_MISC,   /* type=3 o frame con descrittore incoerente */
} wifi_usb_promiscuous_pkt_type_t;

/* Metadati per pacchetto.
 * rssi: decodificato dal blocco "phy status" che il chip antepone al frame
 * (quando il bit PHYST del descrittore RX e' acceso), percorsi CCK/OFDM
 * separati. Formula presa dal driver Realtek di riferimento, MAI validata
 * contro un misuratore o un AP a distanza nota: trattare come indicativa,
 * non come dBm calibrato.
 * rate: indice di rate hardware grezzo (vedi wifi_usb_phy_rate_t), letto
 * dal campo RXMCS del descrittore RX. */
typedef struct {
    uint16_t sig_len;    /* lunghezza del frame 802.11, byte (FCS escluso) */
    uint8_t  channel;    /* canale corrente al momento della ricezione */
    int8_t   rssi;       /* dBm approssimativo, vedi nota sopra */
    uint8_t  rate;       /* indice hardware, vedi wifi_usb_phy_rate_t */
    bool     crc_err;    /* bit CRC_ERR del descrittore RX del chip */
    bool     icv_err;    /* bit ICV_ERR del descrittore RX del chip */
} wifi_usb_pkt_rx_ctrl_t;

/* Indici di rate hardware, ricalcati sull'enum "DESC_RATE_*" del driver
 * Realtek di riferimento: stesso enum usato sia dal campo RATE_ID del
 * descrittore TX sia dal campo RXMCS del descrittore RX. Il chip e' 1T1R,
 * quindi ci si ferma a MCS7 (niente doppio flusso spaziale). */
typedef enum {
    WIFI_USB_RATE_1M   = 0x00,
    WIFI_USB_RATE_2M   = 0x01,
    WIFI_USB_RATE_5M5  = 0x02,
    WIFI_USB_RATE_11M  = 0x03,
    WIFI_USB_RATE_6M   = 0x04,
    WIFI_USB_RATE_9M   = 0x05,
    WIFI_USB_RATE_12M  = 0x06,
    WIFI_USB_RATE_18M  = 0x07,
    WIFI_USB_RATE_24M  = 0x08,
    WIFI_USB_RATE_36M  = 0x09,
    WIFI_USB_RATE_48M  = 0x0A,
    WIFI_USB_RATE_54M  = 0x0B,
    WIFI_USB_RATE_MCS0 = 0x0C,
    WIFI_USB_RATE_MCS1 = 0x0D,
    WIFI_USB_RATE_MCS2 = 0x0E,
    WIFI_USB_RATE_MCS3 = 0x0F,
    WIFI_USB_RATE_MCS4 = 0x10,
    WIFI_USB_RATE_MCS5 = 0x11,
    WIFI_USB_RATE_MCS6 = 0x12,
    WIFI_USB_RATE_MCS7 = 0x13,
} wifi_usb_phy_rate_t;

typedef struct {
    wifi_usb_pkt_rx_ctrl_t rx_ctrl;
    uint8_t payload[0];   /* frame 802.11 grezzo, rx_ctrl.sig_len byte.
                           * Valido SOLO per la durata della callback. */
} wifi_usb_promiscuous_pkt_t;

typedef void (*wifi_usb_promiscuous_cb_t)(void *buf, wifi_promiscuous_pkt_type_t type);

/* ---- Ciclo di vita, ricalcato su esp_wifi_init/deinit/start/stop ---- */

/* Installa lo stack USB host, si mette in attesa della chiavetta e, appena
 * la trova, esegue tutta la sequenza di accensione (firmware, MAC, PHY/RF,
 * canale 1, calibrazioni). BLOCCANTE: torna ESP_OK quando il chip e' pronto
 * a ricevere/trasmettere, oppure ESP_ERR_TIMEOUT se la chiavetta non viene
 * rilevata/accesa entro timeout_ms. In caso di timeout i task in background
 * restano comunque attivi e proveranno ad accendersi se la chiavetta compare
 * piu' tardi; una chiamata successiva a esp_wifi_usb_init() e' un no-op che
 * ritorna subito ESP_OK se nel frattempo l'accensione e' andata a buon fine. */
esp_err_t esp_wifi_usb_init(uint32_t timeout_ms);

/* Best-effort: ferma il task RX se attivo. Il vero smontaggio dello stack
 * USB host non e' implementato (non serve per l'uso previsto - sniffing/
 * iniezione a lungo termine su un ESP32 dedicato); se lo si chiama comunque
 * torna ESP_OK dopo aver fermato quello che si puo' fermare. */
esp_err_t esp_wifi_usb_deinit(void);

/* Crea il task che legge l'endpoint BULK IN e consegna i frame alla
 * callback promiscua (se impostata e abilitata). Richiede che
 * esp_wifi_usb_init() sia gia' tornato ESP_OK. */
esp_err_t esp_wifi_usb_start(void);

/* Ferma il task RX. Il chip resta acceso (per riavviare basta richiamare
 * esp_wifi_usb_start(), non serve rifare esp_wifi_usb_init()). */
esp_err_t esp_wifi_usb_stop(void);

/* ---- Promiscuous mode, ricalcato su esp_wifi_set/get_promiscuous(_rx_cb) ---- */

/* Il chip e' SEMPRE configurato in RCR promiscuo (serve per lo sniffing,
 * che e' lo scopo di questo driver - non esiste una "modalita' stazione"
 * implementata). Questa funzione quindi non tocca l'hardware: accende o
 * spegne solo la consegna dei frame alla callback, cosi' l'app puo' mettere
 * in pausa la cattura senza fermare il task RX (che deve comunque continuare
 * a svuotare l'endpoint BULK IN). */
esp_err_t esp_wifi_usb_set_promiscuous(bool en);
esp_err_t esp_wifi_usb_get_promiscuous(bool *en);
esp_err_t esp_wifi_usb_set_promiscuous_rx_cb(wifi_usb_promiscuous_cb_t cb);

/* ---- Canale, ricalcato su esp_wifi_set/get_channel ----
 * Solo banda 2.4GHz, solo 20MHz (il chip e' 1T1R b/g/n): niente parametro
 * "second" per i canali affiancati a 40MHz. Cambiare canale rilancia anche
 * LC calibration e IQ calibration, perche' sono valide solo per la
 * frequenza su cui sono state fatte (vedi rtl8188e_iqk.c). */
esp_err_t esp_wifi_usb_set_channel(uint8_t primary);
esp_err_t esp_wifi_usb_get_channel(uint8_t *primary);

/* ---- Indirizzo MAC, ricalcato su esp_wifi_get/set_mac ----
 * Il chip parte con un MAC fisso programmato in rtl8188e_power_on()
 * (70:F1:1C:5E:54:8A - e' il MAC reale della chiavetta usata per il
 * reversing, letto dalla sua efuse durante la cattura originale, non
 * inventato). esp_wifi_usb_get_mac() legge quello attualmente nel
 * registro REG_MACID (0x0610-0x0615); esp_wifi_usb_set_mac() lo
 * sovrascrive - va richiamato DOPO esp_wifi_usb_init(), altrimenti il
 * prossimo giro di power_on() lo rimette al default. */
esp_err_t esp_wifi_usb_get_mac(uint8_t mac[6]);
esp_err_t esp_wifi_usb_set_mac(const uint8_t mac[6]);

/* ---- Rate TX fisso, ricalcato su un sottoinsieme di esp_wifi_internal_set_rate ----
 * Imposta il rate usato da esp_wifi_usb_80211_tx() per OGNI frame successivo
 * (non per singolo pacchetto: il vero esp_wifi lo farebbe per-pacchetto via
 * un parametro aggiuntivo, qui e' uno stato globale per semplicita'). Il
 * default e' WIFI_USB_RATE_1M, lo stesso della cattura originale. */
esp_err_t esp_wifi_usb_set_rate(wifi_usb_phy_rate_t rate);
esp_err_t esp_wifi_usb_get_rate(wifi_usb_phy_rate_t *rate);

/* ---- Potenza TX, ricalcata su esp_wifi_set/get_max_tx_power ----
 * "power_index" e' l'indice hardware 0-63 scritto sui registri TX_AGC del
 * path A (stesso indice su tutti i gruppi di rate: un "volume" unico, non
 * la vera curva di potenza calibrata per rate). */
esp_err_t esp_wifi_usb_set_tx_power(uint8_t power_index);
esp_err_t esp_wifi_usb_get_tx_power(uint8_t *power_index);

/* Conversione indice hardware <-> dBm (0.5 dB/LSB, RTL8188E_TXGI_PER_DBM).
 * "calibration_offset_dbm" compensa l'assenza dei dati EFUSE di calibrazione
 * TSSI del chip (mai letti): di default e' 0, cioe' power_index=0 -> 0dBm,
 * power_index=63 -> +31.5dBm. Regolarlo contro una misura reale (es. con un
 * secondo dispositivo a distanza nota) se serve un valore assoluto accurato. */
esp_err_t esp_wifi_usb_set_tx_power_dbm(float dbm);
esp_err_t esp_wifi_usb_get_tx_power_dbm(float *dbm);
esp_err_t esp_wifi_usb_set_tx_power_calibration_offset(float offset_dbm);
esp_err_t esp_wifi_usb_get_tx_power_calibration_offset(float *offset_dbm);

/* Filtri hardware RX, ricalcati su esp_wifi_set/get_promiscuous_filter
 * e esp_wifi_set/get_promiscuous_ctrl_filter ----
 * Stessi tipi del vero esp_wifi (wifi_promiscuous_filter_t, WIFI_PROMIS_
 * FILTER_MASK_* e WIFI_PROMIS_CTRL_FILTER_MASK_*), applicati pero' davvero
 * in hardware sui registri REG_RXFLTMAP0/1/2 (mappe per-subtype di
 * management/control/data) invece che filtrati via software: i pacchetti
 * esclusi non arrivano nemmeno alla callback perche' il chip non li mette in
 * FIFO. WIFI_PROMIS_FILTER_MASK_MISC/DATA_MPDU/DATA_AMPDU non hanno un
 * equivalente hardware su questo chip e vengono ignorati. FCSFAIL agisce
 * sul bit RCR_ACRC32 (accetta/scarta frame con CRC errato). */
esp_err_t esp_wifi_usb_set_promiscuous_filter(const wifi_promiscuous_filter_t *filter);
esp_err_t esp_wifi_usb_get_promiscuous_filter(wifi_promiscuous_filter_t *filter);
esp_err_t esp_wifi_usb_set_promiscuous_ctrl_filter(const wifi_promiscuous_filter_t *filter);
esp_err_t esp_wifi_usb_get_promiscuous_ctrl_filter(wifi_promiscuous_filter_t *filter);

/* ---- Trasmissione grezza, ricalcata su esp_wifi_80211_tx ----
 * en_sys_seq: se true, lascia che sia il chip a numerare il campo Sequence
 * Control del frame (comportamento consigliato, come nel vero esp_wifi);
 * se false, il campo sequence/fragment del buffer passato viene inviato
 * cosi' com'e'. Da 2026-08-03: la funzione legge da sola il Frame Control
 * del buffer passato per scegliere la coda hardware giusta (beacon/gestione
 * /dati) e il bit broadcast/multicast, invece di riusare sempre lo stesso
 * template - vedi i commenti in esp_wifi_usb.c per cosa e' verificato dalla
 * cattura e cosa e' preso dal driver di riferimento. Ancora NON confermata
 * funzionante su hardware (vedi diario del progetto, causa in corso di
 * indagine). */
esp_err_t esp_wifi_usb_80211_tx(const void *buffer, int len, bool en_sys_seq);

#ifdef __cplusplus
}
#endif

#endif /* ESP_WIFI_USB_H */