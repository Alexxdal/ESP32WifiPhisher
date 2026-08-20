#ifndef _BLE_SPAM_H
#define _BLE_SPAM_H

#include <esp_err.h>
#include <stdbool.h>

/*
 * BLE advertising flood: manda pacchetti non connettibili che imitano i
 * protocolli di pairing/discovery dei vari vendor (Apple Continuity,
 * Samsung, Google Fast Pair, Microsoft Swift Pair) per far comparire i
 * popup di pairing sui dispositivi vicini -- stessa tecnica di
 * "Sour Apple"/"Apple Juice"/"Samsung/Google/Swiftpair Spam" di
 * ESP32Marauder e del BLE spam di GhostESP.
 *
 * Struttura ripresa da (verifica/estendi da qui se vuoi payload più
 * fedeli, soprattutto Samsung e i codici Nearby Action -- vedi i commenti
 * su ogni tabella in ble_spam.c per il livello di confidenza):
 *  - https://github.com/justcallmekoko/ESP32Marauder (wiki: Samsung/Swiftpair/BT-Spam-All)
 *  - https://github.com/Spooks4576/Ghost_ESP
 *  - https://github.com/noproto/apple_ble_spam_ofw (Flipper Zero, tabella modelli AirPods)
 */

typedef enum {
    BLE_SPAM_APPLE = 0,   /* Proximity Pairing (AirPods-style) + Nearby Action */
    BLE_SPAM_SAMSUNG,     /* Galaxy Buds/Watch discovery -- vedi caveat in ble_spam.c */
    BLE_SPAM_GOOGLE,      /* Fast Pair (Android) */
    BLE_SPAM_MICROSOFT,   /* Swift Pair (Windows) */
    BLE_SPAM_ALL,         /* ruota su tutti i vendor sopra, uno a burst */
} ble_spam_type_t;

/**
 * @brief Avvia il flood. Richiede che ble_init() (bleMng.h) sia già
 * stato chiamato e che lo stack sia sincronizzato (ble_is_ready()) --
 * questo modulo non tocca il ciclo di vita di NimBLE, stessa convenzione
 * di ble_sniffer.c. Ogni burst usa un indirizzo sorgente casuale
 * (non-resolvable private address) diverso dal precedente.
 */
esp_err_t ble_spam_start(ble_spam_type_t type);

/**
 * @brief Ferma il flood. Aspetta che il task interno confermi l'uscita
 * (e killa comunque un eventuale burst ancora in volo) prima di tornare.
 */
esp_err_t ble_spam_stop(void);

bool ble_spam_is_running(void);

#endif
