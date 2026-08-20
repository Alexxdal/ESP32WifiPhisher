#include "nimble/nimble_npl.h"

/* Vera implementazione fornita dal framework (quella con
 * BLE_LL_ASSERT(ev->event) che ti sta facendo crashare). */
extern void __real_npl_freertos_event_deinit(struct ble_npl_event *ev);

/* Tutte le chiamate a npl_freertos_event_deinit() dentro NimBLE/ESP-IDF
 * (dirette o via tabella di funzioni npl_funcs) finiscono qui grazie a
 * -Wl,--wrap. Replica esattamente il fix che Espressif ha introdotto
 * a partire da esp-idf v5.5, senza dover aggiornare il framework. */
void __wrap_npl_freertos_event_deinit(struct ble_npl_event *ev)
{
    if (ev == NULL || ev->event == NULL) {
        return;   /* già deinizializzato o mai inizializzato: no-op */
    }
    __real_npl_freertos_event_deinit(ev);
}