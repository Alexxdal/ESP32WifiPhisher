#ifndef _BLE_MNG_H
#define _BLE_MNG_H

#include <esp_err.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Ciclo di vita dello stack NimBLE (host + controller), gestito a
 * mano dal chiamante -- nessun refcount, nessuno start/stop automatico.
 * Chi chiama ble_init() è responsabile di chiamare ble_deinit() quando
 * non serve più, e di coordinarsi con eventuali altri moduli BLE (es.
 * ble_sniffer + un futuro ble_spam) se entrambi usano lo stack insieme:
 * qui non c'è nessuna protezione automatica contro un modulo che fa
 * deinit mentre un altro sta ancora scansionando/advertisando.
 */

/**
 * @brief Porta su lo stack NimBLE: nimble_port_init() + host task +
 * preferenza coex. Idempotente: se lo stack è già su non fa nulla e
 * ritorna ESP_OK. Il sync con il controller è asincrono -- vedi
 * ble_is_ready().
 */
esp_err_t ble_init(void);

/**
 * @brief Ferma l'host task e fa il deinit completo (nimble_port_deinit(),
 * RAM liberata per davvero -- vedi npl_event_deinit_fix.c per il perché
 * serve il --wrap). Idempotente: se lo stack non è su non fa nulla e
 * ritorna ESP_OK.
 */
esp_err_t ble_deinit(void);

/**
 * @brief True una volta che l'host NimBLE ha finito il sync con il
 * controller dopo l'ultima ble_init() -- solo allora ble_gap_disc()/
 * ble_gap_adv_start()/etc. sono sicure da chiamare.
 */
bool ble_is_ready(void);

/**
 * @brief Own address type inferito al sync (vedi ble_hs_id_infer_auto),
 * serve sia a ble_gap_disc() che a ble_gap_adv_start().
 */
uint8_t ble_get_own_addr_type(void);

#endif
