#ifndef _CJSON_POOL_H
#define _CJSON_POOL_H

#include <stddef.h>
#include "esp_err.h"

/**
 * @brief Allocatore a pool per cJSON.
 *
 * cJSON costruisce ogni oggetto/array/stringa con una malloc() separata
 * (cJSON_New_Item = 1 nodo, cJSON_strdup = 1 alloc per stringa). Una singola
 * risposta JSON con decine di AP/client puo' generare centinaia di piccole
 * malloc/free tutte di dimensione variabile ma tipicamente sotto i 64 byte:
 * e' il pattern di allocazione che, su un allocatore TLSF come quello di
 * ESP-IDF, produce la frammentazione osservata (largest-block che collassa
 * sotto carico e non si riprende finche' non si fa reboot).
 *
 * Questo modulo installa in cJSON (tramite cJSON_InitHooks) un allocatore
 * "a pool": un arena statica divisa in blocchi di dimensione fissa, gestita
 * con una free-list intrusiva (nessun array di metadati separato: il
 * puntatore "next" del blocco libero e' scritto nei primi byte del blocco
 * stesso). Le richieste che entrano nel blocco vengono servite dalla pool in
 * O(1) e non lasciano MAI buchi nell'heap generale, perche' tutti i blocchi
 * sono della stessa dimensione (nessuna frammentazione esterna possibile
 * all'interno dell'arena). Le richieste piu' grandi del blocco (es. il
 * buffer di stampa JSON finale) o quelle che arrivano quando la pool e'
 * esaurita ricadono in modo trasparente su malloc()/free() standard.
 *
 * Va inizializzato UNA VOLTA, il prima possibile in app_main(), PRIMA di
 * qualunque uso di cJSON nel progetto (server_api.c, ecc.).
 */

/**
 * @brief Alloca l'arena statica, inizializza la free-list e il mutex, e
 * installa gli hook in cJSON tramite cJSON_InitHooks(). Da chiamare una sola
 * volta. Chiamate successive non hanno effetto (ritornano ESP_OK).
 *
 * @return ESP_OK se installato correttamente, ESP_ERR_NO_MEM se il mutex non
 * puo' essere creato.
 */
esp_err_t cjson_pool_init(void);

/**
 * @brief Statistiche correnti della pool, utili per capire (via console,
 * vedi il comando "cjson-pool-stats") se la dimensione dell'arena e' ben
 * dimensionata rispetto al carico reale del dispositivo.
 *
 * @param out_free_blocks   Blocchi attualmente liberi nella free-list.
 * @param out_total_blocks  Blocchi totali nell'arena (CJSON_POOL_BLOCK_COUNT).
 * @param out_min_free_ever Minimo storico di blocchi liberi mai osservato
 *                          (piu' e' vicino a 0, piu' la pool si e' avvicinata
 *                          all'esaurimento).
 * @param out_fallback_count Numero di allocazioni che sono ricadute su
 *                          malloc() standard (richieste troppo grandi per un
 *                          blocco, o pool esaurita in quel momento). Un
 *                          valore alto e persistente e' un segnale che vale
 *                          la pena aumentare CJSON_POOL_BLOCK_COUNT.
 *
 * Ogni puntatore di output puo' essere NULL se quel valore non interessa.
 */
void cjson_pool_get_stats(size_t *out_free_blocks, size_t *out_total_blocks,
                           size_t *out_min_free_ever, size_t *out_fallback_count);

#endif /* _CJSON_POOL_H */
