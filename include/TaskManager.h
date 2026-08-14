#ifndef _TASK_MANAGER_H
#define _TASK_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"


#define TASK_MANAGER_MAX_TASKS     24

#define TASK_MANAGER_NAME_MAX_LEN  16

/**
 * @brief Inizializza il registro. Va chiamata una sola volta, il prima
 * possibile in app_main(), PRIMA di qualunque modulo che crei un task
 * tramite task_manager_create_task() (compreso esp_wifi_usb_init() su
 * S2/S3, che parte molto presto).
 */
esp_err_t task_manager_init(void);


/**
 * @brief Crea un nuovo task e lo registra. Sostituto drop-in di
 * xTaskCreate(): stessi parametri, nello stesso ordine.
 *
 * Rifiuta la creazione (ESP_ERR_INVALID_STATE) se esiste gia' un task
 * registrato con lo stesso nome, per evitare doppie istanze dello stesso
 * worker se un modulo dimentica il proprio controllo "e' gia' partito?".
 *
 * @return ESP_OK se creato e registrato correttamente
 *         ESP_ERR_INVALID_ARG se entry o name sono NULL
 *         ESP_ERR_INVALID_STATE se un task con lo stesso nome e' gia' registrato
 *         ESP_ERR_NO_MEM se il registro e' pieno o xTaskCreate() fallisce
 */
esp_err_t task_manager_create_task(TaskFunction_t entry,
                                    const char *name,
                                    uint32_t stack_size_bytes,
                                    void *arg,
                                    UBaseType_t priority,
                                    TaskHandle_t *out_handle);


/**
 * @brief Da chiamare DALL'INTERNO del task stesso, subito prima di
 * terminare con vTaskDelete(NULL) (auto-eliminazione). Rimuove il task dal
 * registro. Da usare al posto di task_manager_delete_task_by_handle() ogni
 * volta che e' il task stesso a decidere di uscire dal proprio ciclo di
 * vita, non un chiamante esterno.
 *
 * Esempio d'uso (fine tipica di un *_task()):
 *     task_manager_unregister_current_task();
 *     vTaskDelete(NULL);
 */
void task_manager_unregister_current_task(void);


/**
 * @brief Elimina forzatamente un task ancora registrato (wrapper di
 * vTaskDelete) e lo rimuove dal registro. Da usare SOLO quando non e'
 * disponibile un meccanismo di stop cooperativo (event group / flag +
 * attesa che il task esca da solo): una vTaskDelete "a freddo" non da' modo
 * al task di rilasciare mutex, chiudere socket o liberare memoria che
 * stesse usando in quel momento.
 */
esp_err_t task_manager_delete_task(const char *name);
esp_err_t task_manager_delete_task_by_handle(TaskHandle_t handle);


/**
 * @brief Cerca l'handle di un task registrato per nome. Ritorna NULL se non
 * trovato (nome sbagliato o task non piu' in esecuzione).
 */
TaskHandle_t task_manager_get_handle(const char *name);


/**
 * @brief true se un task con quel nome e' attualmente registrato.
 */
bool task_manager_is_running(const char *name);


/**
 * @brief Numero di task attualmente registrati.
 */
int task_manager_get_task_count(void);


/**
 * @brief Stack libero al minimo storico (high water mark), in BYTE.
 * Nota: su ESP-IDF sia xTaskCreate() che uxTaskGetStackHighWaterMark()
 * lavorano in byte, non in "word" come nel FreeRTOS vanilla.
 * Piu' il valore e' vicino a 0, piu' quel task si e' avvicinato a un
 * overflow dello stack. Ritorna 0 se il task non e' registrato.
 */
uint32_t task_manager_get_free_stack_bytes(const char *name);
uint32_t task_manager_get_free_stack_bytes_by_handle(TaskHandle_t handle);


/**
 * @brief Logga (ESP_LOGI/ESP_LOGW) lo stato di stack di un singolo task:
 * stack dichiarato in creazione, minimo storico libero, percentuale di
 * picco utilizzata.
 */
void task_manager_log_stack_usage(const char *name);


/**
 * @brief Logga lo stato di stack di TUTTI i task registrati, ordinati per
 * percentuale di picco utilizzata (decrescente): in cima i task piu' a
 * rischio overflow, in fondo quelli con piu' margine e quindi candidati a
 * una riduzione dello stack dichiarato (per risparmiare DRAM, vedi anche il
 * problema di dram0_0_seg su ESP32-S2).
 */
void task_manager_log_all_stack_usage(void);


/**
 * @brief true se almeno un task registrato ha uno stack libero (minimo
 * storico) sotto la soglia indicata. Logga un ESP_LOGW per ogni task sotto
 * soglia. Pensata per essere chiamata periodicamente (es. da un timer o dal
 * loop di un task di monitoraggio) come "canary" contro overflow silenziosi.
 */
bool task_manager_check_low_stack(uint32_t threshold_bytes);


/**
 * @brief Stampa (ESP_LOGI) un riepilogo tabellare di tutti i task
 * registrati: nome, priorita', stack dichiarato, stack libero al minimo
 * storico.
 */
void task_manager_print_summary(void);

#endif /* _TASK_MANAGER_H */
