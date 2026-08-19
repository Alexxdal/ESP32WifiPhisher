#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <cJSON.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "cjson_pool.h"

static const char *TAG = "CJSON_POOL";

#define CJSON_POOL_BLOCK_SIZE   64
#define CJSON_POOL_BLOCK_COUNT  256
#define CJSON_POOL_TOTAL_BYTES  (CJSON_POOL_BLOCK_SIZE * CJSON_POOL_BLOCK_COUNT)  /* 16 KB */

typedef struct pool_free_node {
    struct pool_free_node *next;
} pool_free_node_t;

/* Allineata a 8 byte: un blocco puo' ospitare un cJSON (che contiene un
 * "double") e su alcuni target un accesso non allineato a un double e' un
 * hard fault, non solo una penalita' di performance. CJSON_POOL_BLOCK_SIZE
 * e' multiplo di 8, quindi se l'arena parte allineata ogni blocco lo resta. */
static uint8_t s_pool_arena[CJSON_POOL_TOTAL_BYTES] __attribute__((aligned(8)));

static pool_free_node_t *s_free_list = NULL;
static SemaphoreHandle_t s_pool_mutex = NULL;

static size_t s_free_blocks    = 0;
static size_t s_min_free_ever  = 0;
static size_t s_fallback_count = 0;


static void *cjson_pool_malloc(size_t size)
{
    if (s_pool_mutex == NULL) {
        return malloc(size);
    }

    void *result = NULL;
    bool need_fallback = false;

    if (xSemaphoreTake(s_pool_mutex, portMAX_DELAY) == pdTRUE) {
        if (size > 0 && size <= CJSON_POOL_BLOCK_SIZE && s_free_list != NULL) {
            pool_free_node_t *node = s_free_list;
            s_free_list = node->next;
            s_free_blocks--;
            if (s_free_blocks < s_min_free_ever) {
                s_min_free_ever = s_free_blocks;
            }
            result = (void *)node;
        } else {
            s_fallback_count++;
            need_fallback = true;
        }
        xSemaphoreGive(s_pool_mutex);
    } else {
        need_fallback = true;
    }

    if (need_fallback) {
        return malloc(size);
    }
    return result;
}


static void cjson_pool_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }

    uint8_t *p = (uint8_t *)ptr;
    bool belongs_to_pool = (s_pool_mutex != NULL) &&
                           (p >= s_pool_arena) &&
                           (p < (s_pool_arena + CJSON_POOL_TOTAL_BYTES));

    if (belongs_to_pool) {
        if (xSemaphoreTake(s_pool_mutex, portMAX_DELAY) == pdTRUE) {
            pool_free_node_t *node = (pool_free_node_t *)ptr;
            node->next = s_free_list;
            s_free_list = node;
            s_free_blocks++;
            xSemaphoreGive(s_pool_mutex);
        }
        return;
    }

    free(ptr);
}


esp_err_t cjson_pool_init(void)
{
    if (s_pool_mutex != NULL) {
        return ESP_OK; /* gia' inizializzata */
    }

    s_pool_mutex = xSemaphoreCreateMutex();
    if (s_pool_mutex == NULL) {
        ESP_LOGE(TAG, "Impossibile creare il mutex della pool!");
        return ESP_ERR_NO_MEM;
    }

    s_free_list = NULL;
    for (int i = CJSON_POOL_BLOCK_COUNT - 1; i >= 0; i--) {
        pool_free_node_t *node = (pool_free_node_t *)(s_pool_arena + (size_t)i * CJSON_POOL_BLOCK_SIZE);
        node->next = s_free_list;
        s_free_list = node;
    }
    s_free_blocks   = CJSON_POOL_BLOCK_COUNT;
    s_min_free_ever = CJSON_POOL_BLOCK_COUNT;
    s_fallback_count = 0;

    cJSON_Hooks hooks = {
        .malloc_fn = cjson_pool_malloc,
        .free_fn   = cjson_pool_free,
    };
    cJSON_InitHooks(&hooks);

    ESP_LOGI(TAG, "cJSON pool attiva: %d blocchi x %d byte = %d byte (arena statica).",
             CJSON_POOL_BLOCK_COUNT, CJSON_POOL_BLOCK_SIZE, CJSON_POOL_TOTAL_BYTES);
    return ESP_OK;
}


void cjson_pool_get_stats(size_t *out_free_blocks, size_t *out_total_blocks,
                           size_t *out_min_free_ever, size_t *out_fallback_count)
{
    size_t free_blocks = 0, min_free_ever = 0, fallback_count = 0;

    if (s_pool_mutex != NULL && xSemaphoreTake(s_pool_mutex, portMAX_DELAY) == pdTRUE) {
        free_blocks    = s_free_blocks;
        min_free_ever  = s_min_free_ever;
        fallback_count = s_fallback_count;
        xSemaphoreGive(s_pool_mutex);
    }

    if (out_free_blocks != NULL)    *out_free_blocks = free_blocks;
    if (out_total_blocks != NULL)   *out_total_blocks = CJSON_POOL_BLOCK_COUNT;
    if (out_min_free_ever != NULL)  *out_min_free_ever = min_free_ever;
    if (out_fallback_count != NULL) *out_fallback_count = fallback_count;
}
