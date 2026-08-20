#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "TaskManager.h"

static const char *TAG = "TASK_MANAGER";

typedef struct {
    char         name[TASK_MANAGER_NAME_MAX_LEN];
    TaskHandle_t handle;
    uint32_t     stack_size_bytes;
    UBaseType_t  priority;
    bool         in_use;
} task_manager_entry_t;

static task_manager_entry_t s_tasks[TASK_MANAGER_MAX_TASKS];
static SemaphoreHandle_t    s_lock = NULL;


esp_err_t task_manager_init(void)
{
    if (s_lock != NULL) {
        return ESP_OK;
    }

    memset(s_tasks, 0, sizeof(s_tasks));

    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) {
        ESP_LOGE(TAG, "Impossibile creare il mutex del registro!");
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "TaskManager initialized (max task %d).", TASK_MANAGER_MAX_TASKS);
    return ESP_OK;
}


esp_err_t task_manager_create_task(TaskFunction_t entry,
                                    const char *name,
                                    uint32_t stack_size_bytes,
                                    void *arg,
                                    UBaseType_t priority,
                                    TaskHandle_t *out_handle)
{
    if (out_handle != NULL) {
        *out_handle = NULL;
    }

    if (entry == NULL || name == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (s_lock == NULL) {
        ESP_LOGE(TAG, "task_manager_create_task('%s') chiamata prima di task_manager_init()!", name);
        return ESP_ERR_INVALID_STATE;
    }

    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    /* Rifiuta la creazione se un task con lo stesso nome e' gia' registrato,
     * per evitare doppie istanze dello stesso worker. */
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use && strncmp(s_tasks[i].name, name, TASK_MANAGER_NAME_MAX_LEN) == 0) {
            xSemaphoreGive(s_lock);
            ESP_LOGW(TAG, "Task '%s' e' gia' registrato, creazione ignorata.", name);
            return ESP_ERR_INVALID_STATE;
        }
    }

    int slot = -1;
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (!s_tasks[i].in_use) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        xSemaphoreGive(s_lock);
        ESP_LOGE(TAG, "Registro pieno (max %d task), impossibile creare '%s'.", TASK_MANAGER_MAX_TASKS, name);
        return ESP_ERR_NO_MEM;
    }

    /* Riserva subito lo slot (prima di xTaskCreate) cosi' due create
     * concorrenti con lo stesso nome non possono correre sullo stesso slot. */
    strncpy(s_tasks[slot].name, name, TASK_MANAGER_NAME_MAX_LEN - 1);
    s_tasks[slot].name[TASK_MANAGER_NAME_MAX_LEN - 1] = '\0';
    s_tasks[slot].stack_size_bytes = stack_size_bytes;
    s_tasks[slot].priority = priority;
    s_tasks[slot].handle = NULL;
    s_tasks[slot].in_use = true;

    TaskHandle_t handle = NULL;
    BaseType_t ok = xTaskCreate(entry, name, stack_size_bytes, arg, priority, &handle);
    if (ok != pdPASS) {
        s_tasks[slot].in_use = false;
        xSemaphoreGive(s_lock);
        ESP_LOGE(TAG, "xTaskCreate() fallita per '%s'.", name);
        return ESP_ERR_NO_MEM;
    }

    s_tasks[slot].handle = handle;
    xSemaphoreGive(s_lock);

    if (out_handle != NULL) {
        *out_handle = handle;
    }
    return ESP_OK;
}


void task_manager_unregister_current_task(void)
{
    if (s_lock == NULL) {
        return;
    }

    TaskHandle_t self = xTaskGetCurrentTaskHandle();

    /* Timeout invece di portMAX_DELAY: e' l'ultima cosa che il task fa prima
     * di autodistruggersi, meglio uscire comunque piuttosto che restare
     * bloccati se per qualche motivo il lock non si libera mai. */
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGW(TAG, "task_manager_unregister_current_task: timeout sul lock, entry non rimossa.");
        return;
    }

    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use && s_tasks[i].handle == self) {
            memset(&s_tasks[i], 0, sizeof(s_tasks[i]));
            break;
        }
    }
    xSemaphoreGive(s_lock);
}


esp_err_t task_manager_delete_task_by_handle(TaskHandle_t handle)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    bool found = false;
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use && s_tasks[i].handle == handle) {
            memset(&s_tasks[i], 0, sizeof(s_tasks[i]));
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_lock);

    if (!found) {
        ESP_LOGW(TAG, "task_manager_delete_task_by_handle: handle non registrato.");
    }

    vTaskDelete(handle);
    return ESP_OK;
}


esp_err_t task_manager_delete_task(const char *name)
{
    if (name == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    TaskHandle_t handle = task_manager_get_handle(name);
    if (handle == NULL) {
        ESP_LOGW(TAG, "task_manager_delete_task: '%s' non registrato.", name);
        return ESP_ERR_NOT_FOUND;
    }
    return task_manager_delete_task_by_handle(handle);
}


TaskHandle_t task_manager_get_handle(const char *name)
{
    if (name == NULL || s_lock == NULL) {
        return NULL;
    }

    TaskHandle_t result = NULL;

    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return NULL;
    }
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use && strncmp(s_tasks[i].name, name, TASK_MANAGER_NAME_MAX_LEN) == 0) {
            result = s_tasks[i].handle;
            break;
        }
    }
    xSemaphoreGive(s_lock);
    return result;
}


bool task_manager_is_running(const char *name)
{
    return task_manager_get_handle(name) != NULL;
}


int task_manager_get_task_count(void)
{
    if (s_lock == NULL) {
        return 0;
    }

    int count = 0;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return 0;
    }
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use) {
            count++;
        }
    }
    xSemaphoreGive(s_lock);
    return count;
}


uint32_t task_manager_get_free_stack_bytes_by_handle(TaskHandle_t handle)
{
    if (handle == NULL) {
        return 0;
    }
    /* Su ESP-IDF uxTaskGetStackHighWaterMark() ritorna gia' i BYTE liberi al
     * minimo storico (a differenza del FreeRTOS "vanilla" che ritorna le
     * word). INCLUDE_uxTaskGetStackHighWaterMark e' sempre abilitata in
     * ESP-IDF, non richiede nessuna opzione di Kconfig. */
    return (uint32_t)uxTaskGetStackHighWaterMark(handle);
}


uint32_t task_manager_get_free_stack_bytes(const char *name)
{
    TaskHandle_t handle = task_manager_get_handle(name);
    if (handle == NULL) {
        return 0;
    }
    return task_manager_get_free_stack_bytes_by_handle(handle);
}


void task_manager_log_stack_usage(const char *name)
{
    if (name == NULL || s_lock == NULL) {
        return;
    }

    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return;
    }

    int slot = -1;
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use && strncmp(s_tasks[i].name, name, TASK_MANAGER_NAME_MAX_LEN) == 0) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        xSemaphoreGive(s_lock);
        ESP_LOGW(TAG, "task_manager_log_stack_usage: '%s' not registered.", name);
        return;
    }

    task_manager_entry_t entry = s_tasks[slot];
    xSemaphoreGive(s_lock);

    uint32_t free_bytes = task_manager_get_free_stack_bytes_by_handle(entry.handle);
    uint32_t used_peak = (entry.stack_size_bytes > free_bytes) ? (entry.stack_size_bytes - free_bytes) : entry.stack_size_bytes;
    float used_pct = (entry.stack_size_bytes > 0) ? (100.0f * (float)used_peak / (float)entry.stack_size_bytes) : 0.0f;
    const char *warn = (free_bytes < 256) ? "  <-- WARNING: Overflow risk!" : "";

    ESP_LOGI(TAG, "[%-16s] stack=%5u B  free(min)=%5u B  peak usage=%.1f%%%s",
             entry.name, (unsigned)entry.stack_size_bytes, (unsigned)free_bytes, used_pct, warn);
}


void task_manager_log_all_stack_usage(void)
{
    if (s_lock == NULL) {
        return;
    }

    task_manager_entry_t snapshot[TASK_MANAGER_MAX_TASKS];
    int count = 0;

    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return;
    }
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use) {
            snapshot[count++] = s_tasks[i];
        }
    }
    xSemaphoreGive(s_lock);

    if (count == 0) {
        ESP_LOGI(TAG, "Nessun task registrato.");
        return;
    }

    uint32_t free_b[TASK_MANAGER_MAX_TASKS];
    float pct[TASK_MANAGER_MAX_TASKS];
    for (int i = 0; i < count; i++) {
        free_b[i] = task_manager_get_free_stack_bytes_by_handle(snapshot[i].handle);
        uint32_t used_peak = (snapshot[i].stack_size_bytes > free_b[i]) ? (snapshot[i].stack_size_bytes - free_b[i]) : snapshot[i].stack_size_bytes;
        pct[i] = (snapshot[i].stack_size_bytes > 0) ? (100.0f * (float)used_peak / (float)snapshot[i].stack_size_bytes) : 0.0f;
    }

    /* Insertion sort decrescente per percentuale di picco: in cima i task
     * piu' a rischio overflow, in fondo quelli con piu' margine (candidati a
     * ridurre lo stack dichiarato per risparmiare DRAM). N e' piccolo
     * (< TASK_MANAGER_MAX_TASKS = 24) quindi non serve altro. */
    for (int i = 1; i < count; i++) {
        task_manager_entry_t e = snapshot[i];
        float p = pct[i];
        uint32_t f = free_b[i];
        int j = i - 1;
        while (j >= 0 && pct[j] < p) {
            snapshot[j + 1] = snapshot[j];
            pct[j + 1] = pct[j];
            free_b[j + 1] = free_b[j];
            j--;
        }
        snapshot[j + 1] = e;
        pct[j + 1] = p;
        free_b[j + 1] = f;
    }

    ESP_LOGI(TAG, "=== TaskManager: utilizzo stack (%d task registrati) ===", count);
    for (int i = 0; i < count; i++) {
        const char *warn = (free_b[i] < 256) ? "  <-- WARNING: Overflow risk!" : "";
        ESP_LOGI(TAG, "[%-16s] stack=%5u B  free(min)=%5u B  peak usage=%.1f%%%s",
                 snapshot[i].name, (unsigned)snapshot[i].stack_size_bytes, (unsigned)free_b[i], pct[i], warn);
    }
}


bool task_manager_check_low_stack(uint32_t threshold_bytes)
{
    if (s_lock == NULL) {
        return false;
    }

    task_manager_entry_t snapshot[TASK_MANAGER_MAX_TASKS];
    int count = 0;

    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return false;
    }
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use) {
            snapshot[count++] = s_tasks[i];
        }
    }
    xSemaphoreGive(s_lock);

    bool any_low = false;
    for (int i = 0; i < count; i++) {
        uint32_t free_bytes = task_manager_get_free_stack_bytes_by_handle(snapshot[i].handle);
        if (free_bytes < threshold_bytes) {
            ESP_LOGW(TAG, "Task '%s' sotto soglia: %u B liberi (soglia %u B).",
                     snapshot[i].name, (unsigned)free_bytes, (unsigned)threshold_bytes);
            any_low = true;
        }
    }
    return any_low;
}


void task_manager_print_summary(void)
{
    if (s_lock == NULL) {
        ESP_LOGW(TAG, "TaskManager non ancora inizializzato.");
        return;
    }

    task_manager_entry_t snapshot[TASK_MANAGER_MAX_TASKS];
    int count = 0;

    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return;
    }
    for (int i = 0; i < TASK_MANAGER_MAX_TASKS; i++) {
        if (s_tasks[i].in_use) {
            snapshot[count++] = s_tasks[i];
        }
    }
    xSemaphoreGive(s_lock);

    ESP_LOGI(TAG, "=== TaskManager: %d/%d task registrati ===", count, TASK_MANAGER_MAX_TASKS);
    for (int i = 0; i < count; i++) {
        uint32_t free_bytes = task_manager_get_free_stack_bytes_by_handle(snapshot[i].handle);
        ESP_LOGI(TAG, "  %-16s prio=%2u  stack=%5u B  free(min)=%5u B",
                 snapshot[i].name, (unsigned)snapshot[i].priority,
                 (unsigned)snapshot[i].stack_size_bytes, (unsigned)free_bytes);
    }
}
