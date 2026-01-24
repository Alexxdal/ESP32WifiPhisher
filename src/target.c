#include <string.h>
#include "esp_log.h"
#include "target.h"


static const char *TAG = "TARGET";

static target_info_t targets[TARGET_INFO_MAX] = { 0 };

void target_set(const target_info_t *target, target_info_type_t type)
{
    if (target == NULL) {
        ESP_LOGW(TAG, "NULL target provided to target_set");
        return;
    }
    if (type >= TARGET_INFO_MAX) {
        ESP_LOGW(TAG, "Invalid target type %d in target_set", type);
        return;
    }
    memcpy(&targets[type], target, sizeof(target_info_t));
}

target_info_t* target_get(target_info_type_t type)
{
    if (type >= TARGET_INFO_MAX) {
        ESP_LOGW(TAG, "Invalid target type %d in target_get", type);
        return NULL;
    }
    return &targets[type];
}