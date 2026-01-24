#include "nvs.h"
#include "esp_log.h"
#include "config.h"


static const char *TAG = "CONFIG";


void save_string_to_flash(const char* key, const char* value) 
{
    nvs_handle_t nvs_handle;
    esp_err_t err;

    err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        printf("Errore nell'aprire NVS (%s)\n", esp_err_to_name(err));
        return;
    }

    err = nvs_set_str(nvs_handle, key, value);
    if (err != ESP_OK) {
        printf("Errore nel salvare la stringa (%s)\n", esp_err_to_name(err));
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        printf("Errore nel commit della stringa (%s)\n", esp_err_to_name(err));
    }

    nvs_close(nvs_handle);
}


esp_err_t read_string_from_flash(const char* key, char* value) 
{
    nvs_handle_t nvs_handle;
    esp_err_t err;
    size_t required_size = 0;

    err = nvs_open("storage", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Errore nell'aprire NVS (%s)\n", esp_err_to_name(err));
        return ESP_FAIL;
    }

    err = nvs_get_str(nvs_handle, key, NULL, &required_size);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Errore nel leggere la dimensione della stringa (%s)\n", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return ESP_FAIL;
    }

    err = nvs_get_str(nvs_handle, key, value, &required_size);
    if (err != ESP_OK) 
    {
        ESP_LOGD(TAG, "Errore nel leggere la stringa (%s)\n", esp_err_to_name(err));
        return ESP_FAIL;
    }

    nvs_close(nvs_handle);

    return ESP_OK;
}


void save_int_to_flash(const char* key, int32_t value) 
{
    nvs_handle_t nvs_handle;
    esp_err_t err;

    err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        printf("Errore nell'aprire NVS (%s)\n", esp_err_to_name(err));
        return;
    }

    err = nvs_set_i32(nvs_handle, key, value);
    if (err != ESP_OK) {
        printf("Errore nel salvare la stringa (%s)\n", esp_err_to_name(err));
    }

    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        printf("Errore nel commit della stringa (%s)\n", esp_err_to_name(err));
    }

    nvs_close(nvs_handle);
}


esp_err_t read_int_from_flash(const char* key, int32_t *value) 
{
    nvs_handle_t nvs_handle;
    esp_err_t err;

    err = nvs_open("storage", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Errore nell'aprire NVS (%s)\n", esp_err_to_name(err));
        return ESP_FAIL;
    }

    err = nvs_get_i32(nvs_handle, key, value);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Errore lettura int32 (%s)\n", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return ESP_FAIL;
    }

    nvs_close(nvs_handle);

    return ESP_OK;
}


