#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_spiffs.h"
#include "esp_log.h"
#include "passwordMng.h"
#include "libpcap.h"
#include "sniffer.h"


static const char *TAG = "PASSWORD_MANAGER";
static QueueHandle_t password_queue = NULL;
static uint8_t *pcap_pointer = NULL;
#define PASSWORD_FILE "/spiffs/passwords.txt"
#define QUEUE_LENGTH 4
#define PASSWORD_ITEM_SIZE 128


static esp_err_t password_manager_check_space(size_t data_to_write)
{
    size_t total = 0, used = 0;
    if (esp_spiffs_info(NULL, &total, &used) != ESP_OK) 
    {
        return ESP_FAIL;
    }
    /* Check space */
    if ((total - used) < data_to_write)
    {
        ESP_LOGE(TAG, "Not enough space!");
        return ESP_FAIL;
    }

    return ESP_OK;
}


static void password_manager_save_spiffs(char *text)
{
    if(password_manager_check_space(strlen(text)) != ESP_OK )
    {
        return;
    }

    FILE *file = fopen(PASSWORD_FILE, "a");
    if (file == NULL) {
        ESP_LOGE(TAG, "Unable to open %s file!", PASSWORD_FILE);
        return;
    }

    fprintf(file, "%s\n", text);
    fflush(file);
    fclose(file);
}


static void password_manager_task(void *arg)
{
    char text_buffer[PASSWORD_ITEM_SIZE] = { 0 };

    while (1) {
        if (xQueueReceive(password_queue, text_buffer, pdMS_TO_TICKS(100))) {
            password_manager_save_spiffs(text_buffer);
        }
    }
}


esp_err_t password_manager_init(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs", // Percorso di base per accedere ai file
        .partition_label = NULL,
        .max_files = 5,        // Numero massimo di file aperti contemporaneamente
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error mounting SPIFFS: (%s)", esp_err_to_name(ret));
        return ESP_FAIL;
    }

    ret = esp_spiffs_check(conf.partition_label);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPIFFS_check() failed (%s)", esp_err_to_name(ret));
        return ESP_FAIL;
    }

    password_queue = xQueueCreate(QUEUE_LENGTH, PASSWORD_ITEM_SIZE);
    if (password_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create queue!");
        return ESP_FAIL;
    }

    xTaskCreate(password_manager_task, "password_manager_task", 4096, NULL, 5, NULL);
    return ESP_OK;
}


void password_manager_save(char *text)
{
    if (strlen(text) >= PASSWORD_ITEM_SIZE) {
        ESP_LOGE(TAG, "Text too large to save in queue");
        return;
    }
    if (xQueueSend(password_queue, text, pdMS_TO_TICKS(500)) != pdPASS) {
        ESP_LOGE(TAG, "Failed to enqueue password for saving");
    }
}


void password_manager_read_passwords(httpd_req_t *req)
{
    /* Check if the queue is empty */
    if (uxQueueMessagesWaiting(password_queue) != 0)
    {
        return;
    }

    char buffer[256] = { 0 };
    size_t bytesRead = 0;

    FILE *file = fopen(PASSWORD_FILE, "r");
    if (file == NULL) {
        ESP_LOGE(TAG, "Unable to open %s file!", PASSWORD_FILE);
        return;
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");
    while ((bytesRead = fread(buffer, 1, 256, file)) > 0) 
    {
        httpd_resp_send_chunk(req, buffer, bytesRead);
    }
    httpd_resp_send_chunk(req, NULL, 0);

    fclose(file);
}


void password_manager_clean(void)
{
    FILE *file = fopen(PASSWORD_FILE, "w");
    if (file == NULL) {
        ESP_LOGE(TAG, "Unable to open %s file!", PASSWORD_FILE);
        return;
    }
    fclose(file);
}


void password_manager_append_frame(const uint8_t *buffer, int len, int us)
{
    pcap_serializer_append_frame(buffer, len, us);
}


void password_manager_pcap_finalize(void)
{
    uint32_t pcap_size = pcap_serializer_get_size();
    uint8_t *pcap_data = pcap_serializer_get_buffer();
    if(password_manager_check_space(pcap_size) != ESP_OK )
    {
        return;
    }

    char filename[32] = { 0 };
    const handshake_info_t *target = wifi_sniffer_get_handshake();
    const uint8_t *mac = (const uint8_t *)target->mac_sta;
    snprintf(filename, sizeof(filename), "/spiffs/%02X_%02X_%02X_%02X_%02X_%02X.pcap",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        ESP_LOGE(TAG, "Unable to open %s file!", filename);
        return;
    }

    fwrite(pcap_data, 1, pcap_size, file);
    fflush(file);
    fclose(file);

    ESP_LOGI(TAG, "PCAP Saved with filename: %s", filename);
}