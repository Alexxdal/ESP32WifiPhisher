#include "rtl8188e_usb.h"

static const char *TAG = "RTL8188_USB";

/** 
 * @brief USB Control Transfer Callback
 */
static void control_transfer_cb(usb_transfer_t *transfer) 
{
    SemaphoreHandle_t sync_sem = (SemaphoreHandle_t)transfer->context;
    xSemaphoreGive(sync_sem);
}

/**
 * @brief Helper function to read 1 byte from a Realtek register
 */
uint8_t rtl_read8(usb_device_handle_t dev_hdl, uint16_t reg_addr) 
{
    usb_transfer_t *transfer;
    ESP_ERROR_CHECK(usb_host_transfer_alloc(sizeof(usb_setup_packet_t) + 1, 0, &transfer));
    SemaphoreHandle_t sync_sem = xSemaphoreCreateBinary();
    
    // Realtek Control Transfer Setup Packet
    usb_setup_packet_t *req = (usb_setup_packet_t *)transfer->data_buffer;
    req->bmRequestType = REALTEK_USB_VENQT_READ;    // Direction: IN | Type: VENDOR | Recipient: DEVICE
    req->bRequest = REALTEK_USB_VENQT_CMD_REQ;      // Realtek command per R/W Register
    req->wValue = reg_addr;                         // Indirizzo del registro (es. 0x0000)
    req->wIndex = REALTEK_USB_VENQT_CMD_IDX;        // Index (Not used)
    req->wLength = 1;                               // Byte to read
    
    transfer->num_bytes = sizeof(usb_setup_packet_t) + 1;
    transfer->device_handle = dev_hdl;
    transfer->bEndpointAddress = 0x00; // Endpoint 0 (Control)
    transfer->callback = control_transfer_cb;
    transfer->context = sync_sem;
    
    esp_err_t err = usb_host_transfer_submit_control(global_client_hdl, transfer);
    if(err == ESP_OK) {
        if (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(2000)) == pdTRUE) {
            if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
                ESP_LOGE(TAG, "Transfer failed (STALL or bus error). Status: %d", transfer->status);
                err = ESP_FAIL; 
            }
        } else {
            ESP_LOGE(TAG, "USB transfer timeout!");
            err = ESP_ERR_TIMEOUT;
        }
    }

    uint8_t read_value = transfer->data_buffer[sizeof(usb_setup_packet_t)];
    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sync_sem);
    return read_value;
}

/**
 * @brief Helper function to write 1 byte to a Realtek register
 */
esp_err_t rtl_write8(usb_device_handle_t dev_hdl, uint16_t reg_addr, uint8_t value) 
{
    usb_transfer_t *transfer;
    esp_err_t err = usb_host_transfer_alloc(sizeof(usb_setup_packet_t) + 1, 0, &transfer);
    if (err != ESP_OK) return err;

    SemaphoreHandle_t sync_sem = xSemaphoreCreateBinary();
    
    usb_setup_packet_t *req = (usb_setup_packet_t *)transfer->data_buffer;
    req->bmRequestType = REALTEK_USB_VENQT_WRITE;       // Direction: OUT | Type: VENDOR | Recipient: DEVICE
    req->bRequest = REALTEK_USB_VENQT_CMD_REQ;          // Realtek command per R/W Register
    req->wValue = reg_addr;                             // Indirizzo del registro
    req->wIndex = REALTEK_USB_VENQT_CMD_IDX;
    req->wLength = 1;                                   // Byte to write
    
    transfer->data_buffer[sizeof(usb_setup_packet_t)] = value;
    transfer->num_bytes = sizeof(usb_setup_packet_t) + 1;
    transfer->device_handle = dev_hdl;
    transfer->bEndpointAddress = 0x00; // Endpoint 0
    transfer->callback = control_transfer_cb;
    transfer->context = sync_sem;
    
    err = usb_host_transfer_submit_control(global_client_hdl, transfer);
    if(err == ESP_OK) {
        if (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(2000)) == pdTRUE) {
            if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
                ESP_LOGE(TAG, "Transfer failed (STALL or bus error). Status: %d", transfer->status);
                err = ESP_FAIL; 
            }
        } else {
            ESP_LOGE(TAG, "USB transfer timeout!");
            err = ESP_ERR_TIMEOUT;
        }
    }
 
    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sync_sem);
    return err;
}

/**
 * @brief Helper function to read 2 bytes (16 bits) from a Realtek register
 */
uint16_t rtl_read16(usb_device_handle_t dev_hdl, uint16_t reg_addr) 
{
    usb_transfer_t *transfer;
    ESP_ERROR_CHECK(usb_host_transfer_alloc(sizeof(usb_setup_packet_t) + 2, 0, &transfer));
    SemaphoreHandle_t sync_sem = xSemaphoreCreateBinary();
    
    usb_setup_packet_t *req = (usb_setup_packet_t *)transfer->data_buffer;
    req->bmRequestType = REALTEK_USB_VENQT_READ;
    req->bRequest = REALTEK_USB_VENQT_CMD_REQ;
    req->wValue = reg_addr;
    req->wIndex = REALTEK_USB_VENQT_CMD_IDX;
    req->wLength = 2;
    
    transfer->num_bytes = sizeof(usb_setup_packet_t) + 2;
    transfer->device_handle = dev_hdl;
    transfer->bEndpointAddress = 0x00;
    transfer->callback = control_transfer_cb;
    transfer->context = sync_sem;
    
    esp_err_t err = usb_host_transfer_submit_control(global_client_hdl, transfer);
    if(err == ESP_OK) {
        if (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(2000)) == pdTRUE) {
            if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
                ESP_LOGE(TAG, "Transfer failed (STALL or bus error). Status: %d", transfer->status);
                err = ESP_FAIL; 
            }
        } else {
            ESP_LOGE(TAG, "USB transfer timeout!");
            err = ESP_ERR_TIMEOUT;
        }
    }

    uint16_t read_value = transfer->data_buffer[8] | (transfer->data_buffer[9] << 8);
    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sync_sem);
    return read_value;
}

/**
 * @brief Helper function to write 2 bytes (16 bits) to a Realtek register
 */
esp_err_t rtl_write16(usb_device_handle_t dev_hdl, uint16_t reg_addr, uint16_t value) 
{
    usb_transfer_t *transfer;
    esp_err_t err = usb_host_transfer_alloc(sizeof(usb_setup_packet_t) + 2, 0, &transfer);
    if (err != ESP_OK) return err;

    SemaphoreHandle_t sync_sem = xSemaphoreCreateBinary();
    
    usb_setup_packet_t *req = (usb_setup_packet_t *)transfer->data_buffer;
    req->bmRequestType = REALTEK_USB_VENQT_WRITE;
    req->bRequest = REALTEK_USB_VENQT_CMD_REQ;
    req->wValue = reg_addr;
    req->wIndex = REALTEK_USB_VENQT_CMD_IDX;
    req->wLength = 2;

    transfer->data_buffer[8] = value & 0xFF;
    transfer->data_buffer[9] = (value >> 8) & 0xFF;
    transfer->num_bytes = sizeof(usb_setup_packet_t) + 2;
    transfer->device_handle = dev_hdl;
    transfer->bEndpointAddress = 0x00;
    transfer->callback = control_transfer_cb;
    transfer->context = sync_sem;
    
    err = usb_host_transfer_submit_control(global_client_hdl, transfer);
    if(err == ESP_OK) {
        if (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(2000)) == pdTRUE) {
            if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
                ESP_LOGE(TAG, "Transfer failed (STALL or bus error). Status: %d", transfer->status);
                err = ESP_FAIL;
            }
        } else {
            ESP_LOGE(TAG, "USB transfer timeout!");
            err = ESP_ERR_TIMEOUT;
        }
    }
    
    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sync_sem);
    return err;
}

/**
 * @brief Helper function to read 4 bytes (32 bits) from a Realtek register
 */
uint32_t rtl_read32(usb_device_handle_t dev_hdl, uint16_t reg_addr) 
{
    usb_transfer_t *transfer;
    ESP_ERROR_CHECK(usb_host_transfer_alloc(sizeof(usb_setup_packet_t) + 4, 0, &transfer));
    SemaphoreHandle_t sync_sem = xSemaphoreCreateBinary();
    
    usb_setup_packet_t *req = (usb_setup_packet_t *)transfer->data_buffer;
    req->bmRequestType = REALTEK_USB_VENQT_READ;
    req->bRequest = REALTEK_USB_VENQT_CMD_REQ;
    req->wValue = reg_addr;
    req->wIndex = REALTEK_USB_VENQT_CMD_IDX;
    req->wLength = 4;
    
    transfer->num_bytes = sizeof(usb_setup_packet_t) + 4;
    transfer->device_handle = dev_hdl;
    transfer->bEndpointAddress = 0x00;
    transfer->callback = control_transfer_cb;
    transfer->context = sync_sem;
    
    esp_err_t err = usb_host_transfer_submit_control(global_client_hdl, transfer);
    if(err == ESP_OK) {
        if (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(2000)) == pdTRUE) {
            if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
                ESP_LOGE(TAG, "Transfer failed (STALL or bus error). Status: %d", transfer->status);
            }
        } else {
            ESP_LOGE(TAG, "USB transfer timeout!");
        }
    }

    // Ricostruisce il valore a 32-bit (Little-Endian)
    uint32_t read_value = transfer->data_buffer[8] | 
                         (transfer->data_buffer[9] << 8) | 
                         (transfer->data_buffer[10] << 16) | 
                         (transfer->data_buffer[11] << 24);
                         
    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sync_sem);
    return read_value;
}

/**
 * @brief Helper function to write 4 bytes (32 bits) to a Realtek register
 */
esp_err_t rtl_write32(usb_device_handle_t dev_hdl, uint16_t reg_addr, uint32_t value) 
{
    usb_transfer_t *transfer;
    esp_err_t err = usb_host_transfer_alloc(sizeof(usb_setup_packet_t) + 4, 0, &transfer);
    if (err != ESP_OK) return err;

    SemaphoreHandle_t sync_sem = xSemaphoreCreateBinary();
    
    usb_setup_packet_t *req = (usb_setup_packet_t *)transfer->data_buffer;
    req->bmRequestType = REALTEK_USB_VENQT_WRITE;
    req->bRequest = REALTEK_USB_VENQT_CMD_REQ;
    req->wValue = reg_addr;
    req->wIndex = REALTEK_USB_VENQT_CMD_IDX;
    req->wLength = 4;

    // Scompone il valore a 32-bit in 4 byte (Little-Endian)
    transfer->data_buffer[8]  = value & 0xFF;
    transfer->data_buffer[9]  = (value >> 8) & 0xFF;
    transfer->data_buffer[10] = (value >> 16) & 0xFF;
    transfer->data_buffer[11] = (value >> 24) & 0xFF;
    
    transfer->num_bytes = sizeof(usb_setup_packet_t) + 4;
    transfer->device_handle = dev_hdl;
    transfer->bEndpointAddress = 0x00;
    transfer->callback = control_transfer_cb;
    transfer->context = sync_sem;
    
    err = usb_host_transfer_submit_control(global_client_hdl, transfer);
    if(err == ESP_OK) {
        if (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(2000)) == pdTRUE) {
            if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
                ESP_LOGE(TAG, "Transfer failed (STALL or bus error). Status: %d", transfer->status);
                err = ESP_FAIL;
            }
        } else {
            ESP_LOGE(TAG, "USB transfer timeout!");
            err = ESP_ERR_TIMEOUT;
        }
    }
    
    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sync_sem);
    return err;
}

/**
 * @brief Helper function to write a block of data to Realtek device memory
 */
esp_err_t rtl_write_block(usb_device_handle_t dev_hdl, uint16_t reg_addr, const uint8_t *data, uint16_t len) 
{
    usb_transfer_t *transfer;
    esp_err_t err = usb_host_transfer_alloc(sizeof(usb_setup_packet_t) + len, 0, &transfer);
    if (err != ESP_OK) return err;
    
    SemaphoreHandle_t sync_sem = xSemaphoreCreateBinary();
    
    usb_setup_packet_t *req = (usb_setup_packet_t *)transfer->data_buffer;
    req->bmRequestType = REALTEK_USB_VENQT_WRITE;       // OUT | VENDOR | DEVICE
    req->bRequest = REALTEK_USB_VENQT_CMD_REQ;          // Comando Realtek
    req->wValue = reg_addr;                             // Indirizzo di destinazione
    req->wIndex = REALTEK_USB_VENQT_CMD_IDX;
    req->wLength = len;                                 // Dimensione del blocco
    
    memcpy(&transfer->data_buffer[sizeof(usb_setup_packet_t)], data, len);
    
    transfer->num_bytes = sizeof(usb_setup_packet_t) + len;
    transfer->device_handle = dev_hdl;
    transfer->bEndpointAddress = 0x00; // Endpoint 0
    transfer->callback = control_transfer_cb;
    transfer->context = sync_sem;
    
    err = usb_host_transfer_submit_control(global_client_hdl, transfer);
    if (err == ESP_OK) {
        if (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(2000)) == pdTRUE) {
            if (transfer->status != USB_TRANSFER_STATUS_COMPLETED) {
                ESP_LOGE(TAG, "Transfer fallito (STALL o bus error). Status: %d", transfer->status);
                err = ESP_FAIL; 
            }
        } else {
            ESP_LOGE(TAG, "USB transfer timeout!");
            err = ESP_ERR_TIMEOUT;
        }
    }
    
    usb_host_transfer_free(transfer);
    vSemaphoreDelete(sync_sem);
    return err;
}

