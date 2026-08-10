#ifndef ESP_WIFI_USB_INTERNAL_H
#define ESP_WIFI_USB_INTERNAL_H

#include "esp_wifi_usb.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Definite in esp_wifi_usb.c */
extern volatile bool              g_wifi_usb_promisc_en;
extern wifi_usb_promiscuous_cb_t  g_wifi_usb_promisc_cb;
extern volatile uint8_t           g_wifi_usb_channel;
extern TaskHandle_t                g_wifi_usb_rx_task_hdl;
extern volatile bool              g_wifi_usb_rx_task_should_run;

#endif /* ESP_WIFI_USB_INTERNAL_H */