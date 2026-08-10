/*
 * rtl8188e_driver.h - Stato condiviso del driver
 */
#ifndef RTL8188E_DRIVER_H
#define RTL8188E_DRIVER_H

#include <stdio.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "usb/usb_host.h"

#include "rtl8188e_reg.h"

/* Definiti in main.c */
extern usb_host_client_handle_t global_client_hdl;
extern usb_device_handle_t      global_dev_hdl;
extern TaskHandle_t             driver_task_hdl;

#endif /* RTL8188E_DRIVER_H */
