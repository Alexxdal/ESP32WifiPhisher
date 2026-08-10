/*
 * rtl8188e_usb.h - Accesso ai registri del chip via control transfer USB
 *
 * Ogni lettura/scrittura di registro e' una vendor request sull'endpoint 0.
 * Costa decine di microsecondi: e' il motivo per cui i ritardi da 1 us
 * richiesti dai datasheet Realtek sono soddisfatti implicitamente.
 */
#ifndef RTL8188E_USB_H
#define RTL8188E_USB_H

#include "rtl8188e_driver.h"

uint8_t   rtl_read8 (usb_device_handle_t dev_hdl, uint16_t reg_addr);
uint16_t  rtl_read16(usb_device_handle_t dev_hdl, uint16_t reg_addr);
uint32_t  rtl_read32(usb_device_handle_t dev_hdl, uint16_t reg_addr);

esp_err_t rtl_write8 (usb_device_handle_t dev_hdl, uint16_t reg_addr, uint8_t  value);
esp_err_t rtl_write16(usb_device_handle_t dev_hdl, uint16_t reg_addr, uint16_t value);
esp_err_t rtl_write32(usb_device_handle_t dev_hdl, uint16_t reg_addr, uint32_t value);

esp_err_t rtl_write_block(usb_device_handle_t dev_hdl, uint16_t reg_addr,
                          const uint8_t *data, uint16_t len);

/* Letture il cui valore viene volutamente ignorato: servono solo a
 * riprodurre la sequenza osservata nel driver Windows. */
#define RTL_PROBE8(a)   ((void)rtl_read8 (dev, (a)))
#define RTL_PROBE16(a)  ((void)rtl_read16(dev, (a)))
#define RTL_PROBE32(a)  ((void)rtl_read32(dev, (a)))

#endif /* RTL8188E_USB_H */
