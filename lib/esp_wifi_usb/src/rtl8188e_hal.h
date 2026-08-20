/*
 * rtl8188e_hal.h - Accensione del chip, firmware e configurazione MAC/DMA
 */
#ifndef RTL8188E_HAL_H
#define RTL8188E_HAL_H

#include "rtl8188e_driver.h"

/* Sequenza di accensione ricavata dal reversing del driver Windows.
 * TODO: sostituire con la power sequence tabellare del driver di riferimento
 * (Hal8188EPwrSeq.c / HalPwrSeqCmd.c), che e' documentata e piu' robusta. */
void rtl8188e_power_on(usb_device_handle_t dev);

/* Scarica il firmware nella RAM del microcontrollore interno */
esp_err_t rtl8188e_load_firmware(usb_device_handle_t dev);

void rtl8188e_start_firmware(usb_device_handle_t dev);

/* v3 (2026-08-08): SPLIT da rtl8188e_init_trx_buffer() - vedi il commento
 * su rtl8188e_init_queue_reserved_page() in rtl8188e_hal.c per il perche'.
 * Va chiamata SUBITO dopo rtl8188e_power_on(), PRIMA di
 * rtl8188e_load_firmware(): nel driver reale (usb_halinit.c,
 * _InitQueueReservedPage/_InitPageBoundary/_InitTransferPageSize) queste
 * scritture avvengono tutte prima del download del firmware, non dopo. */
void rtl8188e_init_queue_reserved_page(usb_device_handle_t dev_hdl);

void rtl8188e_init_mac(usb_device_handle_t dev_hdl);

/* v3 (2026-08-08): ora contiene SOLO i confini del buffer TX e la
 * costruzione della LLT (l'equivalente di _InitTxBufferBoundary() +
 * InitLLTTable() nel driver reale) - va chiamata DOPO
 * rtl8188e_enable_bb_rf(), non prima: nel driver reale questi due step
 * arrivano dopo MAC/BB/RF, non subito dopo il MAC. La riserva pagine (RQPN),
 * la dimensione pagina (PBP) e il confine RX sono stati spostati in
 * rtl8188e_init_queue_reserved_page() sopra. */
void rtl8188e_init_trx_buffer(usb_device_handle_t dev_hdl);
void rtl8188e_start_radio(usb_device_handle_t dev_hdl);

#endif /* RTL8188E_HAL_H */
