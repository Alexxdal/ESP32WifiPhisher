/*
 * rtl8188e_rx.h - Ricezione pacchetti e diagnostica
 */
#ifndef RTL8188E_RX_H
#define RTL8188E_RX_H

#include "rtl8188e_driver.h"

/* Task che mette il chip in promiscuo e legge l'endpoint BULK IN */
void rtl8188_rx_task(void *arg);

/* Stampa lo stato di MAC, RF, contatori PHY e baseband */
void rtl8188_dump_rx_state(void);

#endif /* RTL8188E_RX_H */

