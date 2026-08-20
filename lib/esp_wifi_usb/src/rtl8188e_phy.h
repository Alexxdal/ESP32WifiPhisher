/*
 * rtl8188e_phy.h - Baseband e transceiver RF
 */
#ifndef RTL8188E_PHY_H
#define RTL8188E_PHY_H

#include "rtl8188e_driver.h"

/* Valore corrente del registro RF 0x18 (canale + banda). */
extern uint32_t g_rf_chnlbw_val;

/* Read-modify-write su registri baseband con maschera di bit */
void     rtl_bb_write_mask(usb_device_handle_t dev_hdl, uint16_t reg, uint32_t mask, uint32_t value);
uint32_t rtl_bb_read_mask (usb_device_handle_t dev_hdl, uint16_t reg, uint32_t mask);

/* Accesso al transceiver RF tramite bus seriale LSSI */
void     rtl_write_rf(usb_device_handle_t dev_hdl, uint16_t rf_addr, uint32_t data);
uint32_t rtl_read_rf (usb_device_handle_t dev_hdl, uint8_t rf_addr);

/* Sequenza di configurazione, da chiamare in quest'ordine */
void rtl8188e_enable_bb_rf(usb_device_handle_t dev_hdl);   /* 1. accende BB e RF */
void rtl8188e_init_bb_rf  (usb_device_handle_t dev_hdl);   /* 2. AGC + PHY_REG + power */
void rtl8188e_init_rf     (usb_device_handle_t dev_hdl);   /* 3. tabella RadioA */
void rtl8188e_set_channel (usb_device_handle_t dev_hdl, uint8_t channel);

void rtl8188e_reset_phy_counters(usb_device_handle_t dev_hdl);

/* Applica la tabella PG (power-per-rate) ai registri TX_AGC. Chiamata sia da
 * rtl8188e_init_bb_rf() sia da rtl8188e_set_channel() - vedi il commento
 * sulla definizione in rtl8188e_phy.c per i limiti noti (nessuna calibrazione
 * EFUSE per-canale disponibile). */
void rtl8188e_apply_tx_power_by_rate(usb_device_handle_t dev_hdl);

/* Diagnostica una tantum: prova diversi valori di IGI (0xC50) e misura
 * quanti CCA OFDM/CCK arrivano in mezzo secondo per ciascuno, per capire se
 * "OFDM_CCA sempre a zero" e' un problema di soglia di sensibilita' o se il
 * front-end OFDM e' spento/rotto a monte. Ripristina il valore originale
 * alla fine. Va chiamata una volta dopo rtl8188e_start_radio(), prima di
 * entrare nel loop di ricezione vero e proprio. */
void rtl8188e_igi_sweep_diagnostic(usb_device_handle_t dev_hdl);

#endif /* RTL8188E_PHY_H */

