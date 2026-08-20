/*
 * rtl8188e_iqk.h - Calibrazione IQ (IQK) e del sintetizzatore (LCK)
 *
 * Porting di phy_iq_calibrate_8188e / _phy_lc_calibrate_8188e dal driver
 * Realtek v5.13.3 (hal/phydm/rtl8188e/halphyrf_8188e.c), ramo 1T1R.
 *
 * Vanno eseguite DOPO aver caricato PHY_REG, AGC e RadioA, e dopo aver
 * impostato il canale: la calibrazione e' valida per la frequenza corrente.
 */
#ifndef RTL8188E_IQK_H
#define RTL8188E_IQK_H

#include "rtl8188e_driver.h"

/* Calibrazione dello squilibrio I/Q del percorso di trasmissione e ricezione.
 * Esegue fino a 3 giri e sceglie il risultato piu' consistente. */
void rtl8188e_iq_calibrate(usb_device_handle_t dev);

/* Calibrazione del banco LC del sintetizzatore (aggancio del VCO). */
void rtl8188e_lc_calibrate(usb_device_handle_t dev);

#endif /* RTL8188E_IQK_H */

