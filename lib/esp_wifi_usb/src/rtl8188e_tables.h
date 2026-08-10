/*
 * rtl8188e_tables.h - Tabelle di inizializzazione estratte dal driver Realtek
 *
 * mac_reg  : registri MAC, coppie {indirizzo, valore} a 8 bit
 * agc_tab  : tabella AGC, formato phydm con condizioni di board
 * phy_reg  : registri baseband, stesso formato condizionale
 * radioa   : registri del transceiver RF (path A), stesso formato
 */
#ifndef RTL8188E_TABLES_H
#define RTL8188E_TABLES_H

#include <stdint.h>

extern const uint16_t rtl8188e_mac_reg_table[][2];
extern const uint32_t rtl8188e_agc_tab[];
extern const uint32_t rtl8188e_phy_reg[];
extern const uint32_t rtl8188e_radioa_tab[];

extern const uint32_t rtl8188e_mac_reg_table_len;
extern const uint32_t rtl8188e_agc_tab_len;
extern const uint32_t rtl8188e_phy_reg_len;
extern const uint32_t rtl8188e_radioa_tab_len;

#endif /* RTL8188E_TABLES_H */
