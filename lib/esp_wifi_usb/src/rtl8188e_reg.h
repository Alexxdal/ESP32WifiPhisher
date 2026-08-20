/*
 * rtl8188e_reg.h - Registri e bit del chip RTL8188EU
 *
 * Gli indirizzi 0x0000-0x07FF sono registri MAC, 0x0800-0x0FFF sono baseband.
 * I registri del transceiver RF non stanno qui: si raggiungono via LSSI
 * (vedi rtl8188e_phy.c).
 */
#ifndef RTL8188E_REG_H
#define RTL8188E_REG_H

/* Incluso per primo di proposito: se rtl8188e_spec.h definisce gia' un
 * registro, la sua definizione vince e le define qui sotto (tutte protette
 * da #ifndef) non lo ridefiniscono. */
#include "rtl8188e_spec.h"

/* REG_TXPAUSE (0x0522): un bit per coda, 1 = quella coda NON puo' trasmettere.
 * Gia' usato in rtl8188e_iqk.c per bloccare tutto durante IQK/LCK (poi
 * ripristinato al valore di prima, non necessariamente sbloccato). Trovato
 * 2026-08-03 analizzando perche' esp_wifi_usb_80211_tx() non trasmetteva
 * nulla nonostante il transfer USB andasse a buon fine: la cattura reale
 * mostra uno 0x00 (tutte le code SBLOCCATE) scritto esplicitamente dopo
 * IQK/LCK, non un semplice "ripristina il valore di prima" - se il default
 * del chip all'accensione e' "tutto pausato" (comune, per sicurezza), la
 * sola restore lo rimette pausato per sempre. Va sbloccato esplicitamente
 * in rtl8188e_start_radio(). */
#ifndef REG_TXPAUSE
#define REG_TXPAUSE                  0x0522
#endif

/* AGGIUNTO 2026-08-03: MSR ("Media Status Register") non aveva un #define
 * proprio nel nostro codice - rtl8188e_start_radio() lo scriveva come parte
 * di una scrittura a 32 bit su REG_CR con solo un commento numerico
 * ("CR(0x0100-0x0101) + MSR(0x0102)"). Confermato dal diario del progetto
 * (sessione di ricerca 2026-08-03 su rtl8188e_spec.h): MSR = REG_CR + 2,
 * e i 2 bit bassi selezionano lo stato operativo. Il nostro driver non ha
 * mai una vera associazione (solo promiscuo/injection), quindi non cambiamo
 * mai questo valore a runtime, ma il nome rende esplicito cosa scrive
 * rtl8188e_start_radio() invece di lasciare "0x0102" solo in un commento. */
#ifndef REG_MSR
#define REG_MSR                      (REG_CR + 2)
#endif
#ifndef MSR_NOLINK
#define MSR_NOLINK                   0x00
#endif
#ifndef MSR_ADHOC
#define MSR_ADHOC                    0x01
#endif
#ifndef MSR_INFRA
#define MSR_INFRA                    0x02
#endif
#ifndef MSR_AP
#define MSR_AP                       0x03
#endif

/* ---- Potenza TX per rate (path A, l'unico che usiamo: chip 1T1R) ----
 * NOTA DI ONESTA': questi indirizzi NON vengono dalla nostra cattura (la
 * sequenza di calibrazione di potenza TX del driver Windows, vista subito
 * dopo lo sblocco di REG_TXPAUSE, usa un meccanismo a loop chiuso - scrive
 * 0x0908 mentre rilegge un valore misurato dal chip - che non abbiamo
 * reverse-engineered). Vengono invece dal driver Realtek open-source di
 * riferimento (lwfinger/rtl8188eu, Hal8188EPhyReg.h): ogni registro e' a 32
 * bit e contiene 4 indici di potenza da 1 byte ciascuno, uno per gruppo di
 * rate. Scrivere un indice uniforme su tutti equivale a un "volume" unico
 * approssimativo, non alla vera curva di potenza calibrata del driver
 * originale. Non ancora verificato su hardware. */
#ifndef REG_TX_AGC_A_RATE18_06
#define REG_TX_AGC_A_RATE18_06       0x0E00   /* OFDM 6/9/12/18 Mbps */
#endif
#ifndef REG_TX_AGC_A_RATE54_24
#define REG_TX_AGC_A_RATE54_24       0x0E04   /* OFDM 24/36/48/54 Mbps */
#endif
/* v1 (2026-08-07): nome corretto da REG_TX_AGC_A_CCK1_MCint32_t (refuso di
 * un search&replace passato che ha corrotto "MCS32" -> "MCint32_t" - vedi
 * anche "MCint8_t" invece di "MCS8" qualche riga sotto). Solo il nome era
 * sbagliato, l'indirizzo 0x0E08 e l'uso in esp_wifi_usb_set_tx_power() erano
 * gia' corretti. */
#ifndef REG_TX_AGC_A_CCK1_MCS32
#define REG_TX_AGC_A_CCK1_MCS32      0x0E08   /* CCK 1 Mbps (+ MCS32) */
#endif
#ifndef REG_TX_AGC_A_MCS03_MCS00
#define REG_TX_AGC_A_MCS03_MCS00     0x0E10   /* HT MCS0-3 */
#endif
#ifndef REG_TX_AGC_A_MCS07_MCS04
#define REG_TX_AGC_A_MCS07_MCS04     0x0E14   /* HT MCS4-7 */
#endif
#ifndef REG_TX_AGC_A_MCS11_MCS08
#define REG_TX_AGC_A_MCS11_MCS08     0x0E18   /* HT MCS8-11, non usati (1T1R) */
#endif
#ifndef REG_TX_AGC_A_MCS15_MCS12
#define REG_TX_AGC_A_MCS15_MCS12     0x0E1C   /* HT MCS12-15, non usati (1T1R) */
#endif
/* CCK 2/5.5/11 Mbps power, path A: bytes[1:3] of this register (byte[0] is
 * path B CCK 11M, unused on this 1T1R chip). */
#ifndef REG_TX_AGC_B_CCK11_A_CCK2_11
#define REG_TX_AGC_B_CCK11_A_CCK2_11 0x086C
#endif

/* TX power index (0-63) to dBm: 0.5 dB per LSB. */
#ifndef RTL8188E_TXGI_MAX
#define RTL8188E_TXGI_MAX            63
#endif
#ifndef RTL8188E_TXGI_PER_DBM
#define RTL8188E_TXGI_PER_DBM        2
#endif

/* ---- Identificazione USB ---- */
#ifndef VID_REALTEK
#define VID_REALTEK                 0x0BDA
#endif

#ifndef PID_RTL8188EU
#define PID_RTL8188EU               0x8179
#endif


/* ---- Vendor request Realtek sul control endpoint ---- */
#ifndef REALTEK_USB_VENQT_READ
#define REALTEK_USB_VENQT_READ      0xC0
#endif

#ifndef REALTEK_USB_VENQT_WRITE
#define REALTEK_USB_VENQT_WRITE     0x40
#endif

#ifndef REALTEK_USB_VENQT_CMD_REQ
#define REALTEK_USB_VENQT_CMD_REQ   0x05
#endif

#ifndef REALTEK_USB_VENQT_CMD_IDX
#define REALTEK_USB_VENQT_CMD_IDX   0x00
#endif

#ifndef FW_START_ADDRESS
#define FW_START_ADDRESS            0x1000  /* RAM del microcontrollore interno */
#endif
#ifndef FW_CHUNK_SIZE
#define FW_CHUNK_SIZE               196   /* MAX_REG_BOLCK_SIZE del driver Realtek */
#endif


/* ---- Baseband: interfaccia verso il transceiver RF ---- */
#ifndef REG_FPGA0_RFMOD
#define REG_FPGA0_RFMOD             0x0800  /* bit24 CCK_EN, bit25 OFDM_EN, bit0 banda */
#endif

#ifndef REG_FPGA0_XA_HSSI_PARM1
#define REG_FPGA0_XA_HSSI_PARM1     0x0820
#endif

#ifndef REG_FPGA0_XA_HSSI_PARM2
#define REG_FPGA0_XA_HSSI_PARM2     0x0824  /* lunghezza addr/dati bus 3-wire + read */
#endif

#ifndef REG_FPGA0_XA_LSSI_PARM
#define REG_FPGA0_XA_LSSI_PARM      0x0840  /* scrittura seriale verso l'RF */
#endif

#ifndef REG_FPGA0_XA_RF_INT_OE
#define REG_FPGA0_XA_RF_INT_OE      0x0860  /* rfintfo (b0-15) / rfintfe (b16-31) */
#endif

#ifndef REG_FPGA0_XAB_RF_INT_SW
#define REG_FPGA0_XAB_RF_INT_SW     0x0870  /* rfintfs */
#endif

#ifndef REG_FPGA0_ANALOG_PARM2
#define REG_FPGA0_ANALOG_PARM2      0x0884
#endif

#ifndef REG_FPGA0_XA_LSSI_READBACK
#define REG_FPGA0_XA_LSSI_READBACK  0x08A0
#endif

#ifndef REG_HSPI_XA_READBACK
#define REG_HSPI_XA_READBACK        0x08B8
#endif

#ifndef REG_FPGA1_RFMOD
#define REG_FPGA1_RFMOD             0x0900
#endif

#ifndef BRFSI_RFENV
#define BRFSI_RFENV                 0x10
#endif


/* ---- Registri del transceiver RF (indirizzi interni al chip radio) ---- */
#ifndef RF_AC
#define RF_AC                       0x00
#endif

#ifndef RF_CHNLBW
#define RF_CHNLBW                   0x18    /* [9:0] canale, [11:10] banda, [15] avvia LCK */
#endif


/* ---- Contatori false alarm / CCA del baseband ---- */
#ifndef REG_OFDM_FA_HOLDC
#define REG_OFDM_FA_HOLDC           0x0C00  /* bit31 = congela pagina C */
#endif

#ifndef REG_OFDM_FA_RSTC
#define REG_OFDM_FA_RSTC            0x0C0C  /* bit31 = reset pagina C */
#endif

#ifndef REG_OFDM_FA_RSTD
#define REG_OFDM_FA_RSTD            0x0D00  /* bit31 congela, bit27 reset pagina D */
#endif

#ifndef REG_OFDM_FA_TYPE1
#define REG_OFDM_FA_TYPE1           0x0CF0
#endif

/* BUG CORRETTO: questi due NON stanno a 0x0CF4/0x0CF8 (non e' un blocco
 * contiguo a passi di 4 byte come 0x0CF0!). C'e' un salto dalla "pagina C"
 * (0x0C00-0x0CFF) alla "pagina D" (0x0D00-0x0DFF): confermato contro
 * ODM_REG_OFDM_FA_TYPE2/3_11N nel driver di riferimento. Con l'indirizzo
 * sbagliato si leggeva sempre un registro riservato/estraneo che dava
 * costantemente 0, facendo sembrare il demodulatore OFDM morto quando in
 * realta' potrebbe non esserlo mai stato: era solo il contatore letto dal
 * posto sbagliato. */
#ifndef REG_OFDM_FA_TYPE2
#define REG_OFDM_FA_TYPE2           0x0DA0  /* [15:0] OFDM CCA, [31:16] parity fail */
#endif

#ifndef REG_OFDM_FA_TYPE3
#define REG_OFDM_FA_TYPE3           0x0DA4  /* [15:0] rate illegal, [31:16] crc8 fail */
#endif

#ifndef REG_CCK_FA_RST
#define REG_CCK_FA_RST              0x0A2C  /* [13:12] = 2 abilita i contatori CCK */
#endif

#ifndef REG_CCK_FA_MSB
#define REG_CCK_FA_MSB              0x0A58
#endif

#ifndef REG_CCK_FA_LSB
#define REG_CCK_FA_LSB              0x0A5C
#endif

#ifndef REG_CCK_CCA_CNT
#define REG_CCK_CCA_CNT             0x0A60
#endif


/* ---- Allocazione pagine e confini delle FIFO ---- */
#ifndef REG_RQPN
#define REG_RQPN                    0x0200
#endif

#ifndef REG_RQPN_NPQ
#define REG_RQPN_NPQ                0x0214
#endif

#ifndef REG_PBP
#define REG_PBP                     0x0104
#endif

#ifndef REG_TRXFF_BNDY
#define REG_TRXFF_BNDY              0x0114
#endif

#ifndef REG_TXPKTBUF_BCNQ_BDNY
#define REG_TXPKTBUF_BCNQ_BDNY      0x0424
#endif

#ifndef REG_TXPKTBUF_MGQ_BDNY
#define REG_TXPKTBUF_MGQ_BDNY       0x0425
#endif

#ifndef REG_TXPKTBUF_WMAC_LBK_BF_HD
#define REG_TXPKTBUF_WMAC_LBK_BF_HD 0x045D
#endif

#ifndef REG_TDECTRL
#define REG_TDECTRL                 0x0208
#endif

#ifndef REG_RX_DRVINFO_SZ
#define REG_RX_DRVINFO_SZ           0x060F
#endif


#ifndef TX_TOTAL_PAGE_NUM_8188E
#define TX_TOTAL_PAGE_NUM_8188E     0xA9
#endif

#ifndef TX_PAGE_BOUNDARY_8188E
#define TX_PAGE_BOUNDARY_8188E      (TX_TOTAL_PAGE_NUM_8188E + 1)
#endif

/* v2 (2026-08-08, tredicesimo giro): CORRETTO 0xB0 -> 0xAF.
 *
 * La v1 (2026-08-07) aveva messo 0xB0 = 176 citando come prova il commento
 * "/ * 176, 22k * /" che sta in InitLLTTable() (rtl8188e_hal_init.c riga
 * 2733). Era una lettura sbagliata di quel commento: descrive la DIMENSIONE
 * del buffer pacchetti (176 pagine da 128 byte = 22 KB), non l'INDICE
 * dell'ultima pagina. La macro vera, in components/rtl8188eu/include/
 * hal_com_reg.h riga 1857, e' letteralmente:
 *     #define LAST_ENTRY_OF_TX_PKT_BUFFER_8188E(__Adapter)  (175)
 * cioe' 0xAF. Con 176 pagine numerate 0..175, l'ultimo indice valido e' 175:
 * la pagina 0xB0 non esiste.
 *
 * Riscontro SPERIMENTALE (log del dodicesimo giro): rileggendo la LLT,
 * l'entry 0xB0 torna 0xFF invece del 0xAA che ci avevamo scritto - conferma
 * che quell'indirizzo e' fuori dalla tabella. Le ultime due scritture della
 * costruzione LLT finivano quindi fuori bordo, e l'entry 0xAF restava a
 * puntare alla pagina inesistente 0xB0 invece di richiudere l'anello sul
 * confine TX: l'anello del buffer beacon/loopback era rotto. */
#ifndef LAST_ENTRY_OF_TX_PKT_BUFFER_8188E
#define LAST_ENTRY_OF_TX_PKT_BUFFER_8188E   0xAF
#endif

/* Formato del registro REG_LLT_INIT (0x01E0), verbatim da
 * lwfinger/rtl8188eu include/rtl8188e_spec.h: l'INDIRIZZO della entry sta
 * nel byte ALTO, il DATO (pagina successiva) nel byte BASSO. Vedi
 * tx-muta-causa-trovata-llt.md: il porting aveva questi due campi scambiati,
 * causa del silenzio TX totale nonostante la RX funzionasse. */
#ifndef _LLT_INIT_DATA
#define _LLT_INIT_DATA(x)    ((x) & 0xFF)          /* bit [7:0]  */
#endif
#ifndef _LLT_INIT_ADDR
#define _LLT_INIT_ADDR(x)    (((x) & 0xFF) << 8)   /* bit [15:8] */
#endif
#ifndef _LLT_OP
#define _LLT_OP(x)           (((x) & 0x3) << 30)
#endif
#ifndef _LLT_WRITE_ACCESS
#define _LLT_WRITE_ACCESS    0x1
#endif
#ifndef _LLT_NO_ACTIVE
#define _LLT_NO_ACTIVE       0x0
#endif
#ifndef _LLT_OP_VALUE
#define _LLT_OP_VALUE(x)     (((x) >> 30) & 0x3)
#endif

#ifndef TRXFF_BOUNDARY_8188E
#define TRXFF_BOUNDARY_8188E        0x23FF  /* MAX_RX_DMA_BUFFER_SIZE_88E - 1, come nel driver reale
                                              * (prima era 0x25FF: confine RX FIFO troppo alto,
                                              * finiva per invadere lo spazio delle pagine TX) */
#endif


/* BUG CORRETTO (2026-08-03): questi erano i valori del ramo "wifi_spec=1"
 * (WMM) del driver Linux di riferimento, MAI verificati su questo hardware.
 * Una cattura USB reale del driver Windows che riceve pacchetti con
 * successo su questo stesso chip mostra valori completamente diversi:
 * HPQ=0x0C, LPQ=0x00, NPQ=0x0D, PUBQ=0x90 (osservati a REG_RQPN=0x8090000C,
 * REG_RQPN_NPQ=0x0D). Nessuno dei due rami "da manuale" corrispondeva alla
 * verita' — questi sono i valori ground-truth. */
#ifndef RQPN_HPQ_8188E
#define RQPN_HPQ_8188E              0x0C
#endif

#ifndef RQPN_LPQ_8188E
#define RQPN_LPQ_8188E              0x00
#endif

#ifndef RQPN_NPQ_8188E
#define RQPN_NPQ_8188E              0x0D
#endif

#ifndef RQPN_PUBQ_8188E
#define RQPN_PUBQ_8188E             0x90
#endif


/* ---- Aggregazione RX ----
 * CORREZIONE IMPORTANTE (2026-08-03, dalla cattura USB reale): un round
 * precedente aveva "spento" l'aggregazione RX in tre punti diversi
 * (0x0280=0, bit3 di 0xFE55 azzerato, RXDMA_AGG_EN di 0x010C azzerato),
 * partendo dall'ipotesi che l'aggregazione lasciasse il motore DMA senza
 * mai spingere nulla sull'endpoint BULK IN. La cattura reale smentisce
 * questa ipotesi:
 *   - 0x0280 (REG_RXDMA_AGG_PG_TH) non viene MAI toccato dal driver
 *     Windows: resta al default hardware, che noi invece forzavamo a 0
 *     (un valore probabilmente fuori specifica per questo registro).
 *   - 0xFE55 viene scritto a 0x08, cioe' con il bit3 ACCESO, non spento
 *     come facevamo noi (che leggevamo il default e ne cancellavamo il
 *     bit3, ottenendo quasi certamente 0x00 invece di 0x08).
 *   - 0x010C (REG_TRXDMA_CTRL) viene scritto letteralmente a 0xF0 (preceduto
 *     poco prima da una scrittura a 16 bit 0xFAF0 che copre anche 0x010D),
 *     non da una read-modify-write che azzera solo RXDMA_AGG_EN.
 * In pratica il driver reale lascia l'aggregazione ATTIVA (coerente anche
 * col driver Linux di riferimento, che la abilita esplicitamente) e usa
 * valori letterali precisi, non "tutto spento a meta'". Probabile causa
 * reale dello zero pacchetti: il nostro DMA restava in uno stato
 * incoerente/non di fabbrica che il chip non si aspettava mai di vedere. */
#ifndef REG_RXDMA_AGG_PG_TH
#define REG_RXDMA_AGG_PG_TH         0x0280
#endif

#ifndef REG_USB_SPECIAL_OPTION
#define REG_USB_SPECIAL_OPTION      0xFE55
#endif

#ifndef USB_SPEC_AGG_ENABLE
#define USB_SPEC_AGG_ENABLE         (1 << 3)
#endif

/* Valore letterale confermato dalla cattura reale per 0xFE55 (byte intero,
 * non un singolo bit su un default sconosciuto). */
#ifndef USB_SPECIAL_OPTION_REAL_VALUE
#define USB_SPECIAL_OPTION_REAL_VALUE   0x08
#endif

/* Due registri adiacenti scritti dal driver reale subito dopo 0xFE55,
 * mai gestiti prima nel nostro codice. Funzione esatta non confermata
 * (probabile ulteriore configurazione dell'aggregazione USB), ma sono
 * scritture letterali presenti e ripetute nella cattura. */
#ifndef REG_USB_UNKNOWN_0xFE5D
#define REG_USB_UNKNOWN_0xFE5D       0xFE5D
#endif
#ifndef USB_UNKNOWN_0xFE5D_REAL_VALUE
#define USB_UNKNOWN_0xFE5D_REAL_VALUE 0x08
#endif

#ifndef REG_USB_UNKNOWN_0xFE5C
#define REG_USB_UNKNOWN_0xFE5C       0xFE5C
#endif
#ifndef USB_UNKNOWN_0xFE5C_REAL_VALUE
#define USB_UNKNOWN_0xFE5C_REAL_VALUE 0x06
#endif

#ifndef REG_TRXDMA_CTRL
#define REG_TRXDMA_CTRL             0x010C
#endif

#ifndef RXDMA_AGG_EN
#define RXDMA_AGG_EN                (1 << 2)
#endif

/* Valore letterale a 16 bit scritto su 0x010C-0x010D dal driver reale
 * (0x010C=0xF0, 0x010D=0xFA), confermato con una seconda scrittura a 8 bit
 * di 0x010C=0xF0 poco dopo. */
#ifndef TRXDMA_CTRL_REAL_VALUE_16
#define TRXDMA_CTRL_REAL_VALUE_16   0xFAF0
#endif
#ifndef TRXDMA_CTRL_REAL_VALUE_8
#define TRXDMA_CTRL_REAL_VALUE_8    0xF0
#endif


/* ---- REG_RCR (0x0608): filtri di ricezione ---- */
#ifndef REG_RCR
#define REG_RCR                     0x0608
#endif

#ifndef RCR_AAP
#define RCR_AAP                     (1 << 0)   /* Accept All Packets (promiscuo) */
#endif

#ifndef RCR_APM
#define RCR_APM                     (1 << 1)   /* Accept Physical Match */
#endif

#ifndef RCR_AM
#define RCR_AM                      (1 << 2)   /* Accept Multicast */
#endif

#ifndef RCR_AB
#define RCR_AB                      (1 << 3)   /* Accept Broadcast */
#endif

#ifndef RCR_CBSSID_DATA
#define RCR_CBSSID_DATA             (1 << 6)   /* filtra i DATA per BSSID */
#endif

#ifndef RCR_CBSSID_BCN
#define RCR_CBSSID_BCN              (1 << 7)   /* filtra i BEACON per BSSID */
#endif

#ifndef RCR_ACRC32
#define RCR_ACRC32                  (1 << 8)   /* accetta anche CRC errato */
#endif

#ifndef RCR_AICV
#define RCR_AICV                    (1 << 9)   /* accetta anche ICV errato */
#endif

#ifndef RCR_ADF
#define RCR_ADF                     (1 << 11)  /* Accept Data Frames */
#endif

#ifndef RCR_ACF
#define RCR_ACF                     (1 << 12)  /* Accept Control Frames */
#endif

#ifndef RCR_AMF
#define RCR_AMF                     (1 << 13)  /* Accept Management Frames */
#endif

#ifndef RCR_APP_PHYST_RXFF
#define RCR_APP_PHYST_RXFF          (1 << 28)  /* aggiunge PHY status al descrittore */
#endif

/* Bit trovati SOLO analizzando la cattura USB reale (2026-08-03), mai
 * definiti prima. Il driver Windows scrive RCR=0xF000600F in modo
 * identico e ripetuto in 4 punti distinti della cattura (non e' un caso
 * isolato). Confrontando bit a bit con la nostra vecchia costruzione
 * (0x10003B0F) risulta che NON era affatto un "superset" come pensavamo:
 * al reale mancano i nostri bit 8,9,11,12 (ACRC32/AICV/ADF/ACF) e al
 * nostro mancano i bit 14,29,30,31 che il reale invece accende sempre.
 * Percio' ora costruiamo RCR con il valore letterale invece di questi
 * bit "presunti", per non ripetere lo stesso tipo di errore gia' trovato
 * con OFDM_FA_TYPE2/3. */
#ifndef RCR_UNKNOWN_BIT14
#define RCR_UNKNOWN_BIT14            (1 << 14)  /* presente sempre nella cattura reale, funzione non confermata */
#endif

#ifndef RCR_APP_ICV
#define RCR_APP_ICV                  (1 << 29)  /* aggiunge ICV al descrittore RX */
#endif

#ifndef RCR_APP_MIC
#define RCR_APP_MIC                  (1 << 30)  /* aggiunge MIC al descrittore RX */
#endif

#ifndef RCR_APPFCS
#define RCR_APPFCS                   (1 << 31)  /* aggiunge FCS/CRC al descrittore RX */
#endif

/* Valore letterale confermato dalla cattura reale (RQPN/RCR/IQK, 2026-08-03).
 * Usare QUESTO al posto di un OR di bit "presunti" per REG_RCR. */
#ifndef RCR_REAL_CAPTURED_VALUE
#define RCR_REAL_CAPTURED_VALUE      0xF000600FUL
#endif


/* ---- Filtri per sottotipo (usati solo se ADF/ACF/AMF sono a 0) ---- */
#ifndef REG_RXFLTMAP0
#define REG_RXFLTMAP0               0x06A0  /* management */
#endif

#ifndef REG_RXFLTMAP1
#define REG_RXFLTMAP1               0x06A2  /* control */
#endif

#ifndef REG_RXFLTMAP2
#define REG_RXFLTMAP2               0x06A4  /* data */
#endif


/* ---- Vari ---- */
#ifndef REG_RF_CTRL
#define REG_RF_CTRL                 0x001F
#endif

#ifndef XTAL_CAP_MASK
#define XTAL_CAP_MASK               0x007FF800  /* bit[22:11], NON 0x00FFF000 (bit[23:12]) */
#endif

#ifndef XTAL_CAP_DEFAULT
#define XTAL_CAP_DEFAULT            0x20
#endif


#ifndef FEN_BBRSTB
#define FEN_BBRSTB                  (1 << 0)
#endif

#ifndef FEN_BB_GLB_RSTn
#define FEN_BB_GLB_RSTn             (1 << 1)
#endif
#ifndef FEN_DIO_RF
#define FEN_DIO_RF                  (1 << 13)
#endif

#ifndef RF_EN_RSTB_SDMRSTB
#define RF_EN_RSTB_SDMRSTB          0x07
#endif


/* Dimensione del descrittore RX premesso a ogni frame */
#ifndef RTL8188E_RX_DESC_SIZE
#define RTL8188E_RX_DESC_SIZE       24
#endif


/* ---- REG_MCUFWDL (0x0080): stato del download e della CPU interna ---- */
#ifndef MCUFWDL_EN
#define MCUFWDL_EN                  (1 << 0)   /* modalita' download attiva   */
#endif
#ifndef MCUFWDL_RDY
#define MCUFWDL_RDY                 (1 << 1)   /* download concluso           */
#endif
#ifndef MCUFWDL_CHKSUM_RPT
#define MCUFWDL_CHKSUM_RPT          (1 << 2)   /* checksum immagine verificato*/
#endif
#ifndef MCUFWDL_WINTINI_RDY
#define MCUFWDL_WINTINI_RDY         (1 << 6)   /* l'8051 e' partito           */
#endif
#ifndef FEN_CPUEN
#define FEN_CPUEN                   (1 << 10)  /* alimentazione della CPU     */
#endif

/* ---- TROVATO 2026-08-03 scavando nel driver Linux reale (lwfinger/rtl8188eu,
 * hal/usb_halinit.c) invece che nella sola cattura USB: la sequenza di
 * hal_init() del driver vero fa DUE cose, dopo l'accensione di MAC/BB/RF, che
 * il nostro porting non ha mai replicato per niente (non e' un bit sbagliato,
 * e' uno STEP INTERO mancante):
 *
 * 1) _BBTurnOnBlock(): accende esplicitamente i blocchi baseband che
 *    generano il segnale CCK e OFDM in TX (bCCKEn/bOFDMEn su rFPGA0_RFMOD,
 *    0x0800 - lo stesso registro che gia' leggevamo in diagnostica ma senza
 *    mai scrivere questi due bit). Senza questo il baseband puo' benissimo
 *    accettare il descrittore TX e "trasmetterlo" a livello di MAC/DMA (per
 *    questo l'host non vede mai un errore USB) ma il modulatore che
 *    dovrebbe produrre il segnale RF resta spento - la RX non c'entra,
 *    e' un blocco baseband completamente separato dal demodulatore.
 *    Combacia perfettamente con quello che vediamo: RX perfetta, TX zero
 *    output anche a pochi cm.
 *
 * 2) _InitEDCA(): programma i parametri di accesso al canale (SIFS, AIFS/CW/
 *    TXOP per ogni coda EDCA). Il nostro codice non li ha mai scritti - le
 *    codee restano ai default di power-on, che potrebbero non essere validi
 *    per l'arbitraggio CSMA/CA (nessuna finestra di contesa/TXOP definita =
 *    la coda potrebbe non vincere mai un turno di trasmissione sul mezzo,
 *    anche con TXPAUSE/CR/RQPN tutti corretti, perche' quei registri
 *    controllano se il descrittore viene letto in coda, non se la coda
 *    ottiene mai accesso al canale).
 *
 * Valori letterali copiati identici da hal/usb_halinit.c del driver
 * lwfinger/rtl8188eu (stesso chip), non ipotesi. */
#ifndef REG_EDCA_VO_PARAM
#define REG_EDCA_VO_PARAM           0x0500
#endif
#ifndef REG_EDCA_VI_PARAM
#define REG_EDCA_VI_PARAM           0x0504
#endif
#ifndef REG_EDCA_BE_PARAM
#define REG_EDCA_BE_PARAM           0x0508
#endif
#ifndef REG_EDCA_BK_PARAM
#define REG_EDCA_BK_PARAM           0x050C
#endif
#ifndef REG_SPEC_SIFS
#define REG_SPEC_SIFS               0x0428
#endif
#ifndef REG_MAC_SPEC_SIFS
#define REG_MAC_SPEC_SIFS           0x063A
#endif
#ifndef REG_SIFS_CTX
#define REG_SIFS_CTX                0x0514
#endif
#ifndef REG_SIFS_TRX
#define REG_SIFS_TRX                0x0516
#endif
#ifndef REG_HWSEQ_CTRL
#define REG_HWSEQ_CTRL              0x0423
#endif
#ifndef REG_BAR_MODE_CTRL
#define REG_BAR_MODE_CTRL           0x04CC
#endif
#ifndef REG_FWHW_TXQ_CTRL
#define REG_FWHW_TXQ_CTRL           0x0420
#endif

/* AGGIUNTI 2026-08-08 (confronto esaustivo contro l'ordine ESATTO delle
 * scritture di rtl8188eu_hal_init(), usb_halinit.c righe ~1370-1480, non
 * solo l'elenco delle funzioni chiamate ma i registri toccati DENTRO
 * ognuna): mai definiti in questo progetto, quindi mai scritti. */
#ifndef REG_MACID_NO_LINK_0
#define REG_MACID_NO_LINK_0         0x0484
#endif
#ifndef REG_MACID_NO_LINK_1
#define REG_MACID_NO_LINK_1         0x0488
#endif
#ifndef REG_USB_HRPWM
#define REG_USB_HRPWM               0xFE58
#endif

/* AGGIUNTI 2026-08-08 (quarto giro, dopo aver letto rtw_wlan_util.c,
 * hal_com_reg.h e rtl8188e_hal_init.c - file gia' presenti nell'albero
 * components/rtl8188eu ma mai riletti finora, individuati grazie al report
 * "Understand" generato dall'utente sul driver ufficiale):
 * - REG_ACKTO (0x0640): usato da _InitRetryFunction() per l'ACK timeout.
 * - REG_CAMCMD (0x0670): usato da invalidate_cam_all() per invalidare tutte
 *   le 32 entry della CAM (tabella chiavi di sicurezza) all'avvio. */
#ifndef REG_ACKTO
#define REG_ACKTO                   0x0640
#endif
#ifndef REG_CAMCMD
#define REG_CAMCMD                  0x0670
#endif

/* rFPGA0_RFMOD (0x0800): bCCKEn = bit24, bOFDMEn = bit25 */
#ifndef BB_CCK_EN
#define BB_CCK_EN                   (1u << 24)
#endif
#ifndef BB_OFDM_EN
#define BB_OFDM_EN                  (1u << 25)
#endif

#endif /* RTL8188E_REG_H */