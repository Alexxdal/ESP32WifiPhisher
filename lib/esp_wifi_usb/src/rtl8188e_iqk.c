#include "rtl8188e_iqk.h"
#include "rtl8188e_usb.h"
#include "rtl8188e_phy.h"

static const char *TAG = "RTL8188_IQK";

/* ---- Registri usati solo dalla calibrazione ---- */
#define REG_FPGA0_IQK                 0x0E28   /* con maschera 0xFFFFFF00 */
#define REG_TX_IQK                    0x0E40
#define REG_RX_IQK                    0x0E44
#define REG_IQK_AGC_PTS               0x0E48
#define REG_IQK_AGC_RSP               0x0E4C
#define REG_TX_IQK_TONE_A             0x0E30
#define REG_RX_IQK_TONE_A             0x0E34
#define REG_TX_IQK_PI_A               0x0E38
#define REG_RX_IQK_PI_A               0x0E3C

#define REG_TX_POWER_BEFORE_IQK_A     0x0E94
#define REG_TX_POWER_AFTER_IQK_A      0x0E9C
#define REG_RX_POWER_BEFORE_IQK_A_2   0x0EA4
#define REG_RX_POWER_AFTER_IQK_A_2    0x0EAC

#define REG_OFDM_0_XA_TX_IQ_IMBALANCE 0x0C80
#define REG_OFDM_0_XC_TX_AFE          0x0C94
#define REG_OFDM_0_XA_RX_IQ_IMBALANCE 0x0C14
#define REG_OFDM_0_ECCA_THRESHOLD     0x0C4C
#define REG_OFDM_0_RX_IQ_EXT_ANTA     0x0CA0
#define REG_OFDM_0_TRX_PATH_ENABLE    0x0C04
#define REG_OFDM_0_TR_MUX_PAR         0x0C08
#define REG_FPGA0_XCD_RF_INTF_SW      0x0874
#define REG_CONFIG_ANT_A              0x0B68
#define REG_CCK_0_AFE_SETTING         0x0A04
#define REG_FPGA0_XA_HSSI_PARM1       0x0820
#define REG_FPGA0_XB_HSSI_PARM1       0x0828
#define REG_FPGA0_XA_LSSI_PARM        0x0840
#define REG_TXPAUSE                   0x0522

/* Registri del chip RF usati dalla RX IQK */
#define RF_WE_LUT                     0xEF
#define RF_RCK_OS                     0x30
#define RF_TXPA_G1                    0x31
#define RF_TXPA_G2                    0x32

/* NUOVI (trovati 2026-08-03 in una cattura USB reale del driver Windows su
 * questo stesso hardware): sequenza di spegnimento/riaccensione PA/PAD
 * usata PRIMA di ogni trigger di IQK e mai riportata dal codice originale.
 * Senza indicazioni di cosa siano esattamente (non hanno un nome nella
 * documentazione a cui abbiamo accesso), li chiamiamo con l'indirizzo RF. */
#define RF_PA_PAD_A                   0xDF   /* 0x00980 = "off" durante la misura, 0x00180 = ripristino */
#define RF_UNKNOWN_0x56               0x56   /* valore diverso per fase1/fase2/tx-only, vedi commenti */

#define MASKDWORD                     0xFFFFFFFFu
#define MASKH3BYTES                   0xFFFFFF00u
#define MASKH4BITS                    0xF0000000u
#define RFREG_MASK                    0x000FFFFFu

#define IQK_DELAY_MS                  10
#define MAX_TOLERANCE                 5
#define IQK_RETRY_COUNT               2

#define IQK_ADDA_REG_NUM              16
#define IQK_MAC_REG_NUM               4
#define IQK_BB_REG_NUM                9

/* ADDA: i registri analogici del percorso di conversione */
static const uint16_t iqk_adda_reg[IQK_ADDA_REG_NUM] = {
    0x085C, 0x0E6C, 0x0E70, 0x0E74, 0x0E78, 0x0E7C, 0x0E80, 0x0E84,
    0x0E88, 0x0E8C, 0x0ED0, 0x0ED4, 0x0ED8, 0x0EDC, 0x0EE0, 0x0EEC
};

/* MAC: TXPAUSE, BCN_CTRL, BCN_CTRL_1, GPIO_MUXCFG (l'ultimo a 32 bit) */
static const uint16_t iqk_mac_reg[IQK_MAC_REG_NUM] = {
    0x0522, 0x0550, 0x0551, 0x0040
};

/* Baseband da salvare durante la calibrazione */
static const uint16_t iqk_bb_reg[IQK_BB_REG_NUM] = {
    REG_OFDM_0_TRX_PATH_ENABLE, REG_OFDM_0_TR_MUX_PAR,
    REG_FPGA0_XCD_RF_INTF_SW,   REG_CONFIG_ANT_A, 0x0B6C,
    0x0870, 0x0860, 0x0864, REG_CCK_0_AFE_SETTING
};

static uint32_t adda_backup[IQK_ADDA_REG_NUM];
static uint32_t mac_backup[IQK_MAC_REG_NUM];
static uint32_t bb_backup[IQK_BB_REG_NUM];
static bool     rf_pi_enabled;

/* ------------------------------------------------------------------ */
/* Salvataggio e ripristino                                            */
/* ------------------------------------------------------------------ */

static void save_regs(usb_device_handle_t dev, const uint16_t *regs,
                      uint32_t *backup, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++)
        backup[i] = rtl_read32(dev, regs[i]);
}

static void reload_regs(usb_device_handle_t dev, const uint16_t *regs,
                        const uint32_t *backup, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++)
        rtl_write32(dev, regs[i], backup[i]);
}

static void save_mac_regs(usb_device_handle_t dev)
{
    uint32_t i;
    for (i = 0; i < IQK_MAC_REG_NUM - 1; i++)
        mac_backup[i] = rtl_read8(dev, iqk_mac_reg[i]);
    mac_backup[i] = rtl_read32(dev, iqk_mac_reg[i]);
}

static void reload_mac_regs(usb_device_handle_t dev)
{
    uint32_t i;
    for (i = 0; i < IQK_MAC_REG_NUM - 1; i++)
        rtl_write8(dev, iqk_mac_reg[i], (uint8_t)mac_backup[i]);
    rtl_write32(dev, iqk_mac_reg[i], mac_backup[i]);
}

/**
 * @brief Accende il percorso ADDA sul path A (versione 1T1R)
 */
static void path_adda_on(usb_device_handle_t dev)
{
    const uint32_t path_on = 0x0BDB25A0;

    rtl_write32(dev, iqk_adda_reg[0], 0x0B1B25A0);
    for (uint32_t i = 1; i < IQK_ADDA_REG_NUM; i++)
        rtl_write32(dev, iqk_adda_reg[i], path_on);
}

/**
 * @brief Blocca le code di trasmissione durante la calibrazione
 */
static void mac_setting_calibration(usb_device_handle_t dev)
{
    uint32_t i;

    rtl_write8(dev, iqk_mac_reg[0], 0x3F);                 /* TXPAUSE: blocca tutto */

    for (i = 1; i < IQK_MAC_REG_NUM - 1; i++)
        rtl_write8(dev, iqk_mac_reg[i], (uint8_t)(mac_backup[i] & ~(1 << 3)));

    rtl_write8(dev, iqk_mac_reg[i], (uint8_t)(mac_backup[i] & ~(1 << 5)));
}

/**
 * @brief Il baseband deve stare in modalita' PI durante la IQK
 */
static void pi_mode_switch(usb_device_handle_t dev, bool pi_mode)
{
    uint32_t mode = pi_mode ? 0x01000100 : 0x01000000;

    rtl_write32(dev, REG_FPGA0_XA_HSSI_PARM1, mode);
    rtl_write32(dev, REG_FPGA0_XB_HSSI_PARM1, mode);
}

/* ------------------------------------------------------------------ */
/* Calibrazione del path A                                             */
/* ------------------------------------------------------------------ */

/**
 * @brief IQK del percorso di trasmissione. bit0 = TX OK
 */
static uint8_t path_a_tx_iqk(usb_device_handle_t dev)
{
    uint32_t reg_eac, reg_e94, reg_e9c;
    uint8_t result = 0x00;

    /* TUTTO QUESTO BLOCCO CORRETTO IL 2026-08-03 con dati da una cattura USB
     * reale del driver Windows su QUESTO STESSO hardware (non da ricerca o
     * inferenza). Valori precedenti (0x10008C1C/0x30008C1C/0x8214032A,
     * nessuna scrittura RF) erano tutti sbagliati o mancanti:
     * - TONE_A/RX_TONE_A: 0x10.../0x30... non compaiono MAI nella cattura,
     *   il valore vero e' sempre 0x18008C1C/0x38008C1C in questo contesto.
     * - PI_A: il valore osservato per il primo tentativo e' 0x821403FF.
     * - Mancava DEL TUTTO la sequenza RF (WE_LUT/RCK_OS/TXPA_G1/TXPA_G2 +
     *   due registri RF mai usati prima, 0xDF e 0x56, probabilmente uno
     *   spegnimento temporaneo del PA/PAD) che il driver reale fa SEMPRE
     *   prima del trigger, anche per la sola misura TX. */
    rtl_write32(dev, REG_TX_IQK_TONE_A, 0x18008C1C);
    rtl_write32(dev, REG_RX_IQK_TONE_A, 0x38008C1C);
    rtl_write32(dev, REG_TX_IQK_PI_A,   0x821403FF);
    rtl_write32(dev, REG_RX_IQK_PI_A,   0x28160000);

    /* Impostazioni della LO calibration */
    rtl_write32(dev, REG_IQK_AGC_RSP, 0x00462911);

    rtl_bb_write_mask(dev, REG_FPGA0_IQK, MASKH3BYTES, 0x000000);
    rtl_write_rf(dev, RF_WE_LUT,       0x800A0);
    rtl_write_rf(dev, RF_RCK_OS,       0x20000);
    rtl_write_rf(dev, RF_TXPA_G1,      0x0000F);
    rtl_write_rf(dev, RF_TXPA_G2,      0x07F7F);
    rtl_write_rf(dev, RF_PA_PAD_A,     0x00980);   /* PA/PAD "off" per la misura */
    rtl_write_rf(dev, RF_UNKNOWN_0x56, 0x510F0);
    rtl_bb_write_mask(dev, REG_FPGA0_IQK, MASKH3BYTES, 0x808000);

    /* One shot: avvia LOK e IQK sul path A */
    rtl_write32(dev, REG_IQK_AGC_PTS, 0xF9000000);
    rtl_write32(dev, REG_IQK_AGC_PTS, 0xF8000000);
    vTaskDelay(pdMS_TO_TICKS(IQK_DELAY_MS));

    rtl_write_rf(dev, RF_PA_PAD_A, 0x00180);   /* ripristina il PA/PAD */

    reg_eac = rtl_read32(dev, REG_RX_POWER_AFTER_IQK_A_2);
    reg_e94 = rtl_read32(dev, REG_TX_POWER_BEFORE_IQK_A);
    reg_e9c = rtl_read32(dev, REG_TX_POWER_AFTER_IQK_A);

    ESP_LOGD(TAG, "  TX IQK: 0xe94=0x%08X 0xe9c=0x%08X 0xeac=0x%08X",
             (unsigned int)reg_e94, (unsigned int)reg_e9c, (unsigned int)reg_eac);

    if (!(reg_eac & (1 << 28)) &&
        (((reg_e94 & 0x03FF0000) >> 16) != 0x142) &&
        (((reg_e9c & 0x03FF0000) >> 16) != 0x42))
        result |= 0x01;

    return result;
}

/**
 * @brief IQK del percorso di ricezione. bit0 = TX OK, bit1 = RX OK
 *
 * Richiede prima una TX IQK per ricavare la matrice TXIMR, che viene poi
 * ricaricata in 0xE40 prima di misurare il lato ricezione.
 */
static uint8_t path_a_rx_iqk(usb_device_handle_t dev)
{
    uint32_t reg_eac, reg_e94, reg_e9c, reg_ea4, u4tmp;
    uint8_t result = 0x00;

    /* --- Fase 1: ricavo la TXIMR ---
     * CORRETTO IL 2026-08-03 con dati da una cattura USB reale del driver
     * Windows su questo stesso hardware: TONE_A/RX_TONE_A erano sbagliati
     * (0x10.../0x30... non compaiono mai nella cattura, il valore vero e'
     * 0x18008C1C/0x38008C1C anche qui), e PI_A era una stima "non
     * verificata" del turno precedente (0x82160C1F) rivelatasi sbagliata:
     * il valore vero osservato e' 0x82160FFF. Aggiunta anche la coppia di
     * registri RF 0xDF/0x56 (vedi commento in path_a_tx_iqk) che qui gia'
     * un po' si intuiva servisse ma non era mai stata scritta. */
    rtl_bb_write_mask(dev, REG_FPGA0_IQK, MASKH3BYTES, 0x000000);
    rtl_write_rf(dev, RF_WE_LUT,   0x800A0);
    rtl_write_rf(dev, RF_RCK_OS,   0x30000);
    rtl_write_rf(dev, RF_TXPA_G1,  0x0000F);
    rtl_write_rf(dev, RF_TXPA_G2,  0xF117B);
    rtl_write_rf(dev, RF_PA_PAD_A,     0x00980);
    rtl_write_rf(dev, RF_UNKNOWN_0x56, 0x510F0);
    rtl_bb_write_mask(dev, REG_FPGA0_IQK, MASKH3BYTES, 0x808000);

    rtl_write32(dev, REG_TX_IQK, 0x01007C00);
    rtl_write32(dev, REG_RX_IQK, 0x81004800);

    rtl_write32(dev, REG_TX_IQK_TONE_A, 0x18008C1C);
    rtl_write32(dev, REG_RX_IQK_TONE_A, 0x38008C1C);
    rtl_write32(dev, REG_TX_IQK_PI_A,   0x82160FFF);
    rtl_write32(dev, REG_RX_IQK_PI_A,   0x28160000);

    rtl_write32(dev, REG_IQK_AGC_RSP, 0x0046A911);

    rtl_write32(dev, REG_IQK_AGC_PTS, 0xF9000000);
    rtl_write32(dev, REG_IQK_AGC_PTS, 0xF8000000);
    vTaskDelay(pdMS_TO_TICKS(IQK_DELAY_MS));

    rtl_write_rf(dev, RF_PA_PAD_A, 0x00180);   /* ripristina il PA/PAD */

    reg_eac = rtl_read32(dev, REG_RX_POWER_AFTER_IQK_A_2);
    reg_e94 = rtl_read32(dev, REG_TX_POWER_BEFORE_IQK_A);
    reg_e9c = rtl_read32(dev, REG_TX_POWER_AFTER_IQK_A);

    if (!(reg_eac & (1 << 28)) &&
        (((reg_e94 & 0x03FF0000) >> 16) != 0x142) &&
        (((reg_e9c & 0x03FF0000) >> 16) != 0x42))
        result |= 0x01;
    else
        return result;   /* se la TX non riesce, la RX non ha senso */

    /* --- Fase 2: misura vera del lato ricezione --- */
    u4tmp = 0x80007C00 | (reg_e94 & 0x3FF0000) | ((reg_e9c & 0x3FF0000) >> 16);
    rtl_write32(dev, REG_TX_IQK, u4tmp);

    rtl_bb_write_mask(dev, REG_FPGA0_IQK, MASKH3BYTES, 0x000000);
    rtl_write_rf(dev, RF_WE_LUT,   0x800A0);
    rtl_write_rf(dev, RF_RCK_OS,   0x30000);
    rtl_write_rf(dev, RF_TXPA_G1,  0x0000F);
    rtl_write_rf(dev, RF_TXPA_G2,  0xF7FFA);
    rtl_write_rf(dev, RF_PA_PAD_A,     0x00980);
    rtl_write_rf(dev, RF_UNKNOWN_0x56, 0x51000);
    rtl_bb_write_mask(dev, REG_FPGA0_IQK, MASKH3BYTES, 0x808000);

    rtl_write32(dev, REG_RX_IQK, 0x01004800);

    /* CORRETTO IL 2026-08-03 con dati dalla stessa cattura USB reale citata
     * sopra. TONE_A/RX_TONE_A (0x38008C1C/0x18008C1C) erano gia' stati
     * corretti in precedenza e sono confermati giusti dalla cattura. PI_A
     * era ancora sbagliato: il valore vero e' TX_IQK_PI_A=0x82160000 (non
     * 0x82160C05) e RX_IQK_PI_A=0x28160FFF (non 0x28160C1F, che era una
     * stima "non verificata" del turno precedente). */
    rtl_write32(dev, REG_TX_IQK_TONE_A, 0x38008C1C);
    rtl_write32(dev, REG_RX_IQK_TONE_A, 0x18008C1C);
    rtl_write32(dev, REG_TX_IQK_PI_A,   0x82160000);
    rtl_write32(dev, REG_RX_IQK_PI_A,   0x28160FFF);

    rtl_write32(dev, REG_IQK_AGC_RSP, 0x0046A911);

    rtl_write32(dev, REG_IQK_AGC_PTS, 0xF9000000);
    rtl_write32(dev, REG_IQK_AGC_PTS, 0xF8000000);
    vTaskDelay(pdMS_TO_TICKS(IQK_DELAY_MS));

    rtl_write_rf(dev, RF_PA_PAD_A, 0x00180);   /* ripristina il PA/PAD */

    reg_eac = rtl_read32(dev, REG_RX_POWER_AFTER_IQK_A_2);
    reg_ea4 = rtl_read32(dev, REG_RX_POWER_BEFORE_IQK_A_2);

    ESP_LOGD(TAG, "  RX IQK: 0xea4=0x%08X 0xeac=0x%08X",
             (unsigned int)reg_ea4, (unsigned int)reg_eac);

    if (!(reg_eac & (1 << 27)) &&
        (((reg_ea4 & 0x03FF0000) >> 16) != 0x132) &&
        (((reg_eac & 0x03FF0000) >> 16) != 0x36))
        result |= 0x02;

    return result;
}

/**
 * @brief Scrive i coefficienti di correzione trovati nei registri OFDM
 */
static void path_a_fill_iqk_matrix(usb_device_handle_t dev, bool iqk_ok,
                                   int32_t result[][8], uint8_t candidate,
                                   bool tx_only)
{
    uint32_t oldval_0, X, TX0_A, reg;
    int32_t Y, TX0_C;

    if (candidate == 0xFF || !iqk_ok)
        return;

    oldval_0 = (rtl_read32(dev, REG_OFDM_0_XA_TX_IQ_IMBALANCE) >> 22) & 0x3FF;

    X = result[candidate][0];
    if (X & 0x00000200)
        X |= 0xFFFFFC00;                      /* estensione di segno a 10 bit */
    TX0_A = (X * oldval_0) >> 8;

    rtl_bb_write_mask(dev, REG_OFDM_0_XA_TX_IQ_IMBALANCE, 0x3FF, TX0_A);
    rtl_bb_write_mask(dev, REG_OFDM_0_ECCA_THRESHOLD, (1u << 31),
                      ((X * oldval_0 >> 7) & 0x1));

    Y = result[candidate][1];
    if (Y & 0x00000200)
        Y |= 0xFFFFFC00;
    TX0_C = (Y * oldval_0) >> 8;

    rtl_bb_write_mask(dev, REG_OFDM_0_XC_TX_AFE, MASKH4BITS, ((TX0_C & 0x3C0) >> 6));
    rtl_bb_write_mask(dev, REG_OFDM_0_XA_TX_IQ_IMBALANCE, 0x003F0000, (TX0_C & 0x3F));
    rtl_bb_write_mask(dev, REG_OFDM_0_ECCA_THRESHOLD, (1u << 29),
                      ((Y * oldval_0 >> 7) & 0x1));

    if (tx_only) {
        ESP_LOGD(TAG, "Solo la parte TX e' stata calibrata");
        return;
    }

    reg = result[candidate][2];
    rtl_bb_write_mask(dev, REG_OFDM_0_XA_RX_IQ_IMBALANCE, 0x3FF, reg);

    reg = result[candidate][3] & 0x3F;
    rtl_bb_write_mask(dev, REG_OFDM_0_XA_RX_IQ_IMBALANCE, 0xFC00, reg);

    reg = (result[candidate][3] >> 6) & 0xF;
    rtl_bb_write_mask(dev, REG_OFDM_0_RX_IQ_EXT_ANTA, MASKH4BITS, reg);
}

/**
 * @brief Due giri di calibrazione sono attendibili solo se danno risultati vicini
 */
static bool similarity_compare(int32_t result[][8], uint8_t c1, uint8_t c2)
{
    const uint32_t bound = 4;               /* 1T1R: solo il path A */
    uint32_t bitmap = 0;
    uint8_t final[2] = { 0xFF, 0xFF };
    bool ok = true;

    for (uint32_t i = 0; i < bound; i++) {
        uint32_t diff = (result[c1][i] > result[c2][i])
                      ? (result[c1][i] - result[c2][i])
                      : (result[c2][i] - result[c1][i]);

        if (diff > MAX_TOLERANCE) {
            if ((i == 2 || i == 6) && !bitmap) {
                if (result[c1][i] + result[c1][i + 1] == 0)
                    final[i / 4] = c2;
                else if (result[c2][i] + result[c2][i + 1] == 0)
                    final[i / 4] = c1;
                else
                    bitmap |= (1 << i);
            } else {
                bitmap |= (1 << i);
            }
        }
    }

    if (bitmap == 0) {
        for (uint32_t i = 0; i < bound / 4; i++) {
            if (final[i] != 0xFF) {
                for (uint32_t j = i * 4; j < (i + 1) * 4 - 2; j++)
                    result[3][j] = result[final[i]][j];
                ok = false;
            }
        }
        return ok;
    }

    if (!(bitmap & 0x0F)) {
        for (uint32_t i = 0; i < 4; i++)
            result[3][i] = result[c1][i];
    }
    return false;
}

/**
 * @brief Un singolo giro di calibrazione
 *
 * @return true solo se sono stati raccolti dati validi sia per il TX sia
 *         per l'RX. path_a_ok da solo non basta: puo' valere 0x01 (solo il
 *         TX "interno" alla fase RX e' andato bene) senza che result[t][]
 *         sia mai stato scritto, e senza che venga stampato alcun warning.
 *         Se poi si confronta un giro cosi' (tutto zero) con un altro giro
 *         anch'esso vuoto, similarity_compare li trova "identici" e la
 *         IQK sembra riuscire mentre in realta' non ha calibrato nulla.
 */
static bool iq_calibrate_round(usb_device_handle_t dev, int32_t result[][8], uint8_t t)
{
    uint8_t path_a_ok = 0;
    bool got_tx = false, got_rx = false;

    if (t == 0) {
        save_regs(dev, iqk_adda_reg, adda_backup, IQK_ADDA_REG_NUM);
        save_mac_regs(dev);
        save_regs(dev, iqk_bb_reg, bb_backup, IQK_BB_REG_NUM);
    }

    path_adda_on(dev);

    if (t == 0)
        rf_pi_enabled = (rtl_read32(dev, REG_FPGA0_XA_HSSI_PARM1) & (1 << 8)) != 0;

    if (!rf_pi_enabled)
        pi_mode_switch(dev, true);

    mac_setting_calibration(dev);

    rtl_bb_write_mask(dev, REG_CCK_0_AFE_SETTING, 0x0F000000, 0xF);
    rtl_write32(dev, REG_OFDM_0_TRX_PATH_ENABLE, 0x03A05600);
    rtl_write32(dev, REG_OFDM_0_TR_MUX_PAR,      0x000800E4);
    rtl_write32(dev, REG_FPGA0_XCD_RF_INTF_SW,   0x22204000);

    rtl_bb_write_mask(dev, 0x0870, (1u << 10), 0x01);
    rtl_bb_write_mask(dev, 0x0870, (1u << 26), 0x01);
    rtl_bb_write_mask(dev, 0x0860, (1u << 10), 0x00);
    rtl_bb_write_mask(dev, 0x0864, (1u << 10), 0x00);

    rtl_write32(dev, REG_CONFIG_ANT_A, 0x0F600000);

    rtl_bb_write_mask(dev, REG_FPGA0_IQK, MASKH3BYTES, 0x808000);
    rtl_write32(dev, REG_TX_IQK, 0x01007C00);
    rtl_write32(dev, REG_RX_IQK, 0x81004800);

    for (int i = 0; i < IQK_RETRY_COUNT; i++) {
        path_a_ok = path_a_tx_iqk(dev);
        if (path_a_ok == 0x01) {
            result[t][0] = (rtl_read32(dev, REG_TX_POWER_BEFORE_IQK_A) & 0x3FF0000) >> 16;
            result[t][1] = (rtl_read32(dev, REG_TX_POWER_AFTER_IQK_A)  & 0x3FF0000) >> 16;
            got_tx = true;
            break;
        }
    }

    for (int i = 0; i < IQK_RETRY_COUNT; i++) {
        path_a_ok = path_a_rx_iqk(dev);
        if (path_a_ok == 0x03) {
            result[t][2] = (rtl_read32(dev, REG_RX_POWER_BEFORE_IQK_A_2) & 0x3FF0000) >> 16;
            result[t][3] = (rtl_read32(dev, REG_RX_POWER_AFTER_IQK_A_2)  & 0x3FF0000) >> 16;
            got_rx = true;
            break;
        }
    }

    if (!got_tx || !got_rx)
        ESP_LOGD(TAG, "Giro %d: IQK del path A fallita (TX=%s RX=%s)",
                 t, got_tx ? "ok" : "no", got_rx ? "ok" : "no");

    /* Torna in modalita' baseband normale */
    rtl_bb_write_mask(dev, REG_FPGA0_IQK, MASKH3BYTES, 0x000000);

    if (t != 0) {
        if (!rf_pi_enabled)
            pi_mode_switch(dev, false);

        reload_regs(dev, iqk_adda_reg, adda_backup, IQK_ADDA_REG_NUM);
        reload_mac_regs(dev);
        reload_regs(dev, iqk_bb_reg, bb_backup, IQK_BB_REG_NUM);

        /* Ripristina il guadagno iniziale di ricezione */
        rtl_write32(dev, REG_FPGA0_XA_LSSI_PARM, 0x00032ED3);

        /* Valori di default del registro 0xE30 */
        rtl_write32(dev, REG_TX_IQK_TONE_A, 0x01008C00);
        rtl_write32(dev, REG_RX_IQK_TONE_A, 0x01008C00);
    }

    return got_tx && got_rx;
}

/* ------------------------------------------------------------------ */
/* Interfaccia pubblica                                                */
/* ------------------------------------------------------------------ */

void rtl8188e_iq_calibrate(usb_device_handle_t dev)
{
    int32_t result[4][8];
    uint8_t final_candidate = 0xFF;
    bool patha_ok = false;
    int32_t reg_sum = 0;

    ESP_LOGD(TAG, "=== Avvio IQ Calibration ===");

    bool valid[3] = { false, false, false };

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            result[i][j] = 0;

    for (uint8_t i = 0; i < 3; i++) {
        valid[i] = iq_calibrate_round(dev, result, i);

        /* Due giri "vuoti" (nessun dato raccolto) risultano sempre identici
         * a se stessi: senza il controllo su valid[] similarity_compare li
         * dichiarerebbe concordi e la IQK sembrerebbe riuscita applicando
         * pero' una correzione nulla (X=Y=0), cioe' nessuna correzione. */
        if (i == 1 && valid[0] && valid[1] && similarity_compare(result, 0, 1)) {
            final_candidate = 0;
            ESP_LOGD(TAG, "Giri 1 e 2 concordi");
            break;
        }

        if (i == 2) {
            if (valid[0] && valid[2] && similarity_compare(result, 0, 2)) {
                final_candidate = 0;
                ESP_LOGD(TAG, "Giri 1 e 3 concordi");
                break;
            }
            if (valid[1] && valid[2] && similarity_compare(result, 1, 2)) {
                final_candidate = 1;
                ESP_LOGD(TAG, "Giri 2 e 3 concordi");
            } else {
                for (int j = 0; j < 8; j++)
                    reg_sum += result[3][j];
                final_candidate = (reg_sum != 0) ? 3 : 0xFF;
            }
        }
    }

    if (final_candidate != 0xFF) {
        patha_ok = true;
        ESP_LOGD(TAG, "Candidato scelto: %d -> X=0x%X Y=0x%X RX=0x%X/0x%X",
                 final_candidate,
                 (unsigned int)result[final_candidate][0],
                 (unsigned int)result[final_candidate][1],
                 (unsigned int)result[final_candidate][2],
                 (unsigned int)result[final_candidate][3]);
    } else {
        ESP_LOGD(TAG, "IQK fallita: si usano i valori di default");
    }

    if (final_candidate != 0xFF && result[final_candidate][0] != 0)
        path_a_fill_iqk_matrix(dev, patha_ok, result, final_candidate,
                               (result[final_candidate][2] == 0));

    ESP_LOGD(TAG, "IQ Calibration completata");
}

void rtl8188e_lc_calibrate(usb_device_handle_t dev)
{
    uint8_t tmp_reg;
    uint32_t lc_cal, cnt;

    ESP_LOGD(TAG, "=== Avvio LC Calibration ===");

    tmp_reg = rtl_read8(dev, 0x0D03);

    if ((tmp_reg & 0x70) != 0)
        rtl_write8(dev, 0x0D03, tmp_reg & 0x8F);   /* ferma la TX continua */
    else
        rtl_write8(dev, REG_TXPAUSE, 0xFF);        /* blocca tutte le code */

    /* Legge il valore attuale di RF 0x18 e accende il bit 15, che avvia
     * la calibrazione del banco LC e si autocancella a fine procedura. */
    lc_cal = rtl_read_rf(dev, RF_CHNLBW);
    rtl_write_rf(dev, RF_CHNLBW, lc_cal | 0x08000);

    vTaskDelay(pdMS_TO_TICKS(100));

    for (cnt = 0; cnt < 5; cnt++) {
        if ((rtl_read_rf(dev, RF_CHNLBW) & 0x8000) == 0)
            break;
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (cnt == 5)
        ESP_LOGW(TAG, "LCK non terminata entro il timeout");
    else
        ESP_LOGD(TAG, "LC Calibration completata");

    /* Ripristina il numero di canale */
    rtl_write_rf(dev, RF_CHNLBW, lc_cal & RFREG_MASK);

    if ((tmp_reg & 0x70) != 0)
        rtl_write8(dev, 0x0D03, tmp_reg);
    else
        rtl_write8(dev, REG_TXPAUSE, 0x00);
}

