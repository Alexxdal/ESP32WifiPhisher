#ifndef _DISPLAY_MNG_H_
#define _DISPLAY_MNG_H_

#include "esp_err.h"

/**
 * @brief Init the Cardputer TFT (ST7789, 240x135 landscape, SPI) and start
 * a background task that redraws a few essential status lines about once
 * a second (WiFi AP/STA, active attacks, BLE, client/device counters,
 * uptime, free heap).
 *
 * No-op that just returns ESP_OK on every target other than
 * TARGET_CARDPUTER (see platformio.ini) -- safe to call unconditionally
 * from main.c regardless of which board is being built.
 */
esp_err_t display_init(void);

/**
 * @brief Stop the refresh task and release the panel/SPI bus.
 */
esp_err_t display_deinit(void);

#endif /* _DISPLAY_MNG_H_ */
