#ifndef _WIFI_MNG_H
#define _WIFI_MNG_H

#include <esp_err.h>
#include <esp_wifi.h>

/**
 * @brief Client ack tracking for unicast frames, 
 * used to avoid counting unicast frames as dropped when they
 * fail to send (since many APs will reject them)
 */
typedef struct {
    uint8_t mac[6];
    int64_t last_ack_time_us;
    uint32_t fail_count;
} client_ack_tracker_t;


extern esp_err_t esp_wifi_internal_set_retry_counter(uint8_t short_retry, uint8_t long_retry);


/**
 * @brief Init Wifi interface
 * 
 */
esp_err_t wifi_init(void);


/**
 * @brief Start wifi in AP mode
 * 
 */
void wifi_start_softap(void);


/**
 * @brief Start wifi AP with given settings
 * 
 * @param wifi_config 
 * @param bssid 
 */
void wifi_ap_clone(wifi_config_t *wifi_config, uint8_t *bssid);


/**
 * @brief Safely set wifi channel, deauth connected stations if needed
 * 
 * @param new_channel 
 * @return esp_err_t 
 */
esp_err_t wifi_set_channel_safe(uint8_t new_channel);


/**
 * @brief Send ROC request to set a channel temporarly
 * @param window default 150ms, its the time window for the attack in this channel
 */
esp_err_t wifi_set_temporary_channel(uint8_t new_channel, uint32_t window);


/**
 * @brief Change SoftAP channel using CSA (Channel Switch Announcement)
 * * @param new_channel Il nuovo canale desiderato (1-13)
 * @return esp_err_t 
 */
esp_err_t wifi_switch_ap_channel_csa(uint8_t new_channel);


/**
 * @brief Get sent frames
 */
uint32_t wifi_get_sent_frames(void);


/**
 * @brief Get dropped frames
 */
uint32_t wifi_get_dropped_frames(void);


/**
 * @brief Increment sent frames counter (for use in raw frame sending functions)
 */
void wifi_sent_frame_increment(void);


/**
 * @brief Increment dropped frames counter (for use in raw frame sending functions)
 */
void wifi_dropped_frame_increment(void);


/**
 * @brief Reset frame counters
 */
void wifi_reset_frame_counters(void);


/**
 * @brief Get current frames per second (PPS)
 */
uint32_t wifi_get_frame_pps(void);


/**
 * @brief Check if a client is responsive based on ACK tracking
 * This is used to avoid counting unicast frames as dropped when the client is not responding.
 */
bool wifi_mng_is_client_responsive(const uint8_t *mac);


#endif