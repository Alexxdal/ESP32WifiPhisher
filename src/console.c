#include <driver/uart.h>
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "console.h"
#define EMBEDDED_CLI_IMPL
#include "embedded_cli.h"
#define UART_PORT_NUM UART_NUM_0
#include "TaskManager.h"
#include "wifiMng.h"
#include "scanner.h"
#include "sniffer.h"
#include "cjson_pool.h"

#define WIFI_CONSOLE_SSID_MAX_LEN 32
#define WIFI_CONSOLE_PASS_MAX_LEN 64

static EmbeddedCli *cli = NULL;
static TaskHandle_t console_task_handle = NULL;

typedef struct {
    char ssid[WIFI_CONSOLE_SSID_MAX_LEN + 1];
    char password[WIFI_CONSOLE_PASS_MAX_LEN + 1];
} wifi_connect_console_args_t;


static void wifi_connect_task(void *arg)
{
    wifi_connect_console_args_t *params = (wifi_connect_console_args_t *)arg;
    wifi_connect(params->ssid, params->password);
    free(params);
    task_manager_unregister_current_task();
    vTaskDelete(NULL);
}


static void wifi_scan_task(void *arg)
{
    EmbeddedCli *cli_ptr = (EmbeddedCli *)arg;
    embeddedCliPrint(cli_ptr, "Scanning for WiFi networks... please wait.");
    
    // Esegue la scansione e popola la struttura interna detected_aps
    if (wifi_sniffer_scan_fill_aps() == ESP_OK) {
        
        aps_info_light_t aps_info;
        // Recupera i risultati in modo thread-safe
        if (wifi_sniffer_get_aps_light(&aps_info) == ESP_OK) {
            
            char line[128];
            snprintf(line, sizeof(line), "Found %d access points in memory:", aps_info.count);
            embeddedCliPrint(cli_ptr, line);
            embeddedCliPrint(cli_ptr, "CH  | RSSI | BSSID             | SSID");
            embeddedCliPrint(cli_ptr, "----|------|-------------------|--------------------------------");
            
            // Itera sull'array dei risultati
            for (int i = 0; i < aps_info.count; i++) {
                ap_ext_light_t *ap = &aps_info.ap[i];
                snprintf(line, sizeof(line), "%2d  | %4d | %02X:%02X:%02X:%02X:%02X:%02X | %s", 
                         ap->primary, 
                         ap->rssi, 
                         ap->bssid[0], ap->bssid[1], ap->bssid[2], 
                         ap->bssid[3], ap->bssid[4], ap->bssid[5],
                         ap->ssid[0] == '\0' ? "<hidden>" : (char *)ap->ssid);
                embeddedCliPrint(cli_ptr, line);
            }
        } else {
            embeddedCliPrint(cli_ptr, "Failed to retrieve APs list from memory.");
        }
    } else {
        embeddedCliPrint(cli_ptr, "WiFi scan failed.");
    }
    
    task_manager_unregister_current_task();
    vTaskDelete(NULL);
}

//################################ COMMANDS ####################################################################################################
void wifi_connect_console(EmbeddedCli *cli, char *args, void *context)
{
    uint16_t token_count = embeddedCliGetTokenCount(args);
    const char *ssid = embeddedCliGetToken(args, 1);
    const char *password = (token_count >= 2) ? embeddedCliGetToken(args, 2) : NULL;

    if (ssid == NULL || token_count > 2) {
        embeddedCliPrint(cli, "usage: wifi_connect <ssid> [password]");
        embeddedCliPrint(cli, "if ssid/password contain spaces, use quotes: wifi_connect \"My SSID\" \"My Pass\"");
        return;
    }

    if (strlen(ssid) > WIFI_CONSOLE_SSID_MAX_LEN || (password != NULL && strlen(password) > WIFI_CONSOLE_PASS_MAX_LEN)) {
        embeddedCliPrint(cli, "ssid/password too long");
        return;
    }

    wifi_connect_console_args_t *params = calloc(1, sizeof(wifi_connect_console_args_t));
    if (params == NULL) {
        embeddedCliPrint(cli, "out of memory");
        return;
    }
    strncpy(params->ssid, ssid, WIFI_CONSOLE_SSID_MAX_LEN);
    if (password != NULL) {
        strncpy(params->password, password, WIFI_CONSOLE_PASS_MAX_LEN);
    }

    if (task_manager_create_task(wifi_connect_task, "wifi_connect_tsk", 4096, params, 5, NULL) != ESP_OK) {
        embeddedCliPrint(cli, "connection already in progress, or registry/memory full");
        free(params);
    }
}


void wifi_scan_console(EmbeddedCli *cli, char *args, void *context)
{
    if (task_manager_is_running("wifi_scan_tsk")) {
        embeddedCliPrint(cli, "A WiFi scan is already in progress. Please wait...");
        return;
    }
    if (task_manager_create_task(wifi_scan_task, "wifi_scan_tsk", 4096, cli, 5, NULL) != ESP_OK) {
        embeddedCliPrint(cli, "Failed to start scan task (registry or memory full)");
    }
}


void port_scan_console(EmbeddedCli *cli, char *args, void *context)
{
    uint16_t token_count = embeddedCliGetTokenCount(args);
    const char *target = embeddedCliGetToken(args, 1);
    const char *port = (token_count >= 2) ? embeddedCliGetToken(args, 2) : NULL;

    if (target == NULL || token_count > 2) {
        embeddedCliPrint(cli, "usage: port_scan <target> [port]");
        return;
    }

    if (port == NULL) {
        embeddedCliPrint(cli, "usage: port_scan <target> [port]");
        return;
    }

    ip4_addr_t target_ip;
    ip4addr_aton(target, &target_ip);
    uint16_t port_int = atoi(port);

    int scan_res = port_scan(target_ip, port_int, 0, TCP_SYN_SCAN);
    char buff[32];
    switch (scan_res)
    {
    case PORT_CLOSED:
        snprintf(buff, sizeof(buff), "PORT %d [CLOSED]", port_int);
        embeddedCliPrint(cli, buff);
        break;
    case PORT_FILTERED:
        snprintf(buff, sizeof(buff), "PORT %d [FILTERED]", port_int);
        embeddedCliPrint(cli, buff);
        break;
    case PORT_OPEN:
        snprintf(buff, sizeof(buff), "PORT %d [OPEN]", port_int);
        embeddedCliPrint(cli, buff);
        break;
    default:
        snprintf(buff, sizeof(buff), "PORT %d [ERROR]", port_int);
        embeddedCliPrint(cli, buff);
        break;
    }
}


void task_summary(EmbeddedCli *cli, char *args, void *context) 
{
    task_manager_print_summary();
}


void meminfo(EmbeddedCli *cli, char *args, void *context)
{
    char buff[64];

    /* Internal RAM (DRAM): where task stacks and most heap allocations */
    size_t total_internal   = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    size_t free_internal    = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t min_free_internal = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_internal  = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    /* Combined heap across all capabilities (internal + PSRAM if present). */
    size_t free_default = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

    embeddedCliPrint(cli, "--- Memory info ---");

    /* This is the pool the heap allocator owns AFTER .bss/.data/.noinit and
     * early boot reservations -- i.e. the real budget shared by every
     * malloc() for the rest of the device's life (WiFi/BT buffers, task
     * stacks created after boot, cJSON, sockets, everything). */
    snprintf(buff, sizeof(buff), "Internal heap TOTAL:  %u bytes", (unsigned int)total_internal);
    embeddedCliPrint(cli, buff);

    snprintf(buff, sizeof(buff), "Internal free:        %u bytes", (unsigned int)free_internal);
    embeddedCliPrint(cli, buff);

    snprintf(buff, sizeof(buff), "Internal min-ever:    %u bytes", (unsigned int)min_free_internal);
    embeddedCliPrint(cli, buff);

    snprintf(buff, sizeof(buff), "Internal largest blk: %u bytes", (unsigned int)largest_internal);
    embeddedCliPrint(cli, buff);

    snprintf(buff, sizeof(buff), "Default heap free:    %u bytes", (unsigned int)free_default);
    embeddedCliPrint(cli, buff);
}


void cjson_pool_stats_cmd(EmbeddedCli *cli, char *args, void *context)
{
    char buff[80];
    size_t free_blocks, total_blocks, min_free_ever, fallback_count;

    cjson_pool_get_stats(&free_blocks, &total_blocks, &min_free_ever, &fallback_count);

    embeddedCliPrint(cli, "--- cJSON pool stats ---");

    snprintf(buff, sizeof(buff), "Blocks free now:    %u / %u", (unsigned int)free_blocks, (unsigned int)total_blocks);
    embeddedCliPrint(cli, buff);

    snprintf(buff, sizeof(buff), "Blocks min-ever:    %u / %u", (unsigned int)min_free_ever, (unsigned int)total_blocks);
    embeddedCliPrint(cli, buff);

    snprintf(buff, sizeof(buff), "Fallback to malloc: %u", (unsigned int)fallback_count);
    embeddedCliPrint(cli, buff);
}


void reboot(EmbeddedCli *cli, char *args, void *context) {
    esp_restart();
}
//##############################################################################################################################################


static void writeCharToCli(EmbeddedCli *embeddedCli, char c) {
    uart_write_bytes(UART_PORT_NUM, &c, 1);
}


static void uart_read_task(void *pvParameters) 
{
    uint8_t c;
    while(true) 
    {
        int rxBytes = uart_read_bytes(UART_PORT_NUM, &c, 1, pdMS_TO_TICKS(10));
        if (rxBytes > 0) {
            embeddedCliReceiveChar(cli, (char)c);
        }
        embeddedCliProcess(cli);
    }
}


esp_err_t console_init(void)
{
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(UART_PORT_NUM, &uart_config);
    uart_driver_install(UART_PORT_NUM, 256, 0, 0, NULL, 0);

    EmbeddedCliConfig *config = embeddedCliDefaultConfig();
    config->maxBindingCount = 16;
    cli = embeddedCliNew(config);
    cli->writeChar = writeCharToCli;

    if(cli == NULL) {
        return ESP_FAIL;
    }

    CliCommandBinding reboot_cmd = {
        .name = "reboot",
        .help = "Reboot the device",
        .tokenizeArgs = true,
        .context = NULL,
        .binding = reboot
    };
    embeddedCliAddBinding(cli, reboot_cmd);

    CliCommandBinding task_summary_cmd = {
        .name = "task-summary",
        .help = "Get tasks summary",
        .tokenizeArgs = true,
        .context = NULL,
        .binding = task_summary
    };
    embeddedCliAddBinding(cli, task_summary_cmd);

    CliCommandBinding meminfo_cmd = {
        .name = "meminfo",
        .help = "Print RAM memory usage",
        .tokenizeArgs = true,
        .context = NULL,
        .binding = meminfo
    };
    embeddedCliAddBinding(cli, meminfo_cmd);

    CliCommandBinding cjson_pool_stats_binding = {
        .name = "cjson-pool-stats",
        .help = "Print cJSON memory pool allocator stats",
        .tokenizeArgs = true,
        .context = NULL,
        .binding = cjson_pool_stats_cmd
    };
    embeddedCliAddBinding(cli, cjson_pool_stats_binding);

    CliCommandBinding wifi_connect_cmd = {
        .name = "wifi_connect",
        .help = "Connect to a wifi network: wifi_connect <ssid> [password]",
        .tokenizeArgs = true,
        .context = NULL,
        .binding = wifi_connect_console
    };
    embeddedCliAddBinding(cli, wifi_connect_cmd);

    CliCommandBinding port_scan_cmd = {
        .name = "port_scan",
        .help = "Run a port scan: port_scan <target> [port]",
        .tokenizeArgs = true,
        .context = NULL,
        .binding = port_scan_console
    };
    embeddedCliAddBinding(cli, port_scan_cmd);

    CliCommandBinding wifi_scan_cmd = {
        .name = "wifi_scan",
        .help = "Scan for nearby WiFi networks",
        .tokenizeArgs = false,
        .context = NULL,
        .binding = wifi_scan_console
    };
    embeddedCliAddBinding(cli, wifi_scan_cmd);

    esp_err_t task_err = task_manager_create_task(uart_read_task, "console_read_task", 4096, NULL, 5, &console_task_handle);
    return task_err;
}