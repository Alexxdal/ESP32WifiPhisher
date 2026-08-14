#include <driver/uart.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "console.h"
#define EMBEDDED_CLI_IMPL
#include "embedded_cli.h"
#define UART_PORT_NUM UART_NUM_0
#include "TaskManager.h"
#include "wifiMng.h"

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


void task_summary(EmbeddedCli *cli, char *args, void *context) {
    task_manager_print_summary();
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

    CliCommandBinding wifi_connect_cmd = {
        .name = "wifi_connect",
        .help = "Connect to a wifi network: wifi_connect <ssid> [password]",
        .tokenizeArgs = true,
        .context = NULL,
        .binding = wifi_connect_console
    };
    embeddedCliAddBinding(cli, wifi_connect_cmd);

    esp_err_t task_err = task_manager_create_task(uart_read_task, "console_read_task", 4096, NULL, 5, &console_task_handle);
    return task_err;
}