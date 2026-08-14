#include <driver/uart.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "console.h"
#define EMBEDDED_CLI_IMPL
#include "embedded_cli.h"
#define UART_PORT_NUM UART_NUM_0

static EmbeddedCli *cli = NULL;
static TaskHandle_t console_task_handle = NULL;

void onLed(EmbeddedCli *cli, char *args, void *context) {
    const char *arg1 = embeddedCliGetToken(args, 1);
    const char *arg2 = embeddedCliGetToken(args, 2);
    if (arg1 == NULL || arg2 == NULL) {
        embeddedCliPrint(cli, "usage:La libreria `embedded-cli` è un get-led [arg1] [arg2]");
        return;
    }
    // Make sure to check if 'args' != NULL, printf's '%s' formatting does not like a null pointer.
    char out_buffer[64];
    snprintf(out_buffer, sizeof(out_buffer), "LED with args: %s and %s", arg1, arg2);
    embeddedCliPrint(cli, out_buffer);
}


static void writeCharToCli(EmbeddedCli *embeddedCli, char c) 
{
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

    CliCommandBinding led_binding = {
        .name = "get-led",
        .help = "Get led status",
        .tokenizeArgs = true,
        .context = NULL,
        .binding = onLed
    };
    embeddedCliAddBinding(cli, led_binding);
    xTaskCreate(uart_read_task, "cli_task", 4096, NULL, 5, &console_task_handle);

    return ESP_OK;
}