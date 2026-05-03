#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/err.h"


#define DNS_PORT 53
#define RESPONSE_IP_ADDR {192, 168, 4, 1}
static const char *TAG = "DNS_SERVER";
static TaskHandle_t dns_server_task_handle = NULL;
static volatile bool dns_server_running = false;

static void dns_server_task(void *pvParameters) 
{
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buf[512];
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("Errore nella creazione del socket DNS\n");
        vTaskDelete(NULL);
        return;
    }

    // Socket timeout to prevent blocking indefinitely on recvfrom
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(DNS_PORT);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Errore nel bind del socket DNS\n");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGD(TAG, "Server DNS in ascolto sulla porta %d\n", DNS_PORT);

    uint8_t response_template[] = {
        0x00, 0x00, // ID (verrà copiato dalla richiesta)
        0x81, 0x80, // Flag: risposta, senza errori
        0x00, 0x01, // QDCOUNT (1 query)
        0x00, 0x01, // ANCOUNT (1 risposta)
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // Risposta dinamica aggiunta qui sotto
    };
    const uint8_t ip_address[] = RESPONSE_IP_ADDR;

    while (dns_server_running) 
    {
        int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_addr_len);
        if (len < 12) {
            continue;
        }

        // Estrai il QTYPE (Type della richiesta DNS, es. 1 per A, 28 per AAAA)
        // Il QTYPE si trova negli ultimi 4 byte del payload della query
        uint16_t qtype = (buf[len - 4] << 8) | buf[len - 3];

        // Se la richiesta è per un record AAAA (IPv6, qtype == 28), la IGNORIAMO completamente.
        // Questo forza Windows a fare il fallback rapido sull'IPv4 (A).
        if (qtype == 28) {
            continue; // Droppa il pacchetto silenziosamente
        }

        // Rispondiamo solo alle richieste A (1) o ANY (255)
        if (qtype != 1 && qtype != 255) {
            continue;
        }

        // Copia l'ID dalla richiesta
        response_template[0] = buf[0];
        response_template[1] = buf[1];

        // Imposta ANCOUNT a 1 se è una query IPv4, 0 se è IPv6 (Placa Windows)
        response_template[7] = 1;

        // Prepara una risposta DNS dinamica
        uint8_t response[512];
        memcpy(response, response_template, sizeof(response_template));
        int response_len = sizeof(response_template);

        // Copia la query originale
        memcpy(&response[response_len], &buf[12], len - 12); // Copia la query
        response_len += (len - 12);

        // Aggiungi la risposta IP solo se stavano cercando un IPv4
        uint8_t answer[] = {
            0xC0, 0x0C, // Puntatore al nome della query
            0x00, 0x01, // Tipo: A (host address)
            0x00, 0x01, // Classe: IN (Internet)
            0x00, 0x00, 0x00, 0x3C, // TTL: 60 secondi
            0x00, 0x04, // Lunghezza dati: 4 byte (IPv4)
            ip_address[0], ip_address[1], ip_address[2], ip_address[3]
        };
        memcpy(&response[response_len], answer, sizeof(answer));
        response_len += sizeof(answer);

        sendto(sock, response, response_len, 0, (struct sockaddr *)&client_addr, client_addr_len);
    }
    close(sock);
    vTaskDelete(NULL);
}


void dns_server_start(void)
{
    if (dns_server_task_handle != NULL)
    {   
        ESP_LOGE(TAG, "DNS Server already started.");
        return;
    }
    dns_server_running = true;
    xTaskCreate(dns_server_task, "dns_server_task", 4096, NULL, 5, &dns_server_task_handle);
}


void dns_server_stop(void)
{
    if (dns_server_task_handle == NULL)
    {
        ESP_LOGE(TAG, "DNS Server task is not running.");
        return;
    }
    dns_server_running = false;
    vTaskDelay(pdMS_TO_TICKS(100));
    dns_server_task_handle = NULL;
}