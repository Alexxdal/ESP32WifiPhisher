#include "esp_log.h"
#include "utils.h"


void print_packet(uint8_t *data, size_t len)
{
    printf("\nPACKET DATA: ############\n");
    for(size_t i = 0; i < len; i++ )
    {
        printf("%02X ", data[i]);
    }
    printf("\n####################\n");
}


void print_buffer(uint8_t *buffer, size_t len)
{
    for(size_t i = 0; i < len; i++ )
    {
        printf("%02X ", buffer[i]);
    }
}


void print_handshake(handshake_info_t *handshake)
{
    printf("\nHANDSHAKE DATA: ############\n");
    printf("Station: ");
    print_buffer(handshake->mac_sta, sizeof(handshake->mac_sta));
    printf("\nANonce: ");
    print_buffer(handshake->anonce, sizeof(handshake->anonce));
    printf("\nSNonce: ");
    print_buffer(handshake->snonce, sizeof(handshake->snonce));
    printf("\nMIC: ");
    print_buffer(handshake->mic, sizeof(handshake->mic));
    printf("\nEAPOL: ");
    print_buffer(handshake->eapol, handshake->eapol_len);
    printf("\n#####################\n");
}
