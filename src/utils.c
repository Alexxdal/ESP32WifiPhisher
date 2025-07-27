#include <string.h>
#include "esp_log.h"
#include "arpa/inet.h"
#include "utils.h"

bool isMacBroadcast(const uint8_t *mac)
{
    uint8_t broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    return memcmp(mac, broadcast, 6) == 0;
}


bool isMacZero(uint8_t *mac)
{
    uint8_t zero_mac[6] = {0};
    return memcmp(mac, zero_mac, 6) == 0;
}


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
    printf("\nKey Descriptor Version: %d", handshake->key_decriptor_version);
    printf("\n#####################\n");
}


size_t libwifi_dump_wpa_auth_data(struct libwifi_wpa_auth_data *auth_data, uint8_t *buffer, size_t buffer_len) 
{
    if( buffer_len < auth_data->length )
    {
        return -EINVAL; 
    }
    size_t offset = 0;

    // Serialize 'version'
    memcpy(buffer + offset, &auth_data->version, sizeof(auth_data->version));
    offset += sizeof(auth_data->version);

    // Serialize 'type'
    memcpy(buffer + offset, &auth_data->type, sizeof(auth_data->type));
    offset += sizeof(auth_data->type);

    // Serialize 'Length'
    uint16_t data_len_network = htons(auth_data->length); 
    memcpy(buffer + offset, &data_len_network, sizeof(auth_data->length));
    offset += sizeof(auth_data->length);

    // Serialize 'Descriptor'
    memcpy(buffer + offset, &auth_data->descriptor, sizeof(auth_data->descriptor));
    offset += sizeof(auth_data->descriptor);

    // Serialize 'Key information'
    uint16_t key_info_network = htons(auth_data->key_info.information); 
    memcpy(buffer + offset, &key_info_network, sizeof(auth_data->key_info.information));
    offset += sizeof(auth_data->key_info.information);

    // Serialize 'key_len'
    uint16_t key_len_network = htons(auth_data->key_info.key_length);
    memcpy(buffer + offset, &key_len_network, sizeof(auth_data->key_info.key_length));
    offset += sizeof(auth_data->key_info.key_length);

    // Serialize 'Replay counter'
    memcpy(buffer + offset, &auth_data->key_info.replay_counter, sizeof(auth_data->key_info.replay_counter));
    offset += sizeof(auth_data->key_info.replay_counter);

    // Serialize 'nonce'
    memcpy(buffer + offset, auth_data->key_info.nonce, sizeof(auth_data->key_info.nonce));
    offset += sizeof(auth_data->key_info.nonce);
    
    // Serialize 'IV'
    memcpy(buffer + offset, auth_data->key_info.iv, sizeof(auth_data->key_info.iv));
    offset += sizeof(auth_data->key_info.iv);

    // Serialize 'RSC'
    memcpy(buffer + offset, auth_data->key_info.rsc, sizeof(auth_data->key_info.rsc));
    offset += sizeof(auth_data->key_info.rsc);

    // Serialize 'ID'
    memcpy(buffer + offset, auth_data->key_info.id, sizeof(auth_data->key_info.id));
    offset += sizeof(auth_data->key_info.id);

    // Serialize 'mic'
    memcpy(buffer + offset, auth_data->key_info.mic, sizeof(auth_data->key_info.mic));
    offset += sizeof(auth_data->key_info.mic);

    // Serialize 'data_len'
    uint16_t key_data_len_network = htons(auth_data->key_info.key_data_length);
    memcpy(buffer + offset, &key_data_len_network, sizeof(auth_data->key_info.key_data_length));
    offset += sizeof(auth_data->key_info.key_data_length);

    // Serialize 'data'
    memcpy(buffer + offset, auth_data->key_info.key_data, auth_data->key_info.key_data_length);
    offset += auth_data->key_info.key_data_length;

    return offset;
}


uint8_t getNextChannel(uint8_t current_channel)
{
    if( current_channel >= 14 )
    {
        return 1;
    }
    else
    {
        return current_channel + 1;
    }
}