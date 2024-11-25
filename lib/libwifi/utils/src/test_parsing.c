#include "helpers.h"
#include <errno.h>
#include <libwifi.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>

#define PCAP_SAVEFILE "/tmp/debug.pcap"
#define FILTER ""
#define MODE_BEACON 1
#define MODE_PROBE_RESPONSE 2
#define MODE_PROBE_REQUEST 3
#define MODE_EAPOL 4
#define MODE_DEAUTH 5
#define MODE_DISASSOC 6
#define MODE_ASSOC_RESPONSE 7
#define MODE_ASSOC_REQUEST 8
#define MODE_REASSOC_REQUEST 9
#define MODE_REASSOC_RESPONSE 10
#define MODE_DATA 11
#define MODE_ALL 99

static pcap_t *handle;
pcap_dumper_t *pd;
static struct bpf_program *filter;
static int got_radiotap;
static unsigned long packet_num = 0;
static int mode = 0;
static int parse_radiotap_header = 0;

struct libwifi_bss bss = {0};
struct libwifi_sta sta = {0};

void help(const char *);
void parse_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void print_bss_info(struct libwifi_bss *bss);
void print_sta_info(struct libwifi_sta *sta);
void print_tag_info(unsigned char *data, size_t data_len);

void interrupted(int signum) {
    pcap_dump_close(pd);
    pcap_close(handle);
}

void print_bss_info(struct libwifi_bss *bss) {
    if (bss == NULL) {
        return;
    }

    printf("=== BSS Parsing ===\n");
    printf("ESSID: %s\n", bss->hidden ? "(hidden)" : bss->ssid);
    printf("BSSID: " MACSTR "\n", MAC2STR(bss->bssid));
    printf("Receiver: " MACSTR "\n", MAC2STR(bss->receiver));
    printf("Transmitter: " MACSTR "\n", MAC2STR(bss->transmitter));
    printf("Channel: %d\n", bss->channel);
    printf("WPS: %s\n", bss->wps ? "yes" : "no");

    char sec_buf[LIBWIFI_SECURITY_BUF_LEN];
    libwifi_get_security_type(bss, sec_buf);
    printf("Encryption: %s\n", sec_buf);

    libwifi_get_group_ciphers(bss, sec_buf);
    printf("\tGroup Ciphers: %s\n", sec_buf);

    libwifi_get_pairwise_ciphers(bss, sec_buf);
    printf("\tPairwise Ciphers: %s\n", sec_buf);

    libwifi_get_auth_key_suites(bss, sec_buf);
    printf("\tAuth Key Suites: %s\n", sec_buf);

    if (bss->rsn_info.rsn_capabilities & LIBWIFI_RSN_CAPAB_MFP_CAPABLE) {
        printf("\tMFP Capable: Yes\n");
    }
    if (bss->rsn_info.rsn_capabilities & LIBWIFI_RSN_CAPAB_MFP_REQUIRED) {
        printf("\tMFP Required: Yes\n");
    }

    if (bss->tags.length) {
        printf("Tagged Parameters:\n");
        print_tag_info(bss->tags.parameters, bss->tags.length);
    } else {
        printf("Tagged Parameters: None\n");
    }

    printf("=== BSS End ===\n");
    printf("\n\n");
}

void print_sta_info(struct libwifi_sta *sta) {
    if (sta == NULL) {
        return;
    }

    printf("=== STA Parsing ===\n");

    if (sta->broadcast_ssid) {
        printf("ESSID: <broadcast>\n");
    } else {
        printf("ESSID: %s\n", sta->ssid);
    }
    printf("Channel: %u\n", sta->channel);
    printf("BSSID: " MACSTR "\n", MAC2STR(sta->bssid));
    printf("MAC: " MACSTR "\n", MAC2STR(sta->transmitter));

    printf("=== STA End ===\n");
    printf("\n\n");
}

void print_tag_info(unsigned char *data, size_t data_len) {
    struct libwifi_tag_iterator it;
    if (libwifi_tag_iterator_init(&it, data, data_len) != 0) {
        printf("Couldn't initialise tag iterator\n");
        return;
    }
    do {
        printf("\tTag: %d (Size: %d)\n", it.tag_header->tag_num, it.tag_header->tag_len);

        int max_size = 16;
        if (it.tag_header->tag_len < 16) {
            max_size = it.tag_header->tag_len;
        }
        printf("\t%d bytes of Tag Data: ", max_size);
        for (size_t i = 0; i < max_size; i++) {
            printf("%02x ", it.tag_data[i]);
        }
        printf("\n");
    } while (libwifi_tag_iterator_next(&it) != -1);
}

void parse_radiotap(const struct libwifi_frame *frame) {
    const struct libwifi_radiotap_info *rtap_info = frame->radiotap_info;

    printf("=== Radiotap Parsing ===\n");
    printf("Radiotap Channel Freq: %d MHz\n", rtap_info->channel.freq);
    printf("Radiotap Freq Band: ");
    if (rtap_info->channel.band & LIBWIFI_RADIOTAP_BAND_2GHZ) {
        printf("2.4 GHz\n");
    } else if (rtap_info->channel.band & LIBWIFI_RADIOTAP_BAND_5GHZ) {
        printf("5 GHz\n");
    } else if (rtap_info->channel.band & LIBWIFI_RADIOTAP_BAND_6GHZ) {
        printf("6 GHz\n");
    } else {
        printf("Unknown Band\n");
    }
    printf("Radiotap Channel: %d\n", rtap_info->channel.center);
    printf("Radiotap Channel Flags: 0x%04x\n", rtap_info->channel.flags);
    printf("Radiotap Rate: %.2f Mb/s\n", rtap_info->rate);
    printf("Radiotap Rate Raw: 0x%02x\n", rtap_info->rate_raw);
    printf("Radiotap Signal: %d dBm\n", rtap_info->signal);
    for (int i = 0; i < rtap_info->antenna_count; i++) {
        printf("Radiotap Antenna %d: %d dBm\n", rtap_info->antennas[i].antenna_number, rtap_info->antennas[i].signal);
    }
    printf("Radiotap Flags: 0x%04x\n", rtap_info->flags);
    printf("Radiotap Extended Flags: 0x%08x\n", rtap_info->extended_flags);
    printf("Radiotap RX Flags: 0x%04x\n", rtap_info->rx_flags);
    printf("Radiotap TX Flags: 0x%04x\n", rtap_info->tx_flags);
    printf("Radiotap TX Power: %d\n", rtap_info->tx_power);
    printf("Radiotap RTS Retries: %d\n", rtap_info->rts_retries);
    printf("Radiotap Data Retries: %d\n", rtap_info->data_retries);
    printf("=== Radiotap End ===\n");
}

void parse_beacon(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_BEACON) {
        printf("Packet : %lu\n", packet_num);
        int ret = libwifi_parse_beacon(&bss, &frame);
        if (ret != 0) {
            printf("Failed to parse beacon: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        print_bss_info(&bss);
    }
}

void parse_probe_request(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_PROBE_REQ) {
        printf("Packet : %lu\n", packet_num);
        int ret = libwifi_parse_probe_req(&sta, &frame);
        if (ret != 0) {
            printf("Failed to parse probe request: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        print_sta_info(&sta);
    }
}
void parse_probe_response(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_PROBE_RESP) {
        printf("Packet : %lu\n", packet_num);
        int ret = libwifi_parse_probe_resp(&bss, &frame);
        if (ret != 0) {
            printf("Failed to parse probe response: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        print_bss_info(&bss);
    }
}
void parse_deauth(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_DEAUTH) {
        printf("Packet : %lu\n", packet_num);
        struct libwifi_parsed_deauth deauth;
        int ret = libwifi_parse_deauth(&deauth, &frame);
        if (ret != 0) {
            printf("Failed to parse deauthentication: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        printf("=== Deauthentication Frame ===\n");
        if (deauth.ordered) {
            printf("Address 1: " MACSTR "\n", MAC2STR(deauth.frame_header.ordered.addr1));
            printf("Address 2: " MACSTR "\n", MAC2STR(deauth.frame_header.ordered.addr2));
            printf("Address 3: " MACSTR "\n", MAC2STR(deauth.frame_header.ordered.addr3));
        } else {
            printf("Address 1: " MACSTR "\n", MAC2STR(deauth.frame_header.unordered.addr1));
            printf("Address 2: " MACSTR "\n", MAC2STR(deauth.frame_header.unordered.addr2));
            printf("Address 3: " MACSTR "\n", MAC2STR(deauth.frame_header.unordered.addr3));
        }

        printf("Reason: %d (0x%04x)\n", deauth.fixed_parameters.reason_code, deauth.fixed_parameters.reason_code);

        if (deauth.tags.length) {
            printf("Tagged Parameters:\n");
            print_tag_info(deauth.tags.parameters, deauth.tags.length);
        } else {
            printf("Tagged Parameters: None\n");
        }

        printf("=== End Deauthentication Frame ===\n");
        printf("\n\n");
    }
}
void parse_disassoc(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_DISASSOC) {
        printf("Packet : %lu\n", packet_num);
        struct libwifi_parsed_disassoc disassoc;
        int ret = libwifi_parse_disassoc(&disassoc, &frame);
        if (ret != 0) {
            printf("Failed to parse diassociation: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        printf("=== Disassociation Frame ===\n");
        if (disassoc.ordered) {
            printf("Address 1: " MACSTR "\n", MAC2STR(disassoc.frame_header.ordered.addr1));
            printf("Address 2: " MACSTR "\n", MAC2STR(disassoc.frame_header.ordered.addr2));
            printf("Address 3: " MACSTR "\n", MAC2STR(disassoc.frame_header.ordered.addr3));
        } else {
            printf("Address 1: " MACSTR "\n", MAC2STR(disassoc.frame_header.unordered.addr1));
            printf("Address 2: " MACSTR "\n", MAC2STR(disassoc.frame_header.unordered.addr2));
            printf("Address 3: " MACSTR "\n", MAC2STR(disassoc.frame_header.unordered.addr3));
        }

        printf("Reason: %d (0x%04x)\n", disassoc.fixed_parameters.reason_code, disassoc.fixed_parameters.reason_code);

        printf("Tagged Parameters:\n");
        if (disassoc.tags.length == 0) {
            printf("\tNo Tags\n");
        } else {
            printf("\tTags Found\n");
        }

        printf("=== End Disassociation Frame ===\n");
        printf("\n\n");
    }
}
void parse_assoc_request(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_ASSOC_REQ) {
        printf("Packet : %lu\n", packet_num);
        int ret = libwifi_parse_assoc_req(&sta, &frame);
        if (ret != 0) {
            printf("Failed to parse association request: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        print_sta_info(&sta);
    }
}
void parse_assoc_response(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_ASSOC_RESP) {
        printf("Packet : %lu\n", packet_num);
        int ret = libwifi_parse_assoc_resp(&bss, &frame);
        if (ret != 0) {
            printf("Failed to parse association response: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        print_bss_info(&bss);
    }
}
void parse_reassoc_request(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_REASSOC_REQ) {
        printf("Packet : %lu\n", packet_num);
        int ret = libwifi_parse_reassoc_req(&sta, &frame);
        if (ret != 0) {
            printf("Failed to parse reassociation request: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        print_sta_info(&sta);
    }
}
void parse_reassoc_response(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_REASSOC_RESP) {
        printf("Packet : %lu\n", packet_num);
        int ret = libwifi_parse_reassoc_resp(&bss, &frame);
        if (ret != 0) {
            printf("Failed to parse reassociation response: %d\n", ret);
            pcap_dump(args, header, packet);
            return;
        }

        print_bss_info(&bss);
    }
}
void parse_data_eapol(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_DATA) {
        if (libwifi_check_wpa_handshake(&frame) > 0) {
            printf("=== EAPOL ===\n");
            printf("WPA Handshake\n");
            int part = libwifi_check_wpa_message(&frame);
            printf("WPA Handshake Message: %s\n", libwifi_get_wpa_message_string(&frame));

            struct libwifi_wpa_auth_data data = {0};
            libwifi_get_wpa_data(&frame, &data);

            printf("EAPOL: Version: %d\n", data.version);
            printf("EAPOL: Type: %d\n", data.type);
            printf("EAPOL: Length: %d\n", data.length);
            printf("EAPOL: Descriptor: %d\n", data.descriptor);
            printf("EAPOL: Key Info: Information: 0x%04x\n", data.key_info.information);
            printf("EAPOL: Key Info: Key Length: %d\n", data.key_info.key_length);
            printf("EAPOL: Key Info: Replay Counter: %" PRIu64 "\n", data.key_info.replay_counter);
            printf("EAPOL: Key Info: Nonce: ");
            for (size_t i = 0; i < sizeof(data.key_info.nonce); ++i) printf("%02x ", data.key_info.nonce[i]);
                printf("\n");
            printf("EAPOL: Key Info: IV: ");
            for (size_t i = 0; i < sizeof(data.key_info.iv); ++i) printf("%02x ", data.key_info.iv[i]);
                printf("\n");
            printf("EAPOL: Key Info: RSC: ");
            for (size_t i = 0; i < sizeof(data.key_info.rsc); ++i) printf("%02x ", data.key_info.rsc[i]);
                printf("\n");
            printf("EAPOL: Key Info: ID: ");
            for (size_t i = 0; i < sizeof(data.key_info.id); ++i) printf("%02x ", data.key_info.id[i]);
                printf("\n");
            printf("EAPOL: Key Info: MIC: ");
            for (size_t i = 0; i < sizeof(data.key_info.mic); ++i) printf("%02x ", data.key_info.mic[i]);
                printf("\n");
            printf("EAPOL: Key Info: Key Data Length: %d\n", data.key_info.key_data_length);
            if (data.key_info.key_data_length) {
                printf("EAPOL: Key Info: Key Data: ");
                for (size_t i = 0; i < data.key_info.key_data_length; ++i) printf("%02x ", data.key_info.key_data[i]);
                    printf("\n");
            }

            libwifi_free_wpa_data(&data);

            printf("\n\n");
        }
    }
}

void parse_data(struct libwifi_frame frame, unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (frame.frame_control.type == TYPE_DATA) {
        if (frame.flags & LIBWIFI_FLAGS_IS_QOS) {
            printf("Receiver: " MACSTR "\n", MAC2STR(frame.header.data_qos.addr1));
            printf("Transmitter: " MACSTR "\n", MAC2STR(frame.header.data_qos.addr2));
        } else {
            printf("Receiver: " MACSTR "\n", MAC2STR(frame.header.data.addr1));
            printf("Transmitter: " MACSTR "\n", MAC2STR(frame.header.data.addr2));
        }
        printf("Body Length: %zu\n", frame.len - frame.header_len);
        printf("Body:\n");
        hexdump(frame.body, frame.len - frame.header_len);
    }
}

void parse_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    ++packet_num;
    unsigned long data_len = header->caplen;
    unsigned char *data = (unsigned char *) packet;

    struct libwifi_frame frame = {0};
    int ret = libwifi_get_wifi_frame(&frame, data, data_len, parse_radiotap_header);
    if (ret != 0) {
        printf("[!] Error getting libwifi_frame: %d\n", ret);
        return;
    }

    if (got_radiotap && parse_radiotap_header && frame.flags & LIBWIFI_FLAGS_RADIOTAP_PRESENT) {
        parse_radiotap(&frame);
    }

    memset(&bss, 0, sizeof(struct libwifi_bss));
    memset(&sta, 0, sizeof(struct libwifi_sta));

    switch (mode) {
        case MODE_BEACON:
            parse_beacon(frame, args, header, packet);
            break;
        case MODE_PROBE_REQUEST:
            parse_probe_request(frame, args, header, packet);
            break;
        case MODE_PROBE_RESPONSE:
            parse_probe_response(frame, args, header, packet);
            break;
        case MODE_DEAUTH:
            parse_deauth(frame, args, header, packet);
            break;
        case MODE_DISASSOC:
            parse_disassoc(frame, args, header, packet);
            break;
        case MODE_ASSOC_REQUEST:
            parse_assoc_request(frame, args, header, packet);
            break;
        case MODE_ASSOC_RESPONSE:
            parse_assoc_response(frame, args, header, packet);
            break;
        case MODE_REASSOC_REQUEST:
            parse_reassoc_request(frame, args, header, packet);
            break;
        case MODE_REASSOC_RESPONSE:
            parse_reassoc_response(frame, args, header, packet);
            break;
        case MODE_EAPOL:
            parse_data_eapol(frame, args, header, packet);
            break;
        case MODE_DATA:
            parse_data(frame, args, header, packet);
            break;
        case MODE_ALL:
            parse_beacon(frame, args, header, packet);
            parse_probe_request(frame, args, header, packet);
            parse_probe_response(frame, args, header, packet);
            parse_deauth(frame, args, header, packet);
            parse_disassoc(frame, args, header, packet);
            parse_assoc_request(frame, args, header, packet);
            parse_assoc_response(frame, args, header, packet);
            parse_reassoc_request(frame, args, header, packet);
            parse_reassoc_response(frame, args, header, packet);
            parse_data_eapol(frame, args, header, packet);
            parse_data(frame, args, header, packet);
        default:
            break;
    }

    libwifi_free_bss(&bss);
    libwifi_free_wifi_frame(&frame);
}

void help(const char *name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\t%s --interface [interface] [--mode] [--radiotap]\n", name);
    fprintf(stderr, "\t\tor\n");
    fprintf(stderr, "\t%s --file [capture file] [--mode] [--radiotap]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "\t--beacon\n");
    fprintf(stderr, "\t--probe-req\n");
    fprintf(stderr, "\t--probe-resp\n");
    fprintf(stderr, "\t--deauth\n");
    fprintf(stderr, "\t--disassoc\n");
    fprintf(stderr, "\t--assoc-req\n");
    fprintf(stderr, "\t--assoc-resp\n");
    fprintf(stderr, "\t--reassoc-req\n");
    fprintf(stderr, "\t--reassoc-resp\n");
    fprintf(stderr, "\t--eapol\n");
}

void handle_args(int argc, const char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 4) {
        help(argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[1], "--file") == 0) {
        if ((handle = pcap_open_offline(argv[2], errbuf)) == NULL) {
            fprintf(stderr, "Couldn't read file %s: %s\n", argv[2], errbuf);
            exit(EXIT_FAILURE);
        }
    } else if (strcmp(argv[1], "--interface") == 0) {
        if ((handle = pcap_create(argv[2], errbuf)) == NULL) {
            fprintf(stderr, "Failed to open interface \"%s\" for sniffing: %s\n", argv[2], errbuf);
            exit(EXIT_FAILURE);
        }
        if (pcap_activate(handle) == 0) {
            printf("[+] Started sniffing on %s\n", argv[2]);
        } else {
            fprintf(stderr, "[!] Couldn't activate capture: %s.\n", pcap_geterr(handle));
            pcap_close(handle);
            exit(EXIT_FAILURE);
        }
    } else {
        help(argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[3], "--beacon") == 0) {
        mode = MODE_BEACON;
    } else if (strcmp(argv[3], "--probe-req") == 0) {
        mode = MODE_PROBE_REQUEST;
    } else if (strcmp(argv[3], "--probe-resp") == 0) {
        mode = MODE_PROBE_RESPONSE;
    } else if (strcmp(argv[3], "--deauth") == 0) {
        mode = MODE_DEAUTH;
    } else if (strcmp(argv[3], "--disassoc") == 0) {
        mode = MODE_DISASSOC;
    } else if (strcmp(argv[3], "--assoc-req") == 0) {
        mode = MODE_ASSOC_REQUEST;
    } else if (strcmp(argv[3], "--assoc-resp") == 0) {
        mode = MODE_ASSOC_RESPONSE;
    } else if (strcmp(argv[3], "--reassoc-req") == 0) {
        mode = MODE_REASSOC_REQUEST;
    } else if (strcmp(argv[3], "--reassoc-resp") == 0) {
        mode = MODE_REASSOC_RESPONSE;
    } else if (strcmp(argv[3], "--eapol") == 0) {
        mode = MODE_EAPOL;
    } else if (strcmp(argv[3], "--data") == 0) {
        mode = MODE_DATA;
    } else if (strcmp(argv[3], "--all") == 0) {
        mode = MODE_ALL;
    } else {
        help(argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (argc > 4) {
        if (strcmp(argv[4], "--radiotap") == 0) {
            parse_radiotap_header = 1;
        }
    }
}

int main(int argc, const char *argv[]) {
    packet_num = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle_args(argc, argv);

    int linktype = pcap_datalink(handle);
    if (linktype == DLT_IEEE802_11_RADIO) {
        got_radiotap = 1;
    } else if (linktype == DLT_IEEE802_11) {
        got_radiotap = 0;
    } else {
        fprintf(stderr, "[!] 802.11 and radiotap headers not provided (%d)\n", pcap_datalink(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    if ((filter = malloc(sizeof(struct bpf_program))) == NULL) {
        perror("Malloc failure");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    printf("[*] Compiling and optimizing frame filter, this can take a second\n");
    if (pcap_compile(handle, filter, FILTER, 0, 0) != 0) {
        fprintf(stderr, "[!] Couldn't compile filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        free(filter);
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, filter) != 0) {
        fprintf(stderr, "[!] Couldn't set filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        free(filter);
        exit(EXIT_FAILURE);
    }
    printf("[+] Complete\n");

    pd = pcap_dump_open(handle, PCAP_SAVEFILE);
    pcap_loop(handle, -1 /*INFINITY*/, &parse_packet, (unsigned char *) pd);

    return 0;
}
