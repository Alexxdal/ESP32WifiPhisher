#include <errno.h>
#include <libwifi.h>
#include <libwifi/core/frame/tag.h>
#include <pcap.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "helpers.h"

#define LIVE_INJECT 0
#define OFFLINE_DUMP 1

#define MODE_BEACON 0
#define MODE_PROBE_RESPONSE 1
#define MODE_PROBE_REQUEST 2
#define MODE_DEAUTH 3
#define MODE_DISASSOC 4
#define MODE_ASSOC_RESPONSE 5
#define MODE_ASSOC_REQUEST 6
#define MODE_REASSOC_RESPONSE 7
#define MODE_REASSOC_REQUEST 8
#define MODE_AUTH 9
#define MODE_RTS 10
#define MODE_CTS 11
#define MODE_RANDOM_BEACON 12
#define MODE_ACTION 13
#define MODE_ACTION_NOACK 14
#define MODE_TIMING_AD 15
#define MODE_ATIM 16

#define SNAPLEN 96
#define CHANNEL 11
#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
#define FROM_MAC "\x00\x20\x91\x11\x22\x33"
#define REASSOC_MAC "\xAA\xBB\xCC\xDD\xEE\xFF"
#define BEACON_SSID "libwifi-beacon"
#define PROBE_RESP_SSID "libwifi-probe-resp"
#define PROBE_REQ_SSID "libwifi-probe-req"
#define ASSOC_REQ_SSID "libwifi-assoc-req"
#define REASSOC_REQ_SSID "libwifi-reassoc-req"

pcap_t *handle = NULL;
pcap_dumper_t *outputHandle = NULL;
FILE *filename = NULL;

static unsigned char to[] = TO_MAC;
static unsigned char from[] = FROM_MAC;
static unsigned char bcast[] = BCAST_MAC;
static unsigned char reassoc_mac[] = REASSOC_MAC;
static unsigned char tag_data1[] = "\x00\x13\x37\x01Hello, World!\n";
static unsigned char tag_data2[] = "\x00\x20\x91\x00Goodbye, World!\n";

static int mode = 0;
static int inject_mode = 0;

void handle_interupt(int signal) {
    if (signal == SIGINT) {
        int oldmode = inject_mode;
        mode = -1;
        inject_mode = -1;

        if (oldmode == LIVE_INJECT) {
            pcap_close(handle);
            printf("\n\nClosed Capture Handle!\n");
        } else if (oldmode == OFFLINE_DUMP) {
            pcap_dump_flush(outputHandle);
            pcap_dump_close(outputHandle);
            printf("\n\nDumped and Closed Output File!\n");
        }

        exit(EXIT_SUCCESS);
    }
}

void inject_frame(void *buf, size_t buf_sz) {
    struct libwifi_radiotap_info info = {0};
    info.present = 0x0000002e;     // 0x002e: Flags, Rate, Channel, dBm Ant Signal
    info.channel.flags = 0x0140;   // OFDM, 5GHz
    info.channel.freq = 5180;      // Channel 46
    info.flags = 0x0000;           // No Flags
    info.rate = 1;                 // 1 Mbit
    info.rate_raw = info.rate * 2; // Radiotap uses 500kb/s increments
    info.signal = -20;             // Signal in dBm

    char *rtap = NULL;
    rtap = malloc(LIBWIFI_MAX_RADIOTAP_LEN);
    if (rtap == NULL) {
        printf("malloc failure: %s\n", strerror(errno));
        return;
    }
    memset(rtap, 0, LIBWIFI_MAX_RADIOTAP_LEN);

    int rtap_len = libwifi_create_radiotap(&info, rtap);
    if (rtap_len == -1) {
        printf("error generating radiotap header\n");
        return;
    }

    void *frame = NULL;
    size_t frame_sz = rtap_len + buf_sz;
    frame = malloc(frame_sz);
    if (frame == NULL) {
        printf("malloc failure: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    memcpy(frame, rtap, rtap_len);
    memcpy(frame + rtap_len, buf, buf_sz);

    hexdump(rtap, rtap_len);
    printf("-----\n");
    hexdump(frame, frame_sz);

    if (inject_mode == LIVE_INJECT) {
        pcap_inject(handle, frame, frame_sz);
    } else if (inject_mode == OFFLINE_DUMP) {
        struct pcap_pkthdr hdr = {0};
        hdr.caplen = frame_sz;
        hdr.len = frame_sz;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        hdr.ts = tv;
        pcap_dump((unsigned char *) outputHandle, &hdr, frame);
    }

    free(rtap);
    free(frame);
}

void inject_beacons(int random_mac) {
    while (1) {
        printf("Sending 50 beacons...\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_beacon beacon;
            unsigned char txmac[6] = {0};
            memset(&beacon, 0, sizeof(struct libwifi_beacon));

            if (random_mac) {
                libwifi_random_mac(txmac, NULL);
            } else {
                memcpy(txmac, FROM_MAC, 6);
            }
            libwifi_create_beacon(&beacon, bcast, txmac, txmac, "wifi-beacon", CHANNEL);
            libwifi_quick_add_tag(&beacon.tags, TAG_VENDOR_SPECIFIC, tag_data1, sizeof(tag_data1));
            libwifi_quick_add_tag(&beacon.tags, TAG_VENDOR_SPECIFIC, tag_data2, sizeof(tag_data2));

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_beacon_length(&beacon);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting beacon with:\n");
            printf("\tSSID: %s\n", BEACON_SSID);
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tSource: " MACSTR "\n", MAC2STR(txmac));
            printf("\tDestination: " MACSTR "\n", MAC2STR(bcast));

            libwifi_dump_beacon(&beacon, buf, buf_sz);
            inject_frame(buf, buf_sz);

            libwifi_free_beacon(&beacon);
            free(buf);
            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_probe_responses() {
    while (1) {
        printf("Sending 50 probe responses, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_probe_resp probe_resp;
            memset(&probe_resp, 0, sizeof(struct libwifi_probe_resp));

            libwifi_create_probe_resp(&probe_resp, to, from, from, PROBE_RESP_SSID, CHANNEL);
            libwifi_quick_add_tag(&probe_resp.tags, TAG_VENDOR_SPECIFIC, tag_data1, sizeof(tag_data1));

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_probe_resp_length(&probe_resp);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting probe responses with:\n");
            printf("\tSSID: %s\n", PROBE_RESP_SSID);
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_probe_resp(&probe_resp, buf, buf_sz);
            inject_frame(buf, buf_sz);

            libwifi_free_probe_resp(&probe_resp);
            free(buf);
            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_probe_requests() {
    while (1) {
        printf("Sending 50 probe responses, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_probe_req probe;
            memset(&probe, 0, sizeof(struct libwifi_probe_req));

            libwifi_create_probe_req(&probe, to, from, to, PROBE_REQ_SSID, CHANNEL);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_probe_req_length(&probe);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting probe requests with:\n");
            printf("\tSSID: %s\n", PROBE_REQ_SSID);
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_probe_req(&probe, buf, buf_sz);
            inject_frame(buf, buf_sz);

            libwifi_free_probe_req(&probe);
            free(buf);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_deauths() {
    while (1) {
        printf("Sending 50 probe responses, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_deauth deauth;
            memset(&deauth, 0, sizeof(struct libwifi_deauth));

            libwifi_create_deauth(&deauth, to, from, from, REASON_STA_LEAVING);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_deauth_length(&deauth);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting deauths with:\n");
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tReason: %d\n", REASON_STA_LEAVING);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_deauth(&deauth, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_disassocs() {
    while (1) {
        printf("Sending 50 probe responses, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_disassoc disassoc;
            memset(&disassoc, 0, sizeof(struct libwifi_disassoc));

            libwifi_create_disassoc(&disassoc, to, from, from, REASON_STA_LEAVING);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_disassoc_length(&disassoc);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting disassocs with:\n");
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tReason: %d\n", REASON_STA_LEAVING);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_disassoc(&disassoc, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_assoc_requests() {
    while (1) {
        printf("Sending 50 association requests, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_assoc_req assoc_req;
            memset(&assoc_req, 0, sizeof(struct libwifi_assoc_req));

            libwifi_create_assoc_req(&assoc_req, to, from, from, ASSOC_REQ_SSID, CHANNEL);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_assoc_req_length(&assoc_req);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting association requests with:\n");
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_assoc_req(&assoc_req, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);
            libwifi_free_assoc_req(&assoc_req);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_assoc_responses() {
    while (1) {
        printf("Sending 50 association responses, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_assoc_resp assoc_resp;
            memset(&assoc_resp, 0, sizeof(struct libwifi_assoc_req));

            libwifi_create_assoc_resp(&assoc_resp, to, from, from, CHANNEL);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_assoc_resp_length(&assoc_resp);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting association responses with:\n");
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_assoc_resp(&assoc_resp, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);
            libwifi_free_assoc_resp(&assoc_resp);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_reassoc_requests() {
    while (1) {
        printf("Sending 50 reassociation requests, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_reassoc_req reassoc_req;
            memset(&reassoc_req, 0, sizeof(struct libwifi_assoc_req));

            libwifi_create_reassoc_req(&reassoc_req, to, from, from, reassoc_mac, REASSOC_REQ_SSID, CHANNEL);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_reassoc_req_length(&reassoc_req);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting reassociation requests with:\n");
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));
            printf("\tPrevious BSSID: " MACSTR "\n", MAC2STR(reassoc_mac));

            libwifi_dump_reassoc_req(&reassoc_req, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);
            libwifi_free_reassoc_req(&reassoc_req);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_reassoc_responses() {
    while (1) {
        printf("Sending 50 reassociation responses, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_reassoc_resp reassoc_resp;
            memset(&reassoc_resp, 0, sizeof(struct libwifi_assoc_req));

            libwifi_create_reassoc_resp(&reassoc_resp, to, from, from, CHANNEL);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_reassoc_resp_length(&reassoc_resp);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting reassociation responses with:\n");
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_reassoc_resp(&reassoc_resp, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);
            libwifi_free_reassoc_resp(&reassoc_resp);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_auths() {
    while (1) {
        printf("Sending 50 auth frames, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_auth auth;
            memset(&auth, 0, sizeof(struct libwifi_deauth));

            libwifi_create_auth(&auth, to, from, from, AUTH_OPEN, 0, STATUS_SUCCESS);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_auth_length(&auth);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            libwifi_dump_auth(&auth, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);

            memset(&auth, 0, sizeof(struct libwifi_deauth));

            libwifi_create_auth(&auth, from, to, to, AUTH_OPEN, 1, STATUS_SUCCESS);

            buf = NULL;
            buf_sz = libwifi_get_auth_length(&auth);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting auths with:\n");
            printf("\tChannel: %d\n", CHANNEL);
            printf("\tAlgorithm: %d\n", AUTH_OPEN);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_auth(&auth, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);
            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_timing_ads() {
    while (1) {
        printf("Sending 50 timing advertisement frames, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_timing_advert time_ad = {0};
            struct libwifi_timing_advert_fields ad_fields = {0};

            ad_fields.timing_capabilities = 2;
            memcpy(ad_fields.time_error, "\xCC\xCC\xCC\xCC\xCC", 5);
            memcpy(ad_fields.time_update, "\xBB", 1);
            memcpy(ad_fields.time_value,
                  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 10);

            libwifi_create_timing_advert(&time_ad, to, from, from, &ad_fields, "GB", -56, -56, -30, -20);

            unsigned char *buf = NULL;
            size_t buf_len = libwifi_get_timing_advert_length(&time_ad);
            buf = malloc(buf_len);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }
            printf("buf_len: %zu\n", buf_len);

            size_t ret = libwifi_dump_timing_advert(&time_ad, buf, buf_len);
            if (ret < 0) {
                printf("error dump: %zu\n", ret);
                exit(EXIT_FAILURE);
            }
            hexdump(buf, buf_len);
            inject_frame(buf, buf_len);

            free(buf);
            libwifi_free_timing_advert(&time_ad);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_action_noacks() {
    while (1) {
        printf("Sending 50 action no ack frames, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_action action;
            memset(&action, 0, sizeof(struct libwifi_action));

            libwifi_create_action_no_ack(&action, to, from, from, ACTION_FAST_BSS_TRANSITION);

            unsigned char *action_buf = malloc(256);
            memset(action_buf, 0, 256);

            size_t offset = 0;
            size_t w = 0;

            memcpy(action_buf, "\x01", 1); // Fast BSS Request
            offset += 1;
            memcpy(action_buf + offset, "\xAA\xBB\xCC\xDD\xEE\xFF", 6); // STA Address
            offset += 6;
            memcpy(action_buf + offset, "\xFF\xEE\xDD\xCC\xBB\xAA", 6); // AP Address
            offset += 6;

            unsigned char *tag_tmp = malloc(256);
            memset(tag_tmp, 0, 256);

            struct libwifi_tagged_parameter rsne = {0};
            size_t tsz = libwifi_create_tag(&rsne, TAG_RSN, (const unsigned char * )"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00", 20);
            w = libwifi_dump_tag(&rsne, tag_tmp, tsz);
            memcpy(action_buf + offset, tag_tmp, w);
            offset += w;


            struct libwifi_tagged_parameter mobdom = {0};
            tsz = libwifi_create_tag(&mobdom, TAG_MOBILITY_DOMAIN, (const unsigned char*)"\x00\x11\x01", 3);
            memset(tag_tmp, 0, tsz);
            w = libwifi_dump_tag(&mobdom, tag_tmp, tsz);
            memcpy(action_buf + offset, tag_tmp, w);
            offset += w;
            libwifi_free_tag(&mobdom);

            struct libwifi_tagged_parameter fbss = {0};
            tsz = libwifi_create_tag(&fbss, TAG_FAST_BSS_TRANSITION, (const unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB\xCC\xDD\xEE\xFF\xAA\x03\x04\xAA\xBB\x04\xAA\xBB\xCC\xDD", 88);
            memset(tag_tmp, 0, tsz);
            w = libwifi_dump_tag(&fbss, tag_tmp, tsz);
            memcpy(action_buf + offset, tag_tmp, w);
            offset += w;
            libwifi_free_tag(&fbss);

            libwifi_add_action_detail(&action.fixed_parameters.details, action_buf, offset);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_action_length(&action);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting actions with:\n");
            printf("\tAction: %d\n", ACTION_FAST_BSS_TRANSITION);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_action(&action, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_actions() {
    while (1) {
        printf("Sending 50 action frames, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_action action;
            memset(&action, 0, sizeof(struct libwifi_action));

            libwifi_create_action(&action, to, from, from, ACTION_FAST_BSS_TRANSITION);

            unsigned char *action_buf = malloc(256);
            memset(action_buf, 0, 256);

            size_t offset = 0;
            size_t w = 0;

            memcpy(action_buf, "\x01", 1); // Fast BSS Request
            offset += 1;
            memcpy(action_buf + offset, "\xAA\xBB\xCC\xDD\xEE\xFF", 6); // STA Address
            offset += 6;
            memcpy(action_buf + offset, "\xFF\xEE\xDD\xCC\xBB\xAA", 6); // AP Address
            offset += 6;

            unsigned char *tag_tmp = malloc(256);
            memset(tag_tmp, 0, 256);

            struct libwifi_tagged_parameter rsne = {0};
            size_t tsz = libwifi_create_tag(&rsne, TAG_RSN, (const unsigned char * )"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00", 20);
            w = libwifi_dump_tag(&rsne, tag_tmp, tsz);
            memcpy(action_buf + offset, tag_tmp, w);
            offset += w;


            struct libwifi_tagged_parameter mobdom = {0};
            tsz = libwifi_create_tag(&mobdom, TAG_MOBILITY_DOMAIN, (const unsigned char*)"\x00\x11\x01", 3);
            memset(tag_tmp, 0, tsz);
            w = libwifi_dump_tag(&mobdom, tag_tmp, tsz);
            memcpy(action_buf + offset, tag_tmp, w);
            offset += w;
            libwifi_free_tag(&mobdom);

            struct libwifi_tagged_parameter fbss = {0};
            tsz = libwifi_create_tag(&fbss, TAG_FAST_BSS_TRANSITION, (const unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB\xCC\xDD\xEE\xFF\xAA\xBB\xCC\xDD\xEE\xFF\xAA\x03\x04\xAA\xBB\x04\xAA\xBB\xCC\xDD", 88);
            memset(tag_tmp, 0, tsz);
            w = libwifi_dump_tag(&fbss, tag_tmp, tsz);
            memcpy(action_buf + offset, tag_tmp, w);
            offset += w;
            libwifi_free_tag(&fbss);

            libwifi_add_action_detail(&action.fixed_parameters.details, action_buf, offset);

            unsigned char *buf = NULL;
            size_t buf_sz = libwifi_get_action_length(&action);

            buf = malloc(buf_sz);
            if (buf == NULL) {
                printf("malloc failure: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }

            printf("Injecting actions with:\n");
            printf("\tAction: %d\n", ACTION_FAST_BSS_TRANSITION);
            printf("\tSource: " MACSTR "\n", MAC2STR(from));
            printf("\tDestination: " MACSTR "\n", MAC2STR(to));

            libwifi_dump_action(&action, buf, buf_sz);
            inject_frame(buf, buf_sz);

            free(buf);

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_atim() {
    while (1) {
        printf("Sending 50 ATIM frames, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_atim atim = {0};

            libwifi_create_atim(&atim, to, from, from);

            inject_frame(&atim, sizeof(struct libwifi_atim));

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_rts() {
    while (1) {
        printf("Sending 50 RTS frames, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_rts rts = {0};

            libwifi_create_rts(&rts, to, from, 32);

            inject_frame(&rts, sizeof(struct libwifi_rts));

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void inject_cts() {
    while (1) {
        printf("Sending 50 CTS frames, then sleeping for 1 second\n");
        for (int i = 0; i < 50; ++i) {
            struct libwifi_cts cts = {0};

            libwifi_create_cts(&cts, to, 32);

            inject_frame(&cts, sizeof(struct libwifi_cts));

            usleep(1e4); // 10ms
        }
        sleep(1);
    }
}

void help(const char *name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\t%s --interface [interface] [--mode]\n", name);
    fprintf(stderr, "\t\tor\n");
    fprintf(stderr, "\t%s --file [output file] [--mode]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "\t--beacon\n");
    fprintf(stderr, "\t--random-beacon\n");
    fprintf(stderr, "\t--probe-req\n");
    fprintf(stderr, "\t--probe-resp\n");
    fprintf(stderr, "\t--deauth\n");
    fprintf(stderr, "\t--disassoc\n");
    fprintf(stderr, "\t--assoc-req\n");
    fprintf(stderr, "\t--assoc-resp\n");
    fprintf(stderr, "\t--reassoc-req\n");
    fprintf(stderr, "\t--reassoc-resp\n");
    fprintf(stderr, "\t--auth\n");
    fprintf(stderr, "\t--timing-ad\n");
    fprintf(stderr, "\t--atim\n");
    fprintf(stderr, "\t--rts\n");
    fprintf(stderr, "\t--cts\n");
}

void handle_args(int argc, const char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if (argc < 4) {
        help(argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[1], "--file") == 0) {
        inject_mode = OFFLINE_DUMP;

        filename = fopen(argv[2], "w+");
        if ((handle = pcap_open_dead(DLT_IEEE802_11_RADIO, BUFSIZ)) == NULL) {
            fprintf(stderr, "1 %s: %s\n", argv[2], errbuf);
            exit(EXIT_FAILURE);
        }
        if ((outputHandle = pcap_dump_fopen(handle, filename)) == NULL) {
            fprintf(stderr, "2 %s: %s\n", argv[2], errbuf);
            exit(EXIT_FAILURE);
        }
    } else if (strcmp(argv[1], "--interface") == 0) {
        inject_mode = LIVE_INJECT;

        if ((handle = pcap_create(argv[2], errbuf)) == NULL) {
            fprintf(stderr, "Couldn't open interface %s: %s\n", argv[2], errbuf);
            exit(EXIT_FAILURE);
        }
        if (pcap_activate(handle) == 0) {
            printf("Sniffing on %s\n", argv[2]);
        } else {
            fprintf(stderr, "Couldn't activate %s: %s\n", argv[2], pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    } else {
        help(argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[3], "--beacon") == 0) {
        mode = MODE_BEACON;
    } else if (strcmp(argv[3], "--random-beacon") == 0) {
        mode = MODE_RANDOM_BEACON;
    } else if (strcmp(argv[3], "--probe-resp") == 0) {
        mode = MODE_PROBE_RESPONSE;
    } else if (strcmp(argv[3], "--probe-req") == 0) {
        mode = MODE_PROBE_REQUEST;
    } else if (strcmp(argv[3], "--deauth") == 0) {
        mode = MODE_DEAUTH;
    } else if (strcmp(argv[3], "--disassoc") == 0) {
        mode = MODE_DISASSOC;
    } else if (strcmp(argv[3], "--assoc-resp") == 0) {
        mode = MODE_ASSOC_RESPONSE;
    } else if (strcmp(argv[3], "--assoc-req") == 0) {
        mode = MODE_ASSOC_REQUEST;
    } else if (strcmp(argv[3], "--reassoc-resp") == 0) {
        mode = MODE_REASSOC_RESPONSE;
    } else if (strcmp(argv[3], "--reassoc-req") == 0) {
        mode = MODE_REASSOC_REQUEST;
    } else if (strcmp(argv[3], "--auth") == 0) {
        mode = MODE_AUTH;
    } else if (strcmp(argv[3], "--timing-ad") == 0) {
        mode = MODE_TIMING_AD;
    } else if (strcmp(argv[3], "--action") == 0) {
        mode = MODE_ACTION;
    } else if (strcmp(argv[3], "--action-noack") == 0) {
        mode = MODE_ACTION_NOACK;
    } else if (strcmp(argv[3], "--atim") == 0) {
        mode = MODE_ATIM;
    } else if (strcmp(argv[3], "--rts") == 0) {
        mode = MODE_RTS;
    } else if (strcmp(argv[3], "--cts") == 0) {
        mode = MODE_CTS;
    } else {
        help(argv[0]);
        exit(EXIT_SUCCESS);
    }
}

int main(int argc, const char *argv[]) {
    signal(SIGINT, handle_interupt);
    handle_args(argc, argv);

    printf("Starting in 5 seconds...\n");

    sleep(5);

    switch (mode) {
        case MODE_BEACON:
            inject_beacons(0);
            break;
        case MODE_RANDOM_BEACON:
            inject_beacons(1);
            break;
        case MODE_PROBE_RESPONSE:
            inject_probe_responses();
            break;
        case MODE_PROBE_REQUEST:
            inject_probe_requests();
            break;
        case MODE_DEAUTH:
            inject_deauths();
            break;
        case MODE_DISASSOC:
            inject_disassocs();
            break;
        case MODE_ASSOC_REQUEST:
            inject_assoc_requests();
            break;
        case MODE_ASSOC_RESPONSE:
            inject_assoc_responses();
            break;
        case MODE_REASSOC_REQUEST:
            inject_reassoc_requests();
            break;
        case MODE_REASSOC_RESPONSE:
            inject_reassoc_responses();
            break;
        case MODE_AUTH:
            inject_auths();
            break;
        case MODE_ACTION:
            inject_actions();
            break;
        case MODE_ACTION_NOACK:
            inject_action_noacks();
            break;
        case MODE_TIMING_AD:
            inject_timing_ads();
            break;
        case MODE_ATIM:
            inject_atim();
            break;
        case MODE_RTS:
            inject_rts();
            break;
        case MODE_CTS:
            inject_cts();
            break;
    }

    return 0;
}
