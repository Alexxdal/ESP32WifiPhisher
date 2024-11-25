#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_action_gen_full() {
    struct libwifi_action action = {0};

    int ret = libwifi_create_action(&action, bcast, to, to, ACTION_HT);
    if (ret != 0) {
        fprintf(stderr, "Failed to create action: %s\n", strerror(ret));
        return ret;
    }

    int action_len = libwifi_get_action_length(&action);
    if (action_len <= 0) {
        fprintf(stderr, "Invalid action length: %d\n", action_len);
        return action_len;
    }

    unsigned char *buf = malloc(action_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_action(&action, buf, action_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump action\n");
        return ret;
    }

    return 0;
}

int test_action_add_detail() {
    struct libwifi_action action = {0};

    int ret = libwifi_create_action(&action, bcast, to, to, ACTION_HT);
    if (ret != 0) {
        fprintf(stderr, "Failed to create action: %s\n", strerror(ret));
        return ret;
    }

    ret = libwifi_add_action_detail(&action.fixed_parameters.details, (const unsigned char *) "HELLO WORLD", strlen("HELLO WORLD"));

    int action_len = libwifi_get_action_length(&action);
    if (action_len <= 0) {
        fprintf(stderr, "Invalid action length: %d\n", action_len);
        return action_len;
    }

    unsigned char *buf = malloc(action_len);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return -1;
    }

    int dump_len = libwifi_dump_action(&action, buf, action_len);
    if (dump_len <= 0) {
        fprintf(stderr, "Failed to dump action\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--action-gen-full") == 0) {
        return test_action_gen_full();
    } else if (strcmp(argv[1], "--action-gen-details") == 0) {
        return test_action_add_detail();
    }

    return -1;
}
