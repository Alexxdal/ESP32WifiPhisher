#include "../../src/libwifi.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BCAST_MAC "\xff\xff\xff\xff\xff\xff"
#define TO_MAC "\x00\x20\x91\xAA\xBB\xCC"
const unsigned char to[] = TO_MAC;
const unsigned char bcast[] = BCAST_MAC;

int test_atim_gen_full() {
    struct libwifi_atim atim = {0};

    int ret = libwifi_create_atim(&atim, bcast, to, to);
    if (ret != 0) {
        fprintf(stderr, "Failed to create atim: %s\n", strerror(ret));
        return ret;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Specify test\n");
        return -1;
    }

    if (strcmp(argv[1], "--atim-gen-full") == 0) {
        return test_atim_gen_full();
    }

    return -1;
}
