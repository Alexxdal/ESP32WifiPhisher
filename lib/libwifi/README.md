# libwifi
802.11 Parsing / Generation library

| Build Status                                                                          | OS    |
|---------------------------------------------------------------------------------------|-------|
|![linux](https://github.com/libwifi/libwifi/actions/workflows/linux_x86.yml/badge.svg) | Linux |
|![macOS](https://github.com/libwifi/libwifi/actions/workflows/macos_x86.yml/badge.svg) | macOS |

## What is this?
libwifi is a C library with a permissive license for generating and parsing a wide variety of 802.11 wireless frames (see the [Feature Checklist](https://libwifi.so/features)) on Linux and macOS with a few lines of straight forward code (see the [Examples section](#examples) below).

libwifi has been tested across Linux and macOS, on x86, MIPS and ARM, and is written with a simple-to-use approach while also exposing features that allow more advanced use, with clean and readable code being a priority. Other goals of the library include cross-architecture support, clean compilation without warnings and strict error checking.

The library is fully documented with code comments in both the headers files and the code files.

## Building and Installing
### Building as Release
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```
### Building as Debug
You can also specify `-DCMAKE_BUILD_TYPE=Debug` to CMake, to generate a library with debug symbols present. This also sets the library version number to `dev-BRANCHNAME-COMMITHASH`.
```
$ mkdir build
$ cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Debug
$ make
$ sudo make install
```
```
$ ./test_misc
libwifi version: dev-fixup-7909700
```

## Examples
Some examples are available in the [examples](https://github.com/libwifi/libwifi/tree/main/examples) directory, which show the general flow of how libwifi is used to generate and parse different types of 802.11 frame.

## Running Tests
Using ctest, you can run the tests for the parse and generation functions of libwifi.
```
$ cd test/
$ mkdir build
$ cd build
$ cmake ..
$ make && make test
```

## Using Utilities
Included in the source are some utilities that use libwifi, and serve as references or examples if you need them.
```
$ cd utils/
$ mkdir build
$ cd build
$ cmake ..
$ make
```

## ESP32
This project has been configured to be easily applicable as ESP-IDF component

### Steps to include (Example)

1. Put `libwifi` folder in `components/`
2. Open `main/CMakeLists.txt` and add `libwifi` to `COMPONENT_REQUIRES`
3. In `main/main.c` add `#include "libwifi.h"`
4. Test by running following code:
```C
void app_main(void){  
	printf("libwifi version: %s", libwifi_get_version());  
}
```
