cmake_minimum_required(VERSION 3.18)

if (DEFINED ESP_PLATFORM)
    file(GLOB_RECURSE libwifi_src
            "src/libwifi/*.h"
            "src/libwifi/*.c"
            )
    idf_component_register(
            SRCS ${libwifi_src}
            INCLUDE_DIRS "src/"
    )
    return()
endif()

project(wifi DESCRIPTION "802.11 Parsing / Generation library" VERSION 0.1)

execute_process(COMMAND git rev-parse --abbrev-ref HEAD OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE GITBRANCH)
execute_process(COMMAND git log -1 --pretty=format:%h OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE GITHASH)
execute_process(COMMAND date OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE BUILDTIME)
set(LIBWIFI_VERSION "0.0.10")


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu17")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes -Wstrict-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")

if(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Walloca -Wformat-security -Wnull-dereference -Wstack-protector")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wvla -Warray-bounds -Warray-bounds-pointer-arithmetic -Wassign-enum -Wbad-function-cast")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconditional-uninitialized -Wfloat-equal -Wformat-type-confusion -Widiomatic-parentheses")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wimplicit-fallthrough -Wloop-analysis -Wpointer-arith")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch-enum -Wtautological-constant-in-range-compare -Wunreachable-code-aggressive -Wcomma")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-security -Wnull-dereference -Wstack-protector")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wtrampolines -Walloca -Wvla -Warray-bounds=2 -Wimplicit-fallthrough=3 -Wtraditional-conversion")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 -Wconversion -Wlogical-op")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wduplicated-cond -Wduplicated-branches -Wformat-signedness -Wshadow -Wstrict-overflow=4 -Wundef")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wstack-usage=1000000 -Wcast-align=strict")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-clash-protection -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code")
endif(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")



set(CMAKE_MACOSX_RPATH 1)

message(" ")
message(" _  _  _                _   __  _   ")
message("| |(_)| |              (_) / _|(_)  ")
message("| | _ | |__  __      __ _ | |_  _   ")
message("| || || '_ \\ \\ \\ /\\ / /| ||  _|| |  ")
message("| || || |_| | \\ V  V / | || |  | |  ")
message("|_||_||_.__/   \\_/\\_/  |_||_|  |_|  ")
message("-----------------------------------")
message("802.11 Parsing / Generation Library")
message("Version: ${LIBWIFI_VERSION}, Git: ${GITBRANCH} (${GITHASH}), Time: ${BUILDTIME}")
message("Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("Building for Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
    add_compile_definitions(LIBWIFI_VERSION="dev-${GITBRANCH}-${GITHASH}")
else()
    message("Building for Release")
    add_compile_definitions(LIBWIFI_VERSION="${LIBWIFI_VERSION}")
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

message(" ")

file(GLOB_RECURSE libwifi_src
    "src/libwifi/*.h"
    "src/libwifi/*.c"
)

add_library(wifi SHARED ${libwifi_src})
set_target_properties(wifi PROPERTIES LINKER_LANGUAGE C)
set_target_properties(wifi PROPERTIES VERSION ${LIBWIFI_VERSION})
set_target_properties(wifi PROPERTIES SOVERSION 0)
set_target_properties(wifi PROPERTIES PUBLIC_HEADER src/libwifi.h)

add_library(wifi_static STATIC ${libwifi_src})
set_target_properties(wifi_static PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set_target_properties(wifi_static PROPERTIES LINKER_LANGUAGE C)
set_target_properties(wifi_static PROPERTIES VERSION ${LIBWIFI_VERSION})
set_target_properties(wifi_static PROPERTIES PUBLIC_HEADER src/libwifi.h)
set_target_properties(wifi_static PROPERTIES OUTPUT_NAME wifi)

install(DIRECTORY src/libwifi/core/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include/libwifi/core FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/libwifi/parse/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include/libwifi/parse FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/libwifi/gen/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include/libwifi/gen FILES_MATCHING PATTERN "*.h")
install(TARGETS wifi LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include)

add_custom_target(uninstall COMMAND rm -rf ${CMAKE_INSTALL_PREFIX}/include/libwifi; rm -rf ${CMAKE_INSTALL_PREFIX}/include/libwifi.h; rm -rf ${CMAKE_INSTALL_PREFIX}/lib/libwifi*)
