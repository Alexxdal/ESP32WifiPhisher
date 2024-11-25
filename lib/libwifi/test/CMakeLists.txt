cmake_minimum_required(VERSION 3.18)

project(libwifi_tests VERSION 0.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")

link_directories("../build/")

link_directories(AFTER "/usr/local/lib")
include_directories(AFTER "/usr/local/include")

add_executable(action_tests src/action_tests.c)
target_link_libraries(action_tests wifi)
add_executable(assoc_req_tests src/assoc_req_tests.c)
target_link_libraries(assoc_req_tests wifi)
add_executable(assoc_resp_tests src/assoc_resp_tests.c)
target_link_libraries(assoc_resp_tests wifi)
add_executable(atim_tests src/atim_tests.c)
target_link_libraries(atim_tests wifi)
add_executable(auth_tests src/auth_tests.c)
target_link_libraries(auth_tests wifi)
add_executable(beacon_tests src/beacon_tests.c)
target_link_libraries(beacon_tests wifi)
add_executable(deauth_tests src/deauth_tests.c)
target_link_libraries(deauth_tests wifi)
add_executable(disassoc_tests src/disassoc_tests.c)
target_link_libraries(disassoc_tests wifi)
add_executable(probe_req_tests src/probe_req_tests.c)
target_link_libraries(probe_req_tests wifi)
add_executable(probe_resp_tests src/probe_resp_tests.c)
target_link_libraries(probe_resp_tests wifi)
add_executable(reassoc_req_tests src/reassoc_req_tests.c)
target_link_libraries(reassoc_req_tests wifi)
add_executable(reassoc_resp_tests src/reassoc_resp_tests.c)
target_link_libraries(reassoc_resp_tests wifi)
add_executable(timing_ad_tests src/timing_ad_tests.c)
target_link_libraries(timing_ad_tests wifi)

enable_testing()
add_test(NAME test_action_gen_full COMMAND action_tests --action-gen-full)
add_test(NAME test_action_gen_details COMMAND action_tests --action-gen-details)

add_test(NAME test_assoc_req_gen_full COMMAND assoc_req_tests --assoc_req-gen-full)
add_test(NAME test_assoc_req_gen_tags COMMAND assoc_req_tests --assoc_req-gen-tags)

add_test(NAME test_assoc_resp_gen_full COMMAND assoc_resp_tests --assoc_resp-gen-full)
add_test(NAME test_assoc_resp_gen_tags COMMAND assoc_resp_tests --assoc_resp-gen-tags)

add_test(NAME test_atim_gen_full COMMAND atim_tests --atim-gen-full)

add_test(NAME test_auth_gen_full COMMAND auth_tests --auth-gen-full)
add_test(NAME test_auth_gen_tags COMMAND auth_tests --auth-gen-tags)

add_test(NAME test_beacon_gen_full COMMAND beacon_tests --beacon-gen-full)
add_test(NAME test_beacon_gen_tags COMMAND beacon_tests --beacon-gen-tags)
add_test(NAME test_beacon_parse COMMAND beacon_tests --beacon-parse)

add_test(NAME test_deauth_gen_full COMMAND deauth_tests --deauth-gen-full)
add_test(NAME test_deauth_gen_tags COMMAND deauth_tests --deauth-gen-tags)

add_test(NAME test_disassoc_gen_full COMMAND disassoc_tests --disassoc-gen-full)
add_test(NAME test_disassoc_gen_tags COMMAND disassoc_tests --disassoc-gen-tags)

add_test(NAME test_probe_req_gen_full COMMAND probe_req_tests --probe_req-gen-full)
add_test(NAME test_probe_req_gen_tags COMMAND probe_req_tests --probe_req-gen-tags)

add_test(NAME test_probe_resp_gen_full COMMAND probe_resp_tests --probe_resp-gen-full)
add_test(NAME test_probe_resp_gen_tags COMMAND probe_resp_tests --probe_resp-gen-tags)

add_test(NAME test_reassoc_req_gen_full COMMAND reassoc_req_tests --reassoc_req-gen-full)
add_test(NAME test_reassoc_req_gen_tags COMMAND reassoc_req_tests --reassoc_req-gen-tags)

add_test(NAME test_reassoc_resp_gen_full COMMAND reassoc_resp_tests --reassoc_resp-gen-full)
add_test(NAME test_reassoc_resp_gen_tags COMMAND reassoc_resp_tests --reassoc_resp-gen-tags)

add_test(NAME test_timing_ad_gen_tags COMMAND timing_ad_tests --timing_ad-gen-full)
