# libwifi Tests
libwifi uses CMakes testing functionalities. The tests are in the `src/` directory, and can be used with `make test`.

## Running Tests
```
>> mkdir build
>> cd build
>> cmake ..
>> make && make test
```

## Expected Output
```
>> make test
Running tests...
Test project libwifi/test/build
      Start  1: test_action_gen_full
 1/24 Test  #1: test_action_gen_full .............   Passed    0.00 sec
      Start  2: test_action_gen_details
 2/24 Test  #2: test_action_gen_details ..........   Passed    0.00 sec
      Start  3: test_assoc_req_gen_full
 3/24 Test  #3: test_assoc_req_gen_full ..........   Passed    0.00 sec
      Start  4: test_assoc_req_gen_tags
 4/24 Test  #4: test_assoc_req_gen_tags ..........   Passed    0.00 sec
      Start  5: test_assoc_resp_gen_full
 5/24 Test  #5: test_assoc_resp_gen_full .........   Passed    0.00 sec
      Start  6: test_assoc_resp_gen_tags
 6/24 Test  #6: test_assoc_resp_gen_tags .........   Passed    0.00 sec
      Start  7: test_atim_gen_full
 7/24 Test  #7: test_atim_gen_full ...............   Passed    0.00 sec
      Start  8: test_auth_gen_full
 8/24 Test  #8: test_auth_gen_full ...............   Passed    0.00 sec
      Start  9: test_auth_gen_tags
 9/24 Test  #9: test_auth_gen_tags ...............   Passed    0.00 sec
      Start 10: test_beacon_gen_full
10/24 Test #10: test_beacon_gen_full .............   Passed    0.00 sec
      Start 11: test_beacon_gen_tags
11/24 Test #11: test_beacon_gen_tags .............   Passed    0.00 sec
      Start 12: test_deauth_gen_full
12/24 Test #12: test_deauth_gen_full .............   Passed    0.00 sec
      Start 13: test_deauth_gen_tags
13/24 Test #13: test_deauth_gen_tags .............   Passed    0.00 sec
      Start 14: test_disassoc_gen_full
14/24 Test #14: test_disassoc_gen_full ...........   Passed    0.00 sec
      Start 15: test_disassoc_gen_tags
15/24 Test #15: test_disassoc_gen_tags ...........   Passed    0.00 sec
      Start 16: test_probe_req_gen_full
16/24 Test #16: test_probe_req_gen_full ..........   Passed    0.00 sec
      Start 17: test_probe_req_gen_tags
17/24 Test #17: test_probe_req_gen_tags ..........   Passed    0.00 sec
      Start 18: test_probe_resp_gen_full
18/24 Test #18: test_probe_resp_gen_full .........   Passed    0.00 sec
      Start 19: test_probe_resp_gen_tags
19/24 Test #19: test_probe_resp_gen_tags .........   Passed    0.00 sec
      Start 20: test_reassoc_req_gen_full
20/24 Test #20: test_reassoc_req_gen_full ........   Passed    0.00 sec
      Start 21: test_reassoc_req_gen_tags
21/24 Test #21: test_reassoc_req_gen_tags ........   Passed    0.00 sec
      Start 22: test_reassoc_resp_gen_full
22/24 Test #22: test_reassoc_resp_gen_full .......   Passed    0.00 sec
      Start 23: test_reassoc_resp_gen_tags
23/24 Test #23: test_reassoc_resp_gen_tags .......   Passed    0.00 sec
      Start 24: test_timing_ad_gen_tags
24/24 Test #24: test_timing_ad_gen_tags ..........   Passed    0.00 sec

100% tests passed, 0 tests failed out of 24

Total Test time (real) =   0.06 sec
```
