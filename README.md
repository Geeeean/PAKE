
# 02232 Applied Cryptography PAKE [Group 24]
**Tested on Ubuntu 24.04.2 LT**

## Requirements
```bash
sudo apt install build-essential
sudo apt install libsodium-dev
```

## Compiling
```bash
make
```

## Usage
Starting a server
```bash
STORAGE_PATH=path  ./bin/server serverid
```
Starting a client
```bash
./bin/client clientid password
```

## Testing
```bash
make test
```
Example output:
```bash
test/main.c:963:logic_test_a_and_b_generators:PASS
test/main.c:966:logic_simple_protocol_correct:PASS
test/main.c:967:logic_protocol_doesnt_produce_same_keys_with_same_credentials:PASS
test/main.c:968:logic_wrong_password_used:PASS
test/main.c:969:logic_wrong_id_used:PASS
test/main.c:970:logic_wrong_server_used:PASS
test/main.c:971:logic_name_and_server_switched_around:PASS
test/main.c:974:storage_init_success:PASS
test/main.c:975:storage_store_and_verify_secret:PASS
test/main.c:976:storage_verify_secret_not_found:PASS
test/main.c:977:storage_store_and_verify_secret_wrong_credentials:PASS
test/main.c:980:integration_init:PASS
test/main.c:981:integration_hello_handshake:PASS
test/main.c:982:integration_setup:PASS
test/main.c:983:integration_setup_wrong_password:PASS
test/main.c:984:integration_setup_correct_password:PASS
test/main.c:985:integration_whole_protocol:PASS
test/main.c:986:integration_multiple_client:PASS
-----------------------
18 Tests 0 Failures 0 Ignored
OK
```
The output from the unit testing will display whether it has **PASSED** or **FAILED.** If everything has been compiled correctly, the tests should run without errors and display at the bottom **0 FAILURES.**



