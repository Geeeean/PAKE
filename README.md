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
The output SHOULD show that every test has passed.

