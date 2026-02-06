# SPAKE2+ Implementation

A secure implementation of the SPAKE2+ Password-Authenticated Key Exchange protocol using libsodium and Ristretto255.

## Overview

This project implements SPAKE2+, an augmented Password-Authenticated Key Exchange (PAKE) protocol that provides:

- **Mutual Authentication**: Client and server verify each other without exposing passwords
- **Forward Secrecy**: Session keys remain secure even if passwords are later compromised
- **No Password Transmission**: Passwords never leave the client in plaintext
- **Offline Attack Resistance**: Server stores only verifiers, not plaintext passwords

## Features

- Built on Ristretto255 prime-order group (eliminates cofactor-related vulnerabilities)
- Constant-time cryptographic operations via libsodium
- Multi-client support with concurrent thread handling
- Comprehensive test suite covering protocol logic, storage, and integration
- Clean separation between networking and cryptographic layers

## Requirements

**Tested on Ubuntu 24.04.2 LTS**

```bash
sudo apt install build-essential libsodium-dev
```

## Building

```bash
make
```

## Usage

### Starting the Server

```bash
STORAGE_PATH=/path/to/storage ./bin/server <server_id>
```

The server will:
- Listen for incoming client connections
- Store client verifiers (not plaintext passwords)
- Handle multiple clients concurrently

### Starting a Client

```bash
./bin/client <client_id> <password>
```

On first connection, the client will register with the server. On subsequent connections, it will authenticate and establish a shared session key.

## Testing

Run the complete test suite:

```bash
make test
```

### Expected Output

```
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

### Test Coverage

The test suite includes three layers:

1. **Protocol Logic Tests**: Verify cryptographic correctness and key derivation
2. **Storage Tests**: Validate verifier persistence and credential matching
3. **Integration Tests**: Test complete client-server workflows including concurrent connections

## Protocol Details

### Setup Phase (Registration)

1. Client computes password-derived scalars: `(φ₀, φ₁) = H(password || clientID || serverID)`
2. Client computes verifier: `c = g^φ₁`
3. Client sends verifier `(φ₀, c)` to server (password never transmitted)

### Key Exchange Phase (Authentication)

1. Client generates ephemeral key `α` and sends `u = g^α · a^φ₀`
2. Server generates ephemeral key `β` and sends `v = g^β · b^φ₀`
3. Both parties compute shared values `w` and `d`
4. Session key derived as: `k = H'(φ₀ || clientID || serverID || u || v || w || d)`

Keys match only if both parties use identical credentials.

## Security Considerations

- Uses audited libsodium primitives for all cryptographic operations
- Sensitive memory explicitly zeroed after use via `sodium_memzero()`
- Hash functions provide domain separation (H for scalars, H' for keys)
- Ristretto255 ensures prime-order group without subgroup attacks
- Fresh ephemeral keys per session provide forward secrecy

## References

- [RFC 9383: SPAKE2+ Protocol Specification](https://www.rfc-editor.org/rfc/rfc9383)
- [Ristretto Group Construction](https://ristretto.group/)
- [libsodium Documentation](https://doc.libsodium.org/)

## License

Applied Cryptography course project (02232)
