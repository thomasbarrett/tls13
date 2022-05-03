# TLS13
This repository implements a TLS 1.3 server and client as described in
[RFC8446](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.6).
For testing purposes, our client sends a simple "ping" message and the
server responds with a "pong" message, but this library aims to be
extensible enough to be used as a general encrypted I/O stream that can
be used to make an HTTPS server/client. [Here](https://tls13.ulfheim.net)
is a good reference to explain exactly what is being sent and received
by the server / client.

The server and client can be built using the `make` command. The compiled
binaries can be found in the `bin` folder. In order to run the server
and client, the following commands can be used.
```bash
# Start the server
./bin/server
# Start the client
./bin/client
```

To test the correctness of our server/client implementation, we include a
standard python3 TLS 1.3 server and client that implements the same functionality.
```bash
# Start the sever
python3 server.py
# Start the client
python3 client.py
```

The server and client are not yet complete. Below, we outline a list
of all message types that we must be able to read and write. Note that
we split the messages into three categories (required, error, and optional).
The required messages must be implemented in order to successfully
initiate a TLS 1.3 connection. The error messages are only needed in order
to correctly handle error cases, but we can initiate a connection without them.
The optional messages are truly optional extensions to the TLS 1.3 protocol
that may be implement in the future.

The TLS 1.3 Protocol is actually composed of 4 different protocols.

## Record Protocol
The RecordProtocol is the base protocol that all other protocols are built
upon. It is used to deliminate stream data into discrete messages and label
which protocol each message belongs to. HANDSHAKE and CHANGE_CIPHER_CPEC message
types contain plaintext payload. APPLICATION_DATA messages contain ciphertext
payload. In TLS 1.3 the decrypted payload of APPLICATION_DATA messages contain
additional HANDSHAKE messages.
- [x] R TLSPlaintext records (required)
- [x] W TLSPlaintext records (required)
- [ ] R TLSCiphertext records (required)
- [ ] W TLSCiphertext records (required)

## ChangeCipherSpec Protocol
The ChangeCipherSpec Protocol is unused in TLS 1.3, but a placehold
ChangeCipherSpec exchange is still used to ensure compatability with
TLS 1.2 middlebox compatability.
- [ ] R ChangeCipherSpec messages (required)
- [ ] W ChangeCipherSpec messages (required)

## Handshake Protocol
- [x] R HelloClient messages (required)
- [x] W HelloClient messages (required)
- [x] R HelloServer messages (required)
- [ ] W HelloServer messages (required)
- [ ] R/W HelloRetryRequest messages (error)
- [ ] R/W EncryptedExtensions messages (required)
- [ ] R/W CertificateRequest messages (optional)
- [ ] R/W Certificate messages (required)
- [ ] R/W CertificateVerify messages (required)
- [ ] R/W Finished messages (required)

## Alert Protocol
- [ ] R Alert message (error)
- [ ] W Alert message (error)

# Implementation Details
## ClientHello, ServerHello
In both ClientHello and SeverHello, we correctly signal our very limited support
for key-share protocols, signature schemes, and cipher suites. Notably, we only
support X25519 key-share protocol. The ECDSA_SECP256R1_SHA256 signature scheme, and
the TLS_CHACHA20_POLY1305_SHA256 cipher-suite (We don't actually have a working
implementation for ECDSA_SECP256R1_SHA256 or TLS_CHACHA20_POLY1305_SHA256 yet). 

- supported versions:
    - TLS 1.3
- cipher suites:
    - TLS_CHACHA20_POLY1305_SHA256
- signature algorithms:
    - ECDSA_SECP256R1_SHA256
- supported groups
    - X25519
    - SECP256R1
- key share
    - X25519

# Planned Implementation Timeline:
- [x] R/W TLSPlaintext records
- [x] R/W HelloClient
- [x] R HelloServer
- [x] W HelloServer
- [x] X25519 edDHE
- [x] TLS_CHACHA20_POLY1305_SHA256 AEAD.
- [x] HKDF (Hashed Key Derivation Function)
- [ ] Handshake Keys Calculation
- [ ] R/W TLSCiphertext records
- [ ] R/W Certificate records
- [ ] R/W CertificateVerify records
- [ ] R/W Finished records
- [ ] Application Keys Calculation
- [ ] Hello World HTTPS server.

# Optional Correctness Extensions
- [ ] Protocol Correctness / Error Handling.
- [ ] R/W x509 certificates
- [ ] SECP256R1_SHA256 ECDSA
- [ ] x509 validation

# Optional Optimizing Extensions
- [ ] Scaling: Asynchronous I/O
- [ ] OCSP stapling.
- [ ] PSK support.
- [ ] MTLS support.
