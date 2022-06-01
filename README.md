# Introduction
The TLS 1.3 protocol defines a bi-directional encrypted socket designed to
be used in conjuction with the TCP protocol. It forms the basis of the HTTPS
protocol over which private data, credit card numbers, passwords, and all matter
of information is transmitted when using the internet. This protocol is the most
recent of a long history of deprecated security protocols (TLS 1.2, TLS 1.0,
SSL 2.0, and SSL 1.0) that were later found to be insecure.  The TLS 1.3 protocol
is defined by the IETF in [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.6).

My primary purpose for implementing the TLS 1.3 protocol was educational: The TLS 1.3
protocol is a complex protocol which, despite is ubiquirt, very few people know the
technical details. The secondary purpose was to create a secure implementation utilizing
my constant time big-integer library. The utilization of constant time cryptography is
essential for modern cryptographic libraries and protocols: timing side channels have
been shown to break even the most theoretically secure cryptographic schemes.

# Protocol Overview

## Record Protocol
The RecordProtocol is the base protocol that all other protocols are built
upon. It is used to deliminate stream data into discrete messages and label
which protocol each message belongs to. HANDSHAKE and CHANGE_CIPHER_CPEC message
types contain plaintext payload. APPLICATION_DATA messages contain ciphertext
payload. In TLS 1.3 the decrypted payload of APPLICATION_DATA messages contain
additional HANDSHAKE messages.
- [x] R TLSPlaintext records (required)
- [x] W TLSPlaintext records (required)
- [x] R TLSCiphertext records (required)
- [x] W TLSCiphertext records (required)

## ChangeCipherSpec Protocol
The ChangeCipherSpec Protocol is unused in TLS 1.3, but a placehold
ChangeCipherSpec exchange is still used to ensure compatability with
TLS 1.2 middlebox compatability.
- [x] R ChangeCipherSpec messages (required)
- [x] W ChangeCipherSpec messages (required)

## Handshake Protocol
The Handshake protocol serves the essential purpose of negotiating an encrpyted
connection between the client and the server. This involves two main purposes:
1. Negotiate shared keys.
After performing a secure key exchange protocol, both parties have a common set
of shared keys that can be used to encrypt further traffic (via TLS Ciphertext Records).
This exchange is done in such a way that no middleman has access to the shared key
and cannot read the traffic.

2. Prove the identity of the server.
For the sake of time, I chose not to implement Certificate validation. This decreases
the security gurentees of my implementation, but still allows it to work. With additional
time, this would be an implmementation priority.
- [x] R HelloClient messages (required)
- [x] W HelloClient messages (required)
- [x] R HelloServer messages (required)
- [ ] W HelloServer messages (required)
- [ ] R/W HelloRetryRequest messages (error)
- [ ] R/W EncryptedExtensions messages (required)
- [ ] R/W CertificateRequest messages (optional)
- [ ] R/W Certificate messages (required)
- [ ] R/W CertificateVerify messages (required)
- [x] R/W Finished messages (required)

## Alert Protocol
The Alert protocol is used to communicate errors between the client and server.
Common errors include version incompatability or invalid messages. For the sake
of time, I chose not to implement the Alert protocol for the sake of time. Instead,
my server and client instantly terminates the connection upon recieving an invalid
message.
- [ ] R Alert message (error)
- [ ] W Alert message (error)

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
- [x] CHACHA20 Stream Cipher
- [x] POLY1305 MAC
- [x] TLS_CHACHA20_POLY1305_SHA256 AEAD.
- [x] SHA256 Hash function.
- [x] SHA256-HMAC MAC. 
- [x] SHA256 HKDF (Hashed Key Derivation Function)
- [x] Handshake Keys Calculation
- [x] R/W TLSCiphertext records
- [ ] R/W Certificate records
- [ ] R/W CertificateVerify records
- [x] R/W Finished records
- [x] Application Keys Calculation
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
