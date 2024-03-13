# Securing Internet of Vehicles using TESLA Protocol and Blockchain

This repository contains the implementation of a blockchain-based solution designed for the Internet of Vehicles (IoV) using TESLA (Timed Efficient Stream Loss-tolerant Authentication) for secure broadcast and Python for blockchain implementation.

## Overview

`TESLABC.py` is the core script that sets up the blockchain, including key generation, block creation, and the blockchain itself.

### Features

- Cryptographic key generation for a server and multiple clients.
- Definition of the Block and Blockchain classes.
- SHA-256 hashing for block integrity and security.
- Management of the blockchain with the ability to add new blocks.
- Implementation of TESLA for authenticated packets.

### Prerequisites

To run the `TESLABC.py` script, please ensure that the following Python libraries are installed:

- `cryptography`
- `base64`
- `hashlib`
- `datetime`
- `socket`
- `struct`
- `threading`
- `os`
- `json`
- `pickle`
- `statistics`

These can be installed using `pip`:
pip install cryptography base64 hashlib datetime socket struct threading os json pickle statistics

### Setup and Execution

To use this script, first clone the repository and navigate to the directory containing `TESLABC.py`. You can run the script using Python 3:

```bash
python TESLABC.py

Ensure that the necessary PEM files for the server and client keys are present in the same directory as the TESLABC.py script.

### File Structure
The script requires the following PEM files for cryptographic operations:

- private_key_server.pem - Server's private key.
- public_key_server.pem - Server's public key.
- private_key_client1.pem - Vehicle 1's private key.
- public_key_client1.pem - Vehicle 1's public key.
- .....

