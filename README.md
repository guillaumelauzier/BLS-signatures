# BLS-signatures

BLS (Boneh-Lynn-Shacham) signatures are a type of cryptographic digital signature scheme that allows for fast signature verification and aggregation of multiple signatures. BLS signatures are based on the mathematical properties of pairing-based cryptography, which involves operations between points on elliptic curves.

BLS signatures are often used in blockchain and decentralized finance (DeFi) applications because they enable efficient signature verification and compact signature representation. They are particularly useful in applications where many signatures need to be aggregated, such as in multi-signature transactions and threshold signature schemes.

Compared to other signature schemes like ECDSA and Schnorr signatures, BLS signatures have a few notable advantages. They have shorter signature lengths, allowing for more efficient use of storage space and bandwidth. They also allow for faster signature verification, which can be important in applications where speed is a priority.

# src.cpp

This code generates a new private key and public key for BLS signatures, signs a message using the private key, and verifies the signature using the public key and message. It then prints out the private key, public key, signature, and whether the signature is valid or not. Note that this code does not use any external libraries and only relies on OpenSSL.

# lib.cpp

This code generates a BLS secret key, corresponding public key, and uses them to sign a message. The resulting signature is then verified, and the results are printed to the console. Note that the blst library must be installed and linked to the program for this code to work.

