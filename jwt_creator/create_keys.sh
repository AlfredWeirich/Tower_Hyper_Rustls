#!/bin/bash

# Set filenames
PRIVATE_KEY="private_key.pem"
PUBLIC_KEY="public_key.pem"

# Generate 2048-bit RSA private key
openssl genpkey -algorithm RSA -out "$PRIVATE_KEY" -pkeyopt rsa_keygen_bits:2048

# Extract public key from private key
openssl rsa -pubout -in "$PRIVATE_KEY" -out "$PUBLIC_KEY"

echo "Keys generated:"
echo "Private key: $PRIVATE_KEY"
echo "Public key:  $PUBLIC_KEY"

