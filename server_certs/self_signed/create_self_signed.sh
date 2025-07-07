#!/bin/bash
set -e

# -------- CONFIGURATION --------
CA_KEY="myca.key"
CA_CERT="myca.pem"
CA_DAYS=3650

SERVER_KEY="privkey_self.pem"
SERVER_CSR="server.csr"
SERVER_CERT="fullchain_self.pem"
SERVER_DAYS=365
CN_NAME="192.168.178.26"
SAN_DNS="localhost"
SAN_IP="${CN_NAME}"
# -------- END CONFIG -----------

if [[ -f "$CA_KEY" || -f "$CA_CERT" ]]; then
  echo "CA key or certificate already exists, skipping CA generation."
else
  echo "Generating CA key and certificate..."
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$CA_DAYS" \
    -subj "/CN=MyTestCA" \
    -out "$CA_CERT"
fi

echo "Generating server key..."
openssl genrsa -out "$SERVER_KEY" 4096

# Create openssl config for SANs
SAN_CONFIG="san.cnf"
cat > $SAN_CONFIG <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $SAN_DNS
IP.1 = $SAN_IP
EOF

echo "Generating server CSR..."
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -subj "/CN=$CN_NAME" \
  -config $SAN_CONFIG

echo "Signing server CSR with CA (and adding SANs)..."
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -days "$SERVER_DAYS" -sha256 \
  -extfile $SAN_CONFIG -extensions v3_req

echo "Cleaning up..."
rm "$SERVER_CSR" "$SAN_CONFIG" myca.srl

echo "All done!"
echo "  CA certificate: $CA_CERT"
echo "  Server key:     $SERVER_KEY"
echo "  Server cert:    $SERVER_CERT"

echo
echo "To trust your new CA, import $CA_CERT into your macOS Keychain (for browsers) or your client!"
