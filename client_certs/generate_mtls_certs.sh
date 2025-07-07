#!/bin/bash

set -e

# === Config ===
CA_KEY="ca.key.pem"
CA_CERT="ca.cert.pem"
CLIENT_KEY="client.key.pem"
CLIENT_CSR="client.csr.pem"
CLIENT_CERT="client.cert.pem"
CLIENT_EXT="client_ext.cnf"
DAYS_VALID=365
CN="client.weirich"
EMAIL="alfred.weirich@gmail.com"

echo "▶️ Creating root CA key and certificate..."
openssl genrsa -out "$CA_KEY" 4096
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" -subj "/C=GE/ST=NRW/L=AC/O=Weirich/OU=dev/CN=MyRootCa/emailAddress=$EMAIL"

echo "▶️ Creating client private key..."
openssl genrsa -out "$CLIENT_KEY" 2048

echo "▶️ Creating client extension config..."
cat > "$CLIENT_EXT" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = GE
ST = NRW
L = AC
O = Weirich
OU = dev
CN = $CN

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

echo "▶️ Creating client CSR..."
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -config "$CLIENT_EXT"

echo "▶️ Signing client cert with CA (X.509v3)..."
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
-out "$CLIENT_CERT" -days "$DAYS_VALID" -sha256 -extfile "$CLIENT_EXT" -extensions v3_req

echo "✅ All files created:"
ls -l "$CA_KEY" "$CA_CERT" "$CLIENT_KEY" "$CLIENT_CSR" "$CLIENT_CERT"

# Optional: verify
echo
echo "🔍 Verifying client certificate..."
openssl verify -CAfile "$CA_CERT" "$CLIENT_CERT"

echo "▶️ Create client cert for chrome"
openssl pkcs12 -export \
  -inkey client.key.pem \
  -in client.cert.pem \
  -certfile ca.cert.pem \
  -out client.p12 \
  -name "Client Certificate for Chrome"
