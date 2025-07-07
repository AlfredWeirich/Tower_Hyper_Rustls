#!/bin/bash
set -e

# === Usage ===
# ./thisscript.sh client1
# ./thisscript.sh client2
# etc.

if [ $# -ne 1 ]; then
  echo "Usage: $0 <client_name>"
  exit 1
fi

CLIENT_NAME="$1"

# === Config ===
CA_KEY="ca.key.pem"
CA_CERT="ca.cert.pem"
CA_CONF="openssl-ca.cnf"
CA_DIR="./demoCA"
DAYS_VALID=3650
EMAIL="alfred.weirich@gmail.com"

# Per-client files
CLIENT_KEY="${CLIENT_NAME}.key.pem"
CLIENT_CSR="${CLIENT_NAME}.csr.pem"
CLIENT_CERT="${CLIENT_NAME}.cert.pem"
CLIENT_EXT="${CLIENT_NAME}_ext.cnf"
PKCS12_OUT="${CLIENT_NAME}.p12"

# === CA & DB Setup (do only if not already done) ===
if [ ! -f "$CA_KEY" ]; then
  echo "▶️ Creating root CA key and certificate..."
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$DAYS_VALID" -out "$CA_CERT" \
    -subj "/C=GE/ST=NRW/L=AC/O=Weirich/OU=dev/CN=MyRootCa/emailAddress=$EMAIL"
fi

# Prepare CA database and config if missing
if [ ! -d "$CA_DIR" ]; then
  echo "▶️ Setting up OpenSSL CA DB structure..."
  mkdir -p "$CA_DIR/newcerts"
  touch "$CA_DIR/index.txt"
  echo 1000 > "$CA_DIR/serial"
  echo 1000 > "$CA_DIR/crlnumber"
fi

if [ ! -f "$CA_CONF" ]; then
  echo "▶️ Creating minimal OpenSSL CA config ($CA_CONF)..."
  cat > "$CA_CONF" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $CA_DIR
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = $CA_CERT
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl.pem
private_key       = $CA_KEY
default_crl_days  = 365
default_md        = sha256
policy            = policy_any
x509_extensions   = v3_req

[ policy_any ]
countryName             = supplied
stateOrProvinceName     = supplied
organizationName        = supplied
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
fi

# === Create client key ===
echo "▶️ Creating private key for $CLIENT_NAME ..."
openssl genrsa -out "$CLIENT_KEY" 2048

# === Create client extension config ===
cat > "$CLIENT_EXT" <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
C = GE
ST = NRW
L = AC
O = Weirich
OU = dev
CN = $CLIENT_NAME

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# === Create client CSR ===
echo "▶️ Creating CSR for $CLIENT_NAME ..."
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -config "$CLIENT_EXT"

# === Sign client cert with CA (tracked, so can be revoked/CRLed) ===
echo "▶️ Signing client certificate with CA ..."
openssl ca -batch -config "$CA_CONF" -in "$CLIENT_CSR" -out "$CLIENT_CERT" -extensions v3_req -days "$DAYS_VALID"

echo "✅ Certificate issued for $CLIENT_NAME"
ls -l "$CLIENT_KEY" "$CLIENT_CSR" "$CLIENT_CERT"

# Optional: verify
echo "🔍 Verifying client certificate..."
openssl verify -CAfile "$CA_CERT" "$CLIENT_CERT"

echo "▶️ Create PKCS12 file for Chrome ..."
openssl pkcs12 -export \
  -inkey "$CLIENT_KEY" \
  -in "$CLIENT_CERT" \
  -certfile "$CA_CERT" \
  -out "$PKCS12_OUT" \
  -name "Client Certificate for Chrome - $CLIENT_NAME" \
  -password pass:

echo "▶️ To revoke this client certificate and update CRL, use:"
echo "    openssl ca -config $CA_CONF -revoke $CLIENT_CERT"
echo "    openssl ca -config $CA_CONF -gencrl -out ca.crl.pem"

# (optional) Print all issued and revoked certs
# cat "$CA_DIR/index.txt"

echo "✨ Done."
# End of script
echo "You can now use the client certificate for mTLS authentication."